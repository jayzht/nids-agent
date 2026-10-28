"""知识库管理接口：列表 / 构建 / 进度 / 删除。

构建是耗时操作（克隆 + 分块 + 向量化），所以走后台任务 + 轮询进度，
避免 HTTP 请求超时 —— 这是把离线任务放进 Web 服务时的标准做法。
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException

from app.api.schemas import KBCreateRequest, KBInfo
from app.kb import IngestState, get_kb_manager
from app.settings import get_settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/kbs", tags=["knowledge-base"])

_tasks: dict[str, asyncio.Task] = {}


@router.get("", response_model=list[KBInfo])
async def list_kbs():
    return [KBInfo(**m) for m in get_kb_manager().list_meta()]


@router.post("", status_code=202)
async def create_kb(req: KBCreateRequest):
    s = get_settings()
    mgr = get_kb_manager()
    if mgr.exists(req.name):
        raise HTTPException(409, f"知识库 {req.name} 已存在，可调用 /reindex 重建")

    raw_dir = s.raw_dir / req.name
    if not raw_dir.exists() and not req.repo:
        raise HTTPException(400, f"缺少语料目录 {raw_dir}，请先运行 scripts/fetch_corpus.py 或提供 repo")

    state = IngestState(name=req.name, status="running", phase="prepare")
    mgr.jobs[req.name] = state

    async def job() -> None:
        try:
            if req.repo and not raw_dir.exists():
                state.phase = "download"
                await asyncio.to_thread(_git_pull_docs, req.repo, req.subdir or "", raw_dir)

            def progress(phase: str, cur: int, total: int, msg: str = "") -> None:
                state.phase, state.current, state.total, state.message = phase, cur, total, msg

            index = await mgr.build(
                name=req.name,
                title=req.title,
                description=req.description,
                url_template=req.url_template,
                progress=progress,
            )
            state.status = "done"
            state.stats = index.stats()
            state.finished_at = time.time()
        except Exception as exc:  # noqa: BLE001
            logger.exception("ingest failed")
            state.status = "error"
            state.message = str(exc)[:500]
        finally:
            _tasks.pop(req.name, None)

    _tasks[req.name] = asyncio.create_task(job())
    return {"name": req.name, "status": "running", "message": "后台构建中，轮询 /api/kbs/{name}/status"}


def _git_pull_docs(repo: str, subdir: str, dest: Path) -> None:
    """极简版：clone 后只保留 subdir 里的 Markdown。生产环境应换成带鉴权的任务队列。"""
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(
            ["git", "clone", "--depth", "1", repo, tmp], check=True, capture_output=True
        )
        src = Path(tmp) / subdir if subdir else Path(tmp)
        dest.mkdir(parents=True, exist_ok=True)
        for f in src.rglob("*"):
            if f.suffix.lower() in {".md", ".mdx", ".txt"}:
                target = dest / f.relative_to(src)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(f, target)


@router.get("/{name}/status")
async def kb_status(name: str):
    mgr = get_kb_manager()
    state = mgr.jobs.get(name)
    if state:
        return state.to_dict()
    if mgr.exists(name):
        return {"name": name, "status": "done", "phase": "done", "current": 1, "total": 1}
    raise HTTPException(404, "知识库不存在")


@router.post("/{name}/reindex")
async def reindex(name: str):
    mgr = get_kb_manager()
    if not mgr.exists(name):
        raise HTTPException(404, "知识库不存在")
    state = IngestState(name=name, status="running", phase="prepare")
    mgr.jobs[name] = state

    async def job() -> None:
        try:
            def progress(phase: str, cur: int, total: int, msg: str = "") -> None:
                state.phase, state.current, state.total, state.message = phase, cur, total, msg

            index = await mgr.build(name=name, progress=progress)
            state.status, state.stats = "done", index.stats()
        except Exception as exc:  # noqa: BLE001
            state.status, state.message = "error", str(exc)[:500]
        finally:
            _tasks.pop(name, None)

    _tasks[name] = asyncio.create_task(job())
    return {"name": name, "status": "running"}


@router.delete("/{name}")
async def delete_kb(name: str):
    mgr = get_kb_manager()
    ok = mgr.delete(name)
    if not ok:
        raise HTTPException(404, "知识库不存在")
    return {"ok": True, "deleted": name}
