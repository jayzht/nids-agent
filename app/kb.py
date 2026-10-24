"""知识库的构建与生命周期管理（内存缓存 + 磁盘持久化 + 后台任务进度）。"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from app.core.llm import get_embedder
from app.ingest.chunker import chunk_documents
from app.ingest.loader import load_corpus, load_manifest
from app.retrieval.index import KBIndex
from app.settings import Settings

logger = logging.getLogger(__name__)


@dataclass
class IngestState:
    name: str
    status: str = "pending"       # pending | running | done | error
    phase: str = ""
    current: int = 0
    total: int = 0
    message: str = ""
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    stats: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = {
            "name": self.name,
            "status": self.status,
            "phase": self.phase,
            "current": self.current,
            "total": self.total,
            "message": self.message,
            "stats": self.stats,
            "elapsed": round((self.finished_at or time.time()) - self.started_at, 1),
        }
        return d


class KBManager:
    """一个进程内单例即可：索引在内存里，元信息在磁盘上。"""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._indexes: dict[str, KBIndex] = {}
        self._lock = asyncio.Lock()
        self.jobs: dict[str, IngestState] = {}

    # ---------------- 读 ----------------
    def list_meta(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        root = self.settings.kb_root
        if not root.exists():
            return out
        for d in sorted(root.iterdir()):
            meta_file = d / "meta.json"
            if d.is_dir() and meta_file.exists():
                meta = json.loads(meta_file.read_text(encoding="utf-8"))
                out.append(
                    {
                        "name": meta["name"],
                        "title": meta.get("title", meta["name"]),
                        "description": meta.get("description", ""),
                        "num_docs": meta.get("num_docs", 0),
                        "num_chunks": meta.get("num_chunks", 0),
                        "embedding_model": meta.get("embedding_model", ""),
                        "updated_at": meta.get("updated_at", ""),
                        "loaded": meta["name"] in self._indexes,
                    }
                )
        return out

    def names(self) -> list[str]:
        return [m["name"] for m in self.list_meta()]

    def exists(self, name: str) -> bool:
        return (self.settings.kb_root / name / "meta.json").exists()

    def get(self, name: str) -> KBIndex:
        if name in self._indexes:
            return self._indexes[name]
        path = self.settings.kb_root / name
        if not (path / "meta.json").exists():
            raise KeyError(f"知识库 {name} 不存在")
        index = KBIndex.load(path, self.settings)
        self._indexes[name] = index
        logger.info("loaded kb %s: %d chunks", name, len(index.chunks))
        return index

    async def get_async(self, name: str) -> KBIndex:
        async with self._lock:
            return self.get(name)

    def delete(self, name: str) -> bool:
        self._indexes.pop(name, None)
        path = self.settings.kb_root / name
        if path.exists():
            shutil.rmtree(path)
            return True
        return False

    # ---------------- 建 ----------------
    async def build(
        self,
        name: str,
        title: str = "",
        description: str = "",
        source_dir: Path | None = None,
        url_template: str = "",
        progress: Callable[[str, int, int, str], None] | None = None,
    ) -> KBIndex:
        """从 data/raw/<name> 或指定目录加载语料并建索引。"""
        s = self.settings
        root = source_dir or (s.raw_dir / name)
        if not root.exists():
            raise FileNotFoundError(f"语料目录不存在：{root}")

        manifest = load_manifest(s.raw_dir, name)
        title = title or manifest.get("title", name)
        description = description or manifest.get("description", "")
        url_template = url_template or manifest.get("url_template", "")

        def report(phase: str, cur: int, total: int, msg: str = "") -> None:
            if progress:
                progress(phase, cur, total, msg)

        report("load", 0, 1, "读取 Markdown 文件")
        docs = load_corpus(root, name, url_template, manifest.get("urls"))
        if not docs:
            raise ValueError(f"{root} 下没有可用的 Markdown 文档")
        report("load", len(docs), len(docs), f"{len(docs)} 篇文档")

        report("chunk", 0, len(docs), "结构化分块")
        chunks, dup = chunk_documents(docs, s.chunk_tokens, s.chunk_overlap_tokens)
        report("chunk", len(chunks), len(chunks), f"{len(chunks)} 个片段，去重 {dup}")

        embedder = get_embedder()
        report("embed", 0, len(chunks), f"向量化（{s.embedding_model}）")
        vectors = await embedder.embed(
            [c.embed_text for c in chunks],
            progress=lambda cur, total: report("embed", cur, total, "向量化"),
        )
        report("embed", len(chunks), len(chunks), "向量化完成")

        report("index", 0, 1, "构建 BM25 与索引")
        index = KBIndex.build(
            name=name,
            title=title,
            description=description,
            chunks=chunks,
            vectors=vectors,
            settings=s,
            extra={"url_template": url_template, "git_sha": manifest.get("git_sha", "")},
        )

        async with self._lock:
            index.save(s.kb_root)
            self._indexes[name] = index
        report("done", 1, 1, "索引完成")
        logger.info("kb %s built: %d docs / %d chunks", name, len(docs), len(chunks))
        return index


_manager: KBManager | None = None


def get_kb_manager() -> KBManager:
    global _manager
    if _manager is None:
        from app.settings import get_settings

        _manager = KBManager(get_settings())
    return _manager
