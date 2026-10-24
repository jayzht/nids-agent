"""对话接口：SSE 流式输出 + 非流式兜底 + 用户反馈落盘。"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from app.api.schemas import ChatRequest, ChatResponse, FeedbackRequest
from app.deps import get_rag_agent, get_react_agent, get_retriever
from app.settings import get_settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["chat"])

_feedback_lock = asyncio.Lock()


def sse(event: dict) -> str:
    return f"data: {json.dumps(event, ensure_ascii=False)}\n\n"


def _agent_for(mode: str):
    return get_react_agent() if mode == "react" else get_rag_agent()


@router.post("/chat")
async def chat(req: ChatRequest):
    """默认 SSE 流式。事件序列：start → step* → token* → final。

    为什么用 SSE 而不是 WebSocket：单向推送、原生支持断线重连、能直接过大部分网关。
    """
    try:
        agent = _agent_for(req.mode)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(500, f"Agent 初始化失败：{exc}") from exc

    kbs = [req.kb] if req.kb else (req.kbs or None)
    session_id = req.session_id or uuid.uuid4().hex

    if not req.stream:
        final: dict | None = None
        async for ev in agent.astream(
            req.question, kbs=kbs, session_id=session_id, sources=req.sources
        ):
            if ev["type"] == "final":
                final = ev
        if not final:
            raise HTTPException(500, "未得到最终结果")
        return ChatResponse(**{k: v for k, v in final.items() if k != "type"})

    async def event_stream():
        yield sse({"type": "start", "session_id": session_id,
                   "message_id": uuid.uuid4().hex[:12], "mode": req.mode})
        try:
            async for ev in agent.astream(
            req.question, kbs=kbs, session_id=session_id, sources=req.sources
        ):
                yield sse(ev)
        except asyncio.CancelledError:  # 客户端断开
            raise
        except Exception as exc:  # noqa: BLE001
            logger.exception("chat stream failed")
            yield sse({"type": "error", "message": str(exc)[:500]})

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


@router.post("/feedback")
async def feedback(req: FeedbackRequest):
    s = get_settings()
    path: Path = s.data_dir / "feedback.jsonl"
    record = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        **req.model_dump(),
    }
    async with _feedback_lock:
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return {"ok": True}


@router.get("/chunks/{kb}/{chunk_id}")
async def get_chunk(kb: str, chunk_id: str):
    chunk = await get_retriever().get_chunk(kb, chunk_id)
    if not chunk:
        raise HTTPException(404, "片段不存在")
    return chunk


@router.get("/documents/{kb}/{doc_id}")
async def get_document(kb: str, doc_id: str):
    doc = await get_retriever().get_document(kb, doc_id)
    if not doc:
        raise HTTPException(404, "文档不存在")
    return doc
