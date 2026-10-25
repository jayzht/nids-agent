"""SIEM 接入接口：告警入库 → 去重聚合 → 对 incident 做知识增强研判。"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse

from app.deps import get_rag_agent
from app.siem.parsers import parse_batch
from app.siem.store import AlertStore

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/siem", tags=["siem"])

store = AlertStore()


def sse(event: dict) -> str:
    return f"data: {json.dumps(event, ensure_ascii=False)}\n\n"


@router.post("/ingest")
async def ingest(request: Request):
    """接受单条告警、告警数组、{"lines": "eve.json 原文"} 或直接 text/plain 的 eve 日志。"""
    ctype = (request.headers.get("content-type") or "").lower()
    if "application/json" in ctype:
        body: Any = await request.json()
        if isinstance(body, dict) and "lines" in body:
            alerts = parse_batch(str(body["lines"]))
        else:
            alerts = parse_batch(body)
    else:
        alerts = parse_batch((await request.body()).decode("utf-8", "replace"))

    if not alerts:
        raise HTTPException(400, "没有解析出任何告警（检查字段格式）")
    result = store.ingest(alerts)
    return {**result, "stats": store.stats}


@router.get("/alerts")
async def list_alerts(limit: int = 100, severity: str | None = None, src_ip: str | None = None):
    return {
        "stats": store.stats,
        "alerts": [a.to_dict() for a in store.list(limit, severity, src_ip)],
    }


@router.get("/incidents")
async def list_incidents(window: float = 900.0, min_alerts: int = 1):
    return {"incidents": store.incidents(window=window, min_alerts=min_alerts)}


@router.post("/incidents/{incident_id}/analyze")
async def analyze_incident(incident_id: str, stream: bool = True):
    incident = next((i for i in store.incidents() if i["id"] == incident_id), None)
    if not incident:
        raise HTTPException(404, "找不到该 incident")
    question = store.incident_question(incident)
    agent = get_rag_agent()
    session_id = uuid.uuid4().hex

    if not stream:
        final = None
        async for ev in agent.astream(question, kbs=["ids"], session_id=session_id):
            if ev["type"] == "final":
                final = ev
        if not final:
            raise HTTPException(500, "未生成研判结果")
        return final

    async def event_stream():
        yield sse({"type": "start", "session_id": session_id, "incident_id": incident_id,
                   "question": question})
        try:
            async for ev in agent.astream(question, kbs=["ids"], session_id=session_id):
                yield sse(ev)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.exception("incident analysis failed")
            yield sse({"type": "error", "message": str(exc)[:500]})

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
