"""SIEM 接口：告警入库（SQLite）→ incident 聚合 → 知识增强研判 → 结论回写。"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.deps import get_rag_agent, get_siem_store
from app.settings import get_settings
from app.siem.parsers import parse_batch

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/siem", tags=["siem"])


def sse(event: dict) -> str:
    return f"data: {json.dumps(event, ensure_ascii=False)}\n\n"


class StatusUpdate(BaseModel):
    status: str = Field(..., pattern="^(open|triaged|closed)$")
    note: str = Field("", max_length=1000)


@router.post("/ingest")
async def ingest(request: Request):
    """接受单条告警、告警数组、{"lines": "eve.json 原文"} 或 text/plain 的 eve 日志。"""
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
    result = get_siem_store().ingest(alerts)
    return {**result, "stats": get_siem_store().stats()}


@router.get("/stats")
async def stats():
    return get_siem_store().stats()


@router.get("/alerts")
async def list_alerts(limit: int = 100, severity: str | None = None, src_ip: str | None = None):
    store = get_siem_store()
    return {"stats": store.stats(), "alerts": store.list(limit, severity, src_ip)}


@router.get("/incidents")
async def list_incidents(window: float = 900.0, min_alerts: int = 1,
                         status: str | None = None, refresh: bool = True):
    store = get_siem_store()
    return {"incidents": store.incidents(window=window, min_alerts=min_alerts,
                                         status=status, refresh=refresh)}


@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: str):
    incident = get_siem_store().get_incident(incident_id)
    if not incident:
        raise HTTPException(404, "找不到该 incident")
    return incident


@router.patch("/incidents/{incident_id}")
async def update_status(incident_id: str, body: StatusUpdate):
    """人工处置：open → triaged → closed，可带备注。"""
    try:
        return get_siem_store().update_status(incident_id, body.status, body.note)
    except KeyError as exc:
        raise HTTPException(404, "找不到该 incident") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/incidents/{incident_id}/analyze")
async def analyze_incident(incident_id: str, stream: bool = True):
    store = get_siem_store()
    incident = store.get_incident(incident_id)
    if not incident:
        raise HTTPException(404, "找不到该 incident")
    question = store.incident_question(incident)
    agent = get_rag_agent()
    model = get_settings().llm_model
    session_id = uuid.uuid4().hex

    if not stream:
        final = None
        async for ev in agent.astream(question, kbs=["ids"], session_id=session_id):
            if ev["type"] == "final":
                final = ev
        if not final:
            raise HTTPException(500, "未生成研判结果")
        store.save_analysis(incident_id, final, model=model)
        return final

    async def event_stream():
        yield sse({"type": "start", "session_id": session_id, "incident_id": incident_id,
                   "question": question})
        try:
            async for ev in agent.astream(question, kbs=["ids"], session_id=session_id):
                if ev["type"] == "final":
                    # 结论回写：落到 analyses 表，并把 incident 标成 triaged
                    saved = store.save_analysis(incident_id, ev, model=model)
                    ev["writeback"] = saved
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
