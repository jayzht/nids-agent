"""流量取证接口：确定性分析预览 + Agent 报告流式输出。"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from app.api.schemas import TrafficRequest
from app.deps import get_traffic_agent, get_traffic_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/traffic", tags=["traffic"])


def sse(event: dict) -> str:
    return f"data: {json.dumps(event, ensure_ascii=False)}\n\n"


@router.get("/pcaps")
async def list_pcaps():
    return get_traffic_service().list_pcaps()


@router.get("/findings/{pcap:path}")
async def findings(pcap: str):
    """不走 LLM 的确定性分析结果，用于前端预览或纯规则流水线。"""
    try:
        analysis = get_traffic_service().analyze(pcap)
    except FileNotFoundError as exc:
        raise HTTPException(404, str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(500, f"分析失败：{exc}") from exc
    out = analysis.summary_dict()
    out["dns_queries"] = analysis.dns_queries[:20]
    out["http_requests"] = analysis.http_requests[:20]
    out["tls_sni"] = analysis.tls_sni[:20]
    return out


@router.post("/analyze")
async def analyze(req: TrafficRequest):
    agent = get_traffic_agent()
    session_id = req.session_id or uuid.uuid4().hex

    if not req.stream:
        final = None
        async for ev in agent.astream(req.pcap, req.question, session_id=session_id):
            if ev["type"] == "final":
                final = ev
        if not final:
            raise HTTPException(500, "未生成报告")
        return final

    async def event_stream():
        yield sse({"type": "start", "session_id": session_id, "pcap": req.pcap, "mode": "traffic"})
        try:
            async for ev in agent.astream(req.pcap, req.question, session_id=session_id):
                yield sse(ev)
        except asyncio.CancelledError:
            raise
        except FileNotFoundError as exc:
            yield sse({"type": "error", "message": str(exc)})
        except Exception as exc:  # noqa: BLE001
            logger.exception("traffic analysis failed")
            yield sse({"type": "error", "message": str(exc)[:500]})

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
