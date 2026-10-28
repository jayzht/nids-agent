"""FastAPI 应用入口。"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.agent.checkpointer import close as close_checkpointer
from app.agent.checkpointer import setup as setup_checkpointer
from app.api import chat, evals, kb, siem, traffic
from app.deps import get_siem_store
from app.kb import get_kb_manager
from app.settings import get_settings
from app.siem.tailer import watch

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("devrag")

WEB_DIR = Path(__file__).parent / "web"


@asynccontextmanager
async def lifespan(app: FastAPI):
    s = get_settings()
    mgr = get_kb_manager()
    names = mgr.names()
    logger.info("DevRAG 启动 | LLM=%s | Embedding=%s | 知识库=%s",
                s.llm_model, s.embedding_model, names or "（空）")

    async def preload() -> None:
        for n in names:
            try:
                await asyncio.to_thread(mgr.get, n)
                logger.info("预热完成：%s", n)
            except Exception as exc:  # noqa: BLE001
                logger.warning("预热 %s 失败：%s", n, exc)

    await setup_checkpointer(s)

    task = asyncio.create_task(preload())
    tail_task = None
    if s.siem_tail_paths:
        tail_task = asyncio.create_task(
            watch(s.siem_tail_paths, get_siem_store(), s.siem_tail_interval)
        )
    try:
        yield
    finally:
        task.cancel()
        if tail_task:
            tail_task.cancel()
        await close_checkpointer()


app = FastAPI(
    title="DevRAG · 文档智能问答 Agent",
    description="LangGraph + FastAPI + 混合检索 的 RAG 全链路项目",
    version="1.0.0",
    lifespan=lifespan,
)

s = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=s.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(chat.router)
app.include_router(kb.router)
app.include_router(evals.router)
app.include_router(traffic.router)
app.include_router(siem.router)


@app.get("/healthz", tags=["ops"])
async def healthz():
    return {"ok": True, "kbs": get_kb_manager().names()}


@app.get("/api/info", tags=["ops"])
async def info():
    s = get_settings()
    return {
        "llm": {"model": s.llm_model, "base_url": s.llm_base_url},
        "embedding": {"model": s.embedding_model},
        "retrieval": {
            "vector_backend": s.vector_backend,
            "top_k": s.top_k,
            "candidate_k": s.candidate_k,
            "bm25_weight": s.bm25_weight,
            "fusion": s.fusion,
            "retrieval_mode": s.retrieval_mode,
            "rerank_mode": s.rerank_mode,
        },
        "chunking": {"chunk_tokens": s.chunk_tokens, "overlap": s.chunk_overlap_tokens},
        "kbs": get_kb_manager().list_meta(),
    }


@app.get("/", include_in_schema=False)
async def index():
    return FileResponse(WEB_DIR / "index.html")


app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")
