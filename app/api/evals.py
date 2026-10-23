"""评估接口。"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.schemas import EvalRequest
from app.deps import get_retriever
from app.eval.runner import load_dataset, run_eval
from app.kb import get_kb_manager

router = APIRouter(prefix="/api/eval", tags=["eval"])


@router.get("/dataset")
async def dataset(kb: str | None = None):
    rows = load_dataset(kb)
    return {"num": len(rows), "items": rows}


@router.post("/run")
async def run(req: EvalRequest):
    return await run_eval(
        retriever=get_retriever(),
        manager=get_kb_manager(),
        kb=req.kb,
        mode=req.mode,
        top_k=req.top_k,
    )
