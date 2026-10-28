#!/usr/bin/env python3
"""最小的 cross-encoder rerank 服务（GPU 容器里跑）。

接口和 HuggingFace TEI 的 /rerank 对齐：
    POST /rerank {"query": "...", "texts": ["..."]} -> [{"index": 0, "score": 3.2}]

为什么自己写：TEI 的 GPU 镜像从 ghcr 拉不下来（网络），
但用 python:3.12-slim + CUDA 版 torch 自己搭一个效果一样，代码还透明。
"""

from __future__ import annotations

import os

import torch
from fastapi import FastAPI
from pydantic import BaseModel
from transformers import AutoModelForSequenceClassification, AutoTokenizer

MODEL_PATH = os.environ.get("RERANK_MODEL_PATH", "/models/reranker")
MAX_LENGTH = int(os.environ.get("RERANK_MAX_LENGTH", "512"))
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

app = FastAPI(title="devrag-reranker")
tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH).to(DEVICE).eval()


class RerankRequest(BaseModel):
    query: str
    texts: list[str]
    truncate: bool = True
    raw_scores: bool = False
    top_n: int | None = None


@app.get("/health")
def health() -> dict:
    return {"ok": True, "device": DEVICE, "cuda": torch.cuda.is_available()}


@app.post("/rerank")
def rerank(req: RerankRequest) -> list[dict]:
    pairs = [(req.query, t) for t in req.texts]
    with torch.inference_mode():
        enc = tokenizer(
            [p[0] for p in pairs], [p[1] for p in pairs],
            padding=True, truncation=True, max_length=MAX_LENGTH, return_tensors="pt",
        ).to(DEVICE)
        scores = model(**enc).logits.view(-1).float().tolist()
    out = [{"index": i, "score": float(s)} for i, s in enumerate(scores)]
    out.sort(key=lambda x: -x["score"])
    return out[: req.top_n] if req.top_n else out
