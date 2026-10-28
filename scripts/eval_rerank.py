#!/usr/bin/env python3
"""重排 A/B 评测：none / lexical / llm / http 四种模式在同一套题上对比。

    python scripts/eval_rerank.py --modes none,http --kb ids
    python scripts/eval_rerank.py --modes none,lexical,llm --limit 20
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.eval.runner import run_eval  # noqa: E402
from app.kb import get_kb_manager  # noqa: E402
from app.retrieval.service import Retriever  # noqa: E402
from app.settings import get_settings  # noqa: E402


def service_alive(url: str) -> bool:
    try:
        base = url.rsplit("/", 1)[0]
        return httpx.get(f"{base}/health", timeout=3).status_code == 200
    except Exception:  # noqa: BLE001
        return False


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--modes", default="none,http")
    ap.add_argument("--kb", default=None)
    ap.add_argument("--top-k", type=int, default=6)
    ap.add_argument("--candidate-k", type=int, default=None)
    args = ap.parse_args()

    s = get_settings()
    mgr = get_kb_manager()
    retriever = Retriever(mgr, s)

    if args.candidate_k:
        s.candidate_k = args.candidate_k
    modes = [m.strip() for m in args.modes.split(",") if m.strip()]
    if "http" in modes and not service_alive(s.rerank_url):
        print(f"[skip] rerank 服务不可用：{s.rerank_url}")
        modes = [m for m in modes if m != "http"]

    print(f"candidate_k={s.candidate_k} blend={s.rerank_blend} top_k={args.top_k}")
    print(f"{'mode':10s} {'recall@6':>9s} {'MRR':>8s} {'nDCG@6':>8s} {'耗时':>7s}")
    for mode in modes:
        s.rerank_mode = mode
        res = await run_eval(retriever, mgr, kb=args.kb, mode="retrieval", top_k=args.top_k)
        m = res["summary"]
        print(f"{mode:10s} {m['recall@6']:9.3f} {m['mrr']:8.3f} {m['ndcg@6']:8.3f} {res['elapsed']:6.1f}s")


if __name__ == "__main__":
    asyncio.run(main())
