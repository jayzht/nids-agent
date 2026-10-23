#!/usr/bin/env python3
"""检索超参扫描：不重建索引、不调 LLM，几秒钟跑完。

用来回答这类问题：「bm25 和向量的权重到底怎么定？」——靠数据，不靠感觉。

    python scripts/sweep.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.eval.runner import run_eval  # noqa: E402
from app.kb import get_kb_manager  # noqa: E402
from app.retrieval.service import Retriever  # noqa: E402
from app.settings import get_settings  # noqa: E402


async def main() -> None:
    s = get_settings()
    mgr = get_kb_manager()
    retriever = Retriever(mgr, s)

    grid = [
        (w, mode, cand)
        for w in (0.0, 0.3, 0.5, 0.7, 1.0)
        for mode in ("none", "lexical")
        for cand in (40,)
    ]

    print(f"{'bm25_w':>7} {'rerank':>8} {'cand':>5} {'recall@6':>9} {'mrr':>7} {'ndcg@6':>7}")
    best = None
    for w, mode, cand in grid:
        s.bm25_weight, s.rerank_mode, s.candidate_k = w, mode, cand
        result = await run_eval(retriever, mgr, kb=None, mode="retrieval", top_k=6)
        m = result["summary"]
        print(f"{w:7.1f} {mode:>8} {cand:5d} {m['recall@6']:9.3f} {m['mrr']:7.3f} {m['ndcg@6']:7.3f}")
        if best is None or m["ndcg@6"] > best[0]:
            best = (m["ndcg@6"], w, mode, cand)

    print(f"\n最佳组合（按 nDCG@6）：bm25_weight={best[1]}, rerank={best[2]}, candidate_k={best[3]}")
    print("把这三个值写进 .env 即可生效。")


if __name__ == "__main__":
    asyncio.run(main())
