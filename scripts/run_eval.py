#!/usr/bin/env python3
"""命令行评估。

    python scripts/run_eval.py                    # 全部知识库，只测检索
    python scripts/run_eval.py --kb fastapi
    python scripts/run_eval.py --mode end2end     # 端到端（会跑 LLM，慢）
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.eval.runner import run_eval  # noqa: E402
from app.kb import get_kb_manager  # noqa: E402
from app.retrieval.service import Retriever  # noqa: E402
from app.settings import get_settings  # noqa: E402


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kb", default=None)
    ap.add_argument("--mode", default="retrieval", choices=["retrieval", "end2end"])
    ap.add_argument("--top-k", type=int, default=6)
    ap.add_argument("--limit", type=int, default=None, help="只跑前 N 题（快速对比用）")
    ap.add_argument("--json", action="store_true", help="输出完整 JSON")
    args = ap.parse_args()

    s = get_settings()
    result = await run_eval(
        retriever=Retriever(get_kb_manager(), s),
        manager=get_kb_manager(),
        kb=args.kb,
        mode=args.mode,
        top_k=args.top_k,
        limit=args.limit,
    )

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    if result.get("error"):
        sys.exit(result["error"])

    print(f"\n模式={result['mode']}  知识库={result['kb']}  题数={result['num_questions']}  "
          f"耗时={result['elapsed']}s\n")
    print("汇总指标：")
    for k, v in result["summary"].items():
        print(f"  {k:22s} {v}")

    print("\n明细：")
    for row in result["details"]:
        flag = "✔" if row.get(f"recall@{args.top_k}", 0) >= 1 else "✘"
        print(f"  {flag} [{row['kb']}] {row['question'][:50]}")
        print(f"      top1={row['retrieved'][0] if row['retrieved'] else '-'}")
        if args.mode == "end2end":
            print(f"      verdict={row.get('verdict')} kw={row.get('keyword_coverage')} "
                  f"faithfulness={row.get('faithfulness')}")


if __name__ == "__main__":
    asyncio.run(main())
