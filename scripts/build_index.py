#!/usr/bin/env python3
"""构建/重建知识库索引。

    python scripts/build_index.py              # 全部
    python scripts/build_index.py --kb fastapi
    python scripts/build_index.py --kb all --force
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.kb import get_kb_manager  # noqa: E402
from app.settings import get_settings  # noqa: E402


async def build_one(name: str) -> None:
    s = get_settings()
    mgr = get_kb_manager()
    raw = s.raw_dir / name
    if not raw.exists():
        print(f"  !! 缺少语料目录 {raw}，先跑 scripts/fetch_corpus.py")
        return

    t0 = time.time()
    last_phase = {"v": ""}

    def progress(phase: str, cur: int, total: int, msg: str = "") -> None:
        if phase != last_phase["v"] or cur == total:
            last_phase["v"] = phase
            pct = 100 * cur / total if total else 0
            print(f"\r  [{phase:5s}] {cur}/{total} ({pct:5.1f}%) {msg}          ", end="", flush=True)

    index = await mgr.build(name=name, progress=progress)
    stats = index.stats()
    print(
        f"\r  ✔ {stats['name']}: {stats['num_docs']} docs / {stats['num_chunks']} chunks "
        f"in {time.time() - t0:.1f}s (embed={stats['embedding_model']})"
    )


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kb", default="all")
    ap.add_argument("--force", action="store_true", help="已存在也重建（默认就是重建）")
    args = ap.parse_args()

    s = get_settings()
    names = [d.name for d in s.raw_dir.iterdir() if d.is_dir() and (d / "manifest.json").exists()]
    if args.kb != "all":
        names = [n.strip() for n in args.kb.split(",") if n.strip()]

    if not names:
        sys.exit("没有可用语料，先执行: python scripts/fetch_corpus.py")

    print(f"构建知识库: {', '.join(names)}")
    for n in names:
        await build_one(n)


if __name__ == "__main__":
    asyncio.run(main())
