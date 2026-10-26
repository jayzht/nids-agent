#!/usr/bin/env python3
"""增量消费 Suricata eve.json（命令行版）。

    python scripts/tail_eve.py --path data/alerts/eve.jsonl          # 消费一次
    python scripts/tail_eve.py --path data/alerts/eve.jsonl --follow # 持续 tail
    python scripts/tail_eve.py --cursors                              # 看游标
    python scripts/tail_eve.py --path ... --reset                     # 忽略游标重读
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.siem.store import AlertStore  # noqa: E402
from app.siem.tailer import EveTailer  # noqa: E402
from app.settings import get_settings  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", default="data/alerts/eve.jsonl")
    ap.add_argument("--db", default=None)
    ap.add_argument("--reset", action="store_true")
    ap.add_argument("--follow", action="store_true")
    ap.add_argument("--interval", type=float, default=2.0)
    ap.add_argument("--cursors", action="store_true")
    args = ap.parse_args()

    s = get_settings()
    store = AlertStore(args.db or s.siem_db)
    tailer = EveTailer(store)

    if args.cursors:
        for c in tailer.cursors():
            print(f"{c['path']}  offset={c['offset']} lines={c['lines']}")
        return

    path = Path(args.path) if Path(args.path).is_absolute() else ROOT / args.path
    if args.reset:
        tailer.reset(path)

    while True:
        res = tailer.poll(path)
        if res.get("error"):
            sys.exit(res["error"])
        print(f"[{time.strftime('%H:%M:%S')}] +{res['new_alerts']} 条 "
              f"(读 {res['lines_read']} 行, offset={res['offset']}/{res['size']}"
              f"{', 已重置' if res['reset'] else ''})")
        if not args.follow:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
