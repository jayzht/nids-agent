#!/usr/bin/env python3
"""把本地 pcap 的检测结果转成 Suricata eve.json 风格的告警，推给 SIEM 接口。

用途：没有真实 Suricata 也能演示「告警流 → 聚合 → 研判」整条链路。
本脚本同时是「行为检测」和「签名检测」的接缝：真实环境里这一端换成 Suricata 即可。

    python scripts/emit_alerts.py                     # 写到 data/alerts/eve.jsonl
    python scripts/emit_alerts.py --post http://127.0.0.1:8123
    python scripts/emit_alerts.py --source real       # 用真实恶意流量
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.traffic.analyzer import TrafficAnalyzer  # noqa: E402

SEV = {"high": 1, "medium": 2, "low": 3, "info": 4}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default="samples", choices=["samples", "real", "all"])
    ap.add_argument("--out", default=str(ROOT / "data" / "alerts" / "eve.jsonl"))
    ap.add_argument("--post", default="", help="API 地址，如 http://127.0.0.1:8123")
    args = ap.parse_args()

    root = ROOT / "data" / "pcaps"
    dirs = []
    if args.source in ("samples", "all"):
        dirs.append(root / "samples")
    if args.source in ("real", "all"):
        dirs.append(root / "real")
    pcaps = [p for d in dirs if d.exists() for p in sorted(d.rglob("*.pcap"))]
    if not pcaps:
        sys.exit("没有找到 pcap，先跑 scripts/make_sample_pcaps.py 或 scripts/fetch_real_pcaps.py")

    analyzer = TrafficAnalyzer()
    lines: list[str] = []
    for pcap in pcaps:
        try:
            analysis = analyzer.analyze(pcap)
        except Exception as exc:  # noqa: BLE001
            print(f"跳过 {pcap.name}: {exc}")
            continue
        top = analysis.top_talkers[0] if analysis.top_talkers else {"src": "", "dst": "", "dport": 0}
        for f in analysis.findings:
            ts = datetime.fromtimestamp(analysis.first_ts, tz=timezone.utc).isoformat()
            obj = {
                "timestamp": ts,
                "event_type": "alert",
                "src_ip": f.src_ip or top["src"],
                "dest_ip": f.dst_ip or top["dst"],
                "dest_port": f.dst_port or top["dport"],
                "proto": "TCP",
                "alert": {
                    "signature": f.title,
                    "category": f.kind,
                    "severity": SEV.get(f.severity, 3),
                },
                "payload": f.detail[:300],
                "pcap": str(pcap.relative_to(root)),
            }
            lines.append(json.dumps(obj, ensure_ascii=False))
        print(f"{pcap.relative_to(root)!s:42s} {len(analysis.findings)} alerts")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\n共 {len(lines)} 条告警 -> {out}")

    if args.post:
        url = args.post.rstrip("/") + "/api/siem/ingest"
        with httpx.Client(timeout=30) as c:
            resp = c.post(url, content="\n".join(lines),
                          headers={"Content-Type": "text/plain"})
            print("推送结果:", resp.status_code, resp.text[:300])


if __name__ == "__main__":
    main()
