#!/usr/bin/env python3
"""下载 CTU-Malware-Capture-Botnet-* 单个抓包（pcap + binetflow 标注）。

为什么不继续用 CICIDS2017：
- Engelen et al., "Troubleshooting an Intrusion Detection Dataset: the CICIDS2017
  Case Study"（WTMC 2021）已指出它在**流量生成、流构造、特征提取、标注**四个环节
  都有问题，>20% 的原始流量被重新构造或重新标注；
- 而且它按天给 pcap（每天数 GB），我们这种 pcap → tshark → Suricata 的链路跑不动。

为什么选这个系列：和已接入的 CTU-13 是同一套采集/标注工具链（binetflow 逐流标注），
**评测代码零改动**；每个抓包是独立目录，pcap 通常 10~200MB，可只下需要的；
时间跨度 2016-2021，正好补 CTU-13（2011）的年代盲区。

用法：
    python scripts/fetch_ctu_capture.py --ids 409-2,267-1
    python scripts/fetch_ctu_capture.py --list 20      # 看看有哪些抓包
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASE = "https://mcfp.felk.cvut.cz/publicDatasets"
TIMEOUT = "600"


def log(msg: str) -> None:
    print(msg, flush=True)


def curl(url: str, out: Path | None = None, head: bool = False) -> str:
    import subprocess

    cmd = ["curl", "-sS", "--fail", "--max-time", TIMEOUT, "--retry", "2"]
    if head:
        cmd.append("-I")
    if out:
        cmd += ["-o", str(out)]
    cmd.append(url)
    env = {"http_proxy": "", "https_proxy": "", "HTTP_PROXY": "", "HTTPS_PROXY": ""}
    import os

    full_env = {**os.environ, **env}
    if head:
        return subprocess.run(cmd, capture_output=True, text=True, env=full_env).stdout
    subprocess.run(cmd, check=True, capture_output=True, text=True, env=full_env)
    return ""


def size_mb(url: str) -> float:
    head = curl(url, head=True)
    m = re.search(r"(?i)content-length:\s*(\d+)", head)
    return int(m.group(1)) / 1048576 if m else 0.0


def list_captures(limit: int) -> list[str]:
    import subprocess

    html = subprocess.run(
        ["curl", "-sS", "--max-time", "120", f"{BASE}/"],
        capture_output=True, text=True,
    ).stdout
    ids = sorted(
        {m.group(1) for m in re.finditer(r'href="CTU-Malware-Capture-Botnet-([^"/]+)/?"', html)},
        key=lambda s: (len(s), s),
    )
    return ids[:limit]


def fetch(capture_id: str) -> Path | None:
    name = f"CTU-Malware-Capture-Botnet-{capture_id}"
    out_dir = ROOT / "data" / "labeled" / "ctu-botnet" / capture_id
    out_dir.mkdir(parents=True, exist_ok=True)

    import subprocess

    html = subprocess.run(
        ["curl", "-sS", "--max-time", "120", f"{BASE}/{name}/"],
        capture_output=True, text=True,
    ).stdout
    files = [h for h in re.findall(r'href="([^"?][^"]*)"', html) if h.endswith((".pcap", ".binetflow"))]
    if not files:
        log(f"  !! {capture_id} 目录里没有 pcap/binetflow")
        return None

    readme = subprocess.run(
        ["curl", "-sS", "--max-time", "60", f"{BASE}/{name}/README.md"],
        capture_output=True, text=True,
    ).stdout
    m = re.search(r"Probable Name:\s*(.+)", readme)
    family = m.group(1).strip() if m else "未知"

    for f in files:
        target = out_dir / f
        mb = size_mb(f"{BASE}/{name}/{f}")
        if target.exists() and target.stat().st_size > 0:
            log(f"  已存在 {f}（{target.stat().st_size / 1048576:.1f}MB）")
            continue
        log(f"  下载 {f}（{mb:.1f}MB）…")
        curl(f"{BASE}/{name}/{f}", target)
    log(f"  完成：{capture_id} = {family} → {out_dir.relative_to(ROOT)}")
    return out_dir


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ids", default="", help="逗号分隔，如 409-2,267-1")
    ap.add_argument("--list", type=int, default=0, help="列出前 N 个抓包 id")
    args = ap.parse_args()

    if args.list:
        for i in list_captures(args.list):
            print(i)
        return
    if not args.ids:
        raise SystemExit("需要 --ids 或 --list")

    sys.path.insert(0, str(ROOT))
    from app.eval.labeled import iter_binetflow

    for cid in [s.strip() for s in args.ids.split(",") if s.strip()]:
        out = fetch(cid)
        if not out:
            continue
        labels: dict[str, int] = {}
        flow = next(out.glob("*.binetflow"), None)
        if flow:
            with flow.open(encoding="utf-8", errors="replace") as fh:
                for f in iter_binetflow(fh):
                    key = "botnet" if f.malicious else "background"
                    labels[key] = labels.get(key, 0) + 1
            total = max(sum(labels.values()), 1)
            dist = " · ".join(f"{k} {v}（{v / total:.1%}）" for k, v in sorted(labels.items()))
            log(f"  标注分布：{total} 条流 · {dist}")


if __name__ == "__main__":
    main()
