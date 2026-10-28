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


def _get(url: str, timeout: str = "120") -> str:
    """带重定向跟随与重试的 GET。

    踩过：这个站偶发返回 301/空响应（同一个 URL 有时 200、有时只剩 196 字节），
    不加 -L 就会误判成「目录里没文件」。
    """
    import subprocess

    for _ in range(3):
        out = subprocess.run(
            ["curl", "-sSL", "--max-time", timeout, "--retry", "2", url],
            capture_output=True, text=True,
        ).stdout
        if out and len(out) > 400:
            return out
    return out


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


def fetch(capture_id: str, base: str = "CTU-Malware-Capture-Botnet") -> Path | None:
    # CTU 家族的目录名要拼前缀；IoT-23 的子目录本身就是完整名字
    # 已经是完整目录名（CTU-13 / IoT-23 的子目录都以 CTU- 开头）就直接用
    full = capture_id.startswith(("CTU-", base))
    name = capture_id if full else f"{base}-{capture_id}"
    # 目录相对路径：CTU 家族的 name 自带 base 前缀；IoT-23 的 name 是 CTU-xxx，要补 base/
    rel = name if name.startswith(base) else f"{base}/{name}"
    out_dir = ROOT / "data" / "labeled" / base / name
    out_dir.mkdir(parents=True, exist_ok=True)


    html = _get(f"{BASE}/{rel}/")
    files = [
        h for h in re.findall(r'href="([^"?][^"]*)"', html)
        if h.endswith((".pcap", ".binetflow", "-labeled", ".labeled"))
    ]
    # IoT-23 把 pcap 放在 pcap/ 子目录、标注在根目录或 zeek-labeled/
    if not any(f.endswith(".pcap") for f in files):
        for sub in ("pcap/", "zeek-labeled/"):
            sub_html = _get(f"{BASE}/{rel}/{sub}")
            files += [
                sub + h for h in re.findall(r'href="([^"?][^"]*)"', sub_html)
                if h.endswith((".pcap", "-labeled", ".labeled"))
            ]
    if not files:
        log(f"  !! {capture_id} 目录里没有 pcap/binetflow")
        return None

    readme = _get(f"{BASE}/{rel}/README.md", timeout="60")
    m = re.search(r"Probable Name:\s*(.+)", readme)
    family = m.group(1).strip() if m else "未知"

    for f in files:
        target = out_dir / Path(f).name
        mb = size_mb(f"{BASE}/{rel}/{f}")
        if target.exists() and target.stat().st_size > 0:
            log(f"  已存在 {f}（{target.stat().st_size / 1048576:.1f}MB）")
            continue
        log(f"  下载 {f}（{mb:.1f}MB）…")
        curl(f"{BASE}/{rel}/{f}", target)
    log(f"  完成：{rel} = {family} → {out_dir.relative_to(ROOT)}")
    return out_dir


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ids", default="", help="逗号分隔，如 409-2,267-1")
    ap.add_argument("--base", default="CTU-Malware-Capture-Botnet",
                    help="数据集目录名（如 IoT-23-Dataset-v2），id 即其下的子目录")
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
        out = fetch(cid, base=args.base)
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
