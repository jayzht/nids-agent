#!/usr/bin/env python3
"""下载 CTU-13（带标注的僵尸网络流量数据集）并解压。

为什么用它：项目现在的真实样本是「30 份精选恶意 pcap」，只能证明检出，
**证明不了误报率**——里面没有大段正常背景流量。CTU-13 是同一台机器上
采集的「僵尸网络 + 正常 + 背景」混合流量，每个场景都带逐流标注
（capture*.binetflow），所以能同时算精确率和召回率。

数据来源：https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/
许可：CC-BY（引用论文 Garcia et al., "An empirical comparison of botnet
detection methods", Computers & Security, 2014）。

用法：
    python scripts/fetch_ctu13.py --scenarios 1        # 只解出场景 1（推荐先跑一个）
    python scripts/fetch_ctu13.py --all                # 全部 13 个（约 2GB 压缩包）
    python scripts/fetch_ctu13.py --scenarios 1 --skip-download   # 已下载过

设计说明：
- 单连接实测只有 ~1MB/s（2GB 要半小时），所以按 Range 分片并发拉取；
- 每个分片独立重试、可续传，中断后重跑会跳过已完成的分片；
- 解压时按场景过滤，不会把 2GB 全部落盘。
"""

from __future__ import annotations

import argparse
import concurrent.futures
import os
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
URL = "https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/CTU-13-Dataset.tar.bz2"
TOTAL = 1_997_547_391          # 服务器给的 Content-Length，改了要重新确认
CHUNK = 64 * 1024 * 1024       # 单分片 64MB
WORKERS = 8


def log(msg: str) -> None:
    print(msg, flush=True)


def download(dest: Path, url: str = URL, total: int = TOTAL) -> Path:
    """分片并发下载 + 断点续传。"""
    parts = dest.with_suffix(dest.suffix + ".parts")
    parts.mkdir(parents=True, exist_ok=True)
    n = (total + CHUNK - 1) // CHUNK

    def fetch(i: int) -> Path:
        start = i * CHUNK
        end = min(start + CHUNK, total) - 1
        out = parts / f"{i:05d}"
        want = end - start + 1
        if out.exists() and out.stat().st_size == want:
            return out
        for attempt in range(4):
            try:
                cmd = [
                    "curl", "-sS", "--fail", "--max-time", "600",
                    "--retry", "2", "--range", f"{start}-{end}",
                    "-o", str(out) + ".tmp", url,
                ]
                subprocess.run(cmd, check=True, timeout=700)
                if (out.with_suffix(".tmp")).stat().st_size != want:
                    raise RuntimeError(f"分片 {i} 长度不对")
                os.replace(str(out) + ".tmp", out)
                return out
            except Exception as exc:  # noqa: BLE001
                log(f"  分片 {i} 第 {attempt + 1} 次失败：{exc}")
                time.sleep(2 * (attempt + 1))
        raise RuntimeError(f"分片 {i} 下载失败")

    missing = [i for i in range(n) if not (parts / f"{i:05d}").exists()]
    log(f"分片下载：共 {n} 片，缺 {len(missing)} 片，并发 {WORKERS}")
    t0 = time.time()
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = [pool.submit(fetch, i) for i in missing]
        for fut in concurrent.futures.as_completed(futures):
            fut.result()
            done += 1
            if done % 4 == 0 or done == len(missing):
                mb = done * CHUNK / 1e6
                rate = mb / max(time.time() - t0, 1e-9)
                log(f"  {done}/{len(missing)} 片 · {mb:.0f}MB · {rate:.1f}MB/s")

    # 合并
    if not dest.exists() or dest.stat().st_size != total:
        with dest.open("wb") as fh:
            for i in range(n):
                fh.write((parts / f"{i:05d}").read_bytes())
    size = dest.stat().st_size
    if size != total:
        raise RuntimeError(f"合并后大小 {size} != {total}")
    log(f"完成：{dest}（{size / 1e9:.2f}GB）")
    return dest


def list_scenarios(archive: Path) -> list[str]:
    with tarfile.open(archive, "r:bz2") as tf:
        names = tf.getnames()
    tops = set()
    for n in names:
        parts = n.split("/")
        if len(parts) >= 2 and parts[1].isdigit():
            tops.add(parts[1])
    return sorted(tops, key=int)


def extract(archive: Path, out_dir: Path, scenarios: list[str], all_scenarios: bool) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    wanted = None if all_scenarios else set(scenarios)
    got: list[Path] = []
    log(f"解压到 {out_dir}（{'全部' if all_scenarios else ','.join(scenarios)}）")
    with tarfile.open(archive, "r:bz2") as tf:
        for m in tf:
            parts = m.name.split("/")
            # 成员形如 CTU-13-Dataset/<场景号>/xxx.pcap
            if len(parts) < 3 or not parts[1].isdigit():
                continue
            top = parts[1]
            if wanted is not None and top not in wanted:
                continue
            if m.isdir():
                continue
            # 只留 pcap 和标注文件：exe/zip 对评测没用，还占空间
            if not (m.name.endswith(".pcap") or m.name.endswith(".binetflow")):
                continue
            # 去掉压缩包顶层的 CTU-13-Dataset/，落成 <scenario>/xxx.pcap
            target = out_dir / "/".join(parts[1:])
            if target.exists() and target.stat().st_size == m.size:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(m)
            if src is None:
                continue
            with target.open("wb") as fh:
                shutil.copyfileobj(src, fh)
            got.append(target)
            log(f"  ✔ {target.relative_to(out_dir)}（{m.size / 1e6:.1f}MB）")
    return got


def summarize(out_dir: Path) -> None:
    """打印每个场景的标注分布，确认数据可用。"""
    sys.path.insert(0, str(ROOT))
    from app.eval.labeled import iter_binetflow

    for flow in sorted(out_dir.rglob("*.binetflow")):
        labels: dict[str, int] = {}
        with flow.open(encoding="utf-8", errors="replace") as fh:
            for f in iter_binetflow(fh):
                key = "botnet" if f.malicious else ("background" if "background" in f.label.lower() else "normal")
                labels[key] = labels.get(key, 0) + 1
        total = max(sum(labels.values()), 1)
        dist = " · ".join(f"{k} {v}（{v / total:.1%}）" for k, v in sorted(labels.items()))
        log(f"  {flow.parent.name}/{flow.name}: {total} 条流 · {dist}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/labeled/ctu13", help="解压目录")
    ap.add_argument("--archive", default="data/.cache/CTU-13-Dataset.tar.bz2")
    ap.add_argument("--scenarios", default="1", help="逗号分隔的场景编号")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--skip-download", action="store_true")
    args = ap.parse_args()

    archive = ROOT / args.archive
    out_dir = ROOT / args.out
    archive.parent.mkdir(parents=True, exist_ok=True)

    if not args.skip_download:
        if archive.exists() and archive.stat().st_size == TOTAL:
            log(f"已存在，跳过下载：{archive}")
        else:
            # 这个站直连比走代理快（实测代理直接超时）
            for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
                os.environ.pop(k, None)
            download(archive)

    scenarios = [s.strip() for s in args.scenarios.split(",") if s.strip()]
    extract(archive, out_dir, scenarios, args.all)
    log("标注分布：")
    summarize(out_dir)

    total = sum(f.stat().st_size for f in out_dir.rglob("*") if f.is_file())
    log(f"落盘合计 {total / 1e9:.2f}GB → {out_dir}")
    shutil.rmtree(archive.with_suffix(archive.suffix + ".parts"), ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
