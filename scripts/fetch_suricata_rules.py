#!/usr/bin/env python3
"""下载 Suricata 引擎镜像（可选）与 ET Open 规则集。"""

from __future__ import annotations

import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEST = ROOT / "data" / "suricata" / "rules"
URL = "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz"
IMAGE = "jasonish/suricata:latest"


def main() -> None:
    DEST.mkdir(parents=True, exist_ok=True)
    tarball = DEST / "et.tar.gz"
    if not tarball.exists():
        print(f"下载规则 {URL}")
        urllib.request.urlretrieve(URL, tarball)
    with tarfile.open(tarball) as tf:
        tf.extractall(DEST)
    rules_dir = DEST / "rules"
    files = sorted(rules_dir.glob("*.rules"))
    # Suricata 的 -S 只接受单个文件，合并成 all.rules
    merged = DEST / "all.rules"
    with merged.open("w", encoding="utf-8") as out:
        for f in files:
            out.write(f.read_text(encoding="utf-8", errors="ignore"))
            out.write("\n")
    print(f"合并 {len(files)} 个规则文件 -> {merged} ({merged.stat().st_size/1e6:.1f} MB)")

    try:
        subprocess.run(["docker", "pull", IMAGE], check=True, timeout=600)
        print(f"镜像就绪：{IMAGE}")
    except Exception as exc:  # noqa: BLE001
        print(f"镜像拉取失败（已有镜像可忽略）：{exc}", file=sys.stderr)


if __name__ == "__main__":
    main()
