#!/usr/bin/env python3
"""下载公开的真实恶意流量样本（用于验证检测规则，**不随仓库分发**）。

来源：
    SpiderLabs/IOCs-IDPS —— Trustwave 公开的 IOC/PCAP 仓库，按恶意家族分类
    仓库地址：https://github.com/SpiderLabs/IOCs-IDPS

重要：
1. 这些 pcap **不提交进 git**（体积 + 授权），只在本机 data/pcaps/real/ 下；
2. 仅供本地研究/学习，不要再分发；商用请自行确认授权；
3. 下载后用 `scripts/benchmark_real.py` 跑一遍，得到检测率与误报情况。

用法：
    python scripts/fetch_real_pcaps.py                 # 全部
    python scripts/fetch_real_pcaps.py --list
    python scripts/fetch_real_pcaps.py --only dnscat2,njrat
    python scripts/fetch_real_pcaps.py --proxy http://127.0.0.1:7890
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.parse
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from _net import log, proxy_candidates  # noqa: E402

REPO = "SpiderLabs/IOCs-IDPS"
OUT = ROOT / "data" / "pcaps" / "real"

# family, file, 期望命中的检测项（None = 应当不报，用于误报对照）
CATALOG: list[dict] = [
    {"key": "dnscat2", "family": "CobaltStrike/C2 隧道", "path": "Beacons/dnscat2.pcap",
     "expect": ["dns_tunnel"], "note": "DNS 隧道型 C2，dnscat2"},
    {"key": "ps-empire", "family": "PowerShell Empire", "path": "Beacons/ps-empire.pcap",
     "expect": ["beacon"], "note": "Empire 心跳"},
    {"key": "blacknet", "family": "BlackNET botnet", "path": "Beacons/blacknet.pcap",
     "expect": ["beacon"], "note": "Linux 僵尸网络心跳"},
    {"key": "bot_scanner", "family": "Bot/Scanner", "path": "Bots_Scanners/Bot_Scanner_12May2019.pcap",
     "expect": ["repeated_attempts"], "note": "批量扫描"},
    {"key": "mirai", "family": "Mirai", "path": "Mirai/2016-11-07-10:35.pcap",
     "expect": ["repeated_attempts"], "note": "IoT 僵尸网络 Telnet 扫描"},
    {"key": "njrat", "family": "njRAT", "path": "njRAT/njrat_20190910.pcap",
     "expect": ["beacon"], "note": "RAT 回连"},
    {"key": "lokibot", "family": "LokiBot", "path": "lokibot/lokibot.pcap",
     "expect": [], "note": "窃密木马，主要看 HTTP 外传"},
    {"key": "emotet", "family": "Emotet", "path": "Emotet_Banker/emotet_ssl.pcap",
     "expect": [], "note": "Emotet TLS 下载"},
    {"key": "hancitor", "family": "Hancitor", "path": "Hancitor/hancitor.pcap",
     "expect": [], "note": "下载器"},
    {"key": "printnightmare", "family": "PrintNightmare 扫描",
     "path": "PrintNightmare_CVE-2021-34527/PrintNightmare_Scanner.pcap",
     "expect": ["port_scan"], "note": "SMB 漏洞探测"},
    {"key": "bluekeep", "family": "CVE-2019-0708",
     "path": "CVE-2019-0708/Metasploit_CVE-2019-0708.pcap",
     "expect": [], "note": "单包 RDP 漏洞利用，行为规则抓不到"},
    {"key": "predator", "family": "Predator RAT",
     "path": "Predator_RAT/predator_stealer_14July2019.pcap",
     "expect": [], "note": "窃密木马"},
    {"key": "normal_rdp", "family": "正常 RDP（误报对照）",
     "path": "CVE-2019-0708/normal_rdp.pcap",
     "expect": ["__none__"], "note": "合法 RDP 会话，不应该报"},
]


def default_branch(client: httpx.Client) -> str:
    try:
        return client.get(f"https://api.github.com/repos/{REPO}").json().get("default_branch", "master")
    except Exception:  # noqa: BLE001
        return "master"


def download(client: httpx.Client, branch: str, item: dict, proxies: list[str | None]) -> Path:
    target = OUT / item["key"] / Path(item["path"]).name
    if target.exists() and target.stat().st_size > 0:
        log(f"  [cache] {target.name}")
        return target
    target.parent.mkdir(parents=True, exist_ok=True)
    url = (
        f"https://raw.githubusercontent.com/{REPO}/{branch}/"
        + urllib.parse.quote(item["path"])
    )
    last: Exception | None = None
    for _ in range(2):
        for proxy in proxies:
            try:
                with httpx.Client(proxy=proxy, timeout=90, follow_redirects=True) as c:
                    resp = c.get(url)
                    resp.raise_for_status()
                    target.write_bytes(resp.content)
                    log(f"  {item['key']:16s} {len(resp.content)/1024:8.1f} KB")
                    return target
            except Exception as exc:  # noqa: BLE001
                last = exc
                time.sleep(1)
    raise RuntimeError(f"下载失败 {url}: {last}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--proxy", default=None)
    ap.add_argument("--only", default="")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    if args.list:
        for it in CATALOG:
            print(f"{it['key']:16s} {it['family']:24s} {it['path']}")
        return

    wanted = {x.strip() for x in args.only.split(",") if x.strip()}
    items = [it for it in CATALOG if not wanted or it["key"] in wanted]
    proxies = proxy_candidates(args.proxy)
    OUT.mkdir(parents=True, exist_ok=True)

    with httpx.Client(timeout=30, headers={"User-Agent": "devrag-research"}) as client:
        branch = default_branch(client)

    ok = 0
    for it in items:
        try:
            download(client, branch, it, proxies)
            ok += 1
        except Exception as exc:  # noqa: BLE001
            log(f"  !! {it['key']} 失败：{str(exc)[:150]}")

    (OUT / "sources.json").write_text(
        json.dumps(
            {
                "source": f"https://github.com/{REPO}",
                "license_note": "仅用于本地研究验证，请勿再分发；商用请自行确认授权",
                "items": [
                    {"key": it["key"], "family": it["family"], "path": it["path"],
                     "expect": it["expect"], "note": it["note"]} for it in CATALOG
                ],
            },
            ensure_ascii=False, indent=2,
        ),
        encoding="utf-8",
    )
    log(f"\n完成：{ok}/{len(items)} 份 -> {OUT}")
    log("下一步: python scripts/benchmark_real.py")


if __name__ == "__main__":
    main()
