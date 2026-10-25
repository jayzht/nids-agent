#!/usr/bin/env python3
"""在真实恶意流量上跑一遍规则引擎，输出检测率与已知盲区。

这不是「刷分」脚本，而是用来诚实回答两个问题：
1. 这些行为规则在真实流量上到底能不能命中？
2. 命中不了的是哪些？为什么？

结果同时写进 docs/REAL_TRAFFIC_BENCHMARK.md。

用法：python scripts/benchmark_real.py [--write-doc]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.traffic.analyzer import TrafficAnalyzer  # noqa: E402

REAL = ROOT / "data" / "pcaps" / "real"
DOC = ROOT / "docs" / "REAL_TRAFFIC_BENCHMARK.md"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write-doc", action="store_true")
    args = ap.parse_args()

    sources = REAL / "sources.json"
    if not sources.exists():
        sys.exit("缺少真实样本，先运行 python scripts/fetch_real_pcaps.py")
    meta = json.loads(sources.read_text(encoding="utf-8"))
    analyzer = TrafficAnalyzer()

    rows = []
    for item in meta["items"]:
        pcap = next((REAL / item["key"]).glob("*.pcap"), None)
        if not pcap:
            continue
        t0 = time.time()
        analysis = analyzer.analyze(pcap)
        kinds = [f.kind for f in analysis.findings]
        expect = item["expect"]
        # 计分口径：只要有任意一条告警就算检出（不苛求命中我事先猜的那个检测器），
        # 这样才不会因为「改个检测器名字」就把指标刷上去。
        if expect == ["__none__"]:
            status = "✔ 未误报" if not kinds else "✘ 误报"
        else:
            status = "✔ 检出" if kinds else "✘ 漏检"
        rows.append({
            "key": item["key"], "family": item["family"], "note": item["note"],
            "packets": analysis.packet_count, "seconds": round(time.time() - t0, 2),
            "expect": expect, "actual": kinds, "status": status,
        })

    scored = [r for r in rows if r["expect"] != ["__none__"]]
    hit = [r for r in scored if r["status"].startswith("✔")]
    controls = [r for r in rows if r["expect"] == ["__none__"]
                and r["key"] not in {x["key"] for x in scored}]
    fp = [r for r in controls if r["status"].startswith("✘")]

    print(f"{'样本':16s} {'包数':>7s} {'期望':18s} {'实际':28s} 结果")
    for r in rows:
        print(f"{r['key']:16s} {r['packets']:7d} {','.join(r['expect']) or '-':18s} "
              f"{','.join(r['actual']) or '-':28s} {r['status']}")
    print(f"\n检出率：{len(hit)}/{len(scored)}（任意告警即算检出）"
          f"（{(len(hit) / len(scored)) if scored else 0:.0%}）"
          f"  误报对照：{len(controls) - len(fp)}/{len(controls)} 未触发")

    if args.write_doc:
        DOC.write_text(render_doc(rows, hit, scored, controls, fp), encoding="utf-8")
        print(f"已写入 {DOC}")


def render_doc(rows, hit, scored, controls, fp) -> str:
    lines = [
        "# 真实恶意流量验证结果",
        "",
        "> 数据来源：SpiderLabs/IOCs-IDPS（公开 IOC/PCAP 仓库），样本不入库，用 `scripts/fetch_real_pcaps.py` 按需下载。",
        "> 生成方式：`python scripts/benchmark_real.py --write-doc`。",
        "",
        "## 为什么要做这件事",
        "",
        "自己造的样本只能证明「代码能跑」，证明不了「检测有用」。",
        "所以拿真实恶意流量跑一遍，并且**把漏检名单也列出来**——",
        "漏检不是失败，是告诉你「行为规则的能力边界在哪」。",
        "",
        f"## 结果：{len(hit)}/{len(scored)} 份恶意样本产生告警（{len(hit)/max(len(scored),1):.0%}）",
        "",
        "| 样本 | 家族 | 包数 | 期望检测 | 实际命中 | 结果 |",
        "|---|---|---:|---|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| `{r['key']}` | {r['family']} | {r['packets']} | "
            f"{', '.join(r['expect']) or '—'} | {', '.join(r['actual']) or '—'} | {r['status']} |"
        )
    lines += [
        "",
        f"- 恶意样本：**{len(scored)}** 份，产生告警 **{len(hit)}** 份",
        f"- 误报对照（合法 RDP 流量）：{len(controls)} 份，误报 **{len(fp)}** 份",
        "",
        "## 漏检的为什么漏（能力边界）",
        "",
        "| 漏检样本 | 原因 | 该怎么补 |",
        "|---|---|---|",
        "| `bluekeep`、`printnightmare` | 漏洞利用，只有几个包，没有可统计的行为模式 | **签名检测**（Suricata 规则 / 漏洞特征） |",
        "| `emotet`、`hancitor`、`lokibot`、`predator` | TLS/HTTP 下载器与窃密木马，行为上像正常访问 | 威胁情报（域名/IP 信誉）+ 载荷特征 |",
        "| `njrat` | 单条长连接内的加密 C2，不反复建连 | TLS 指纹（JA3）+ 会话行为基线 |",
        "",
        "结论：**行为规则只能覆盖「扫描 / 爆破 / 隧道 / 心跳」这类有统计规律的攻击**，",
        "覆盖不了漏洞利用和加密外联。这也正是要接 SIEM（Suricata 签名告警）的原因——",
        "两者互补，而不是互相替代。",
        "",
        "## 复现",
        "",
        "```bash",
        "python scripts/fetch_real_pcaps.py      # 按需下载（约 15MB）",
        "python scripts/benchmark_real.py --write-doc",
        "```",
        "",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    main()
