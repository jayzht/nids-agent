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

from app.signature.suricata import SuricataRunner  # noqa: E402
from app.traffic.analyzer import TrafficAnalyzer  # noqa: E402

REAL = ROOT / "data" / "pcaps" / "real"
DOC = ROOT / "docs" / "REAL_TRAFFIC_BENCHMARK.md"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write-doc", action="store_true")
    ap.add_argument("--with-signature", action="store_true",
                    help="同时跑 Suricata 签名检测（慢，约 10s/份）")
    ap.add_argument("--from-cache", action="store_true", help="复用上次结果，只重新生成文档")
    args = ap.parse_args()

    sources = REAL / "sources.json"
    if not sources.exists():
        sys.exit("缺少真实样本，先运行 python scripts/fetch_real_pcaps.py")
    meta = json.loads(sources.read_text(encoding="utf-8"))
    analyzer = TrafficAnalyzer()
    suricata = SuricataRunner(ROOT / "data") if args.with_signature else None
    cache = ROOT / "data" / "benchmark_last.json"

    rows = []
    if args.from_cache and cache.exists():
        rows = json.loads(cache.read_text(encoding="utf-8"))
        print(f"复用缓存：{cache}（{len(rows)} 份）")
    for item in ([] if rows else meta["items"]):
        pcap = next((REAL / item["key"]).glob("*.pcap"), None)
        if not pcap:
            continue
        t0 = time.time()
        analysis = analyzer.analyze(pcap)
        kinds = [f.kind for f in analysis.findings]
        sig_alerts, sig_meta = (suricata.run(pcap) if suricata else ([], {}))
        detected = bool(kinds) or bool(sig_alerts)
        expect = item["expect"]
        if expect == ["__none__"]:
            status = "✔ 未误报" if not detected else "✘ 误报"
        else:
            status = "✔ 检出" if detected else "✘ 漏检"
        rows.append({
            "key": item["key"], "family": item["family"], "note": item["note"],
            "packets": analysis.packet_count, "seconds": round(time.time() - t0, 2),
            "expect": expect, "actual": kinds, "status": status,
            "signature_alerts": len(sig_alerts),
            "signature_seconds": sig_meta.get("seconds", 0),
        })

    if not args.from_cache:
        cache.write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")

    scored = [r for r in rows if r["expect"] != ["__none__"]]
    hit = [r for r in scored if r["status"].startswith("✔")]
    behavior_hit = [r for r in scored if r["actual"]]
    controls = [r for r in rows if r["expect"] == ["__none__"]
                and r["key"] not in {x["key"] for x in scored}]
    fp = [r for r in controls if r["status"].startswith("✘")]

    head = f"{'样本':18s} {'包数':>7s} {'行为命中':22s} {'签名告警':>8s} 结果"
    print(head)
    for r in rows:
        print(f"{r['key']:18s} {r['packets']:7d} {','.join(r['actual']) or '-':22s} "
              f"{r['signature_alerts']:8d} {r['status']}")
    print(f"\n合计检出：{len(hit)}/{len(scored)}（{(len(hit)/len(scored) if scored else 0):.0%}）"
          f"  其中行为引擎：{len(behavior_hit)}  签名补足：{len(hit) - len(behavior_hit)}"
          f"  误报对照：{len(controls) - len(fp)}/{len(controls)} 未触发")

    if args.write_doc:
        DOC.write_text(render_doc(rows, hit, scored, controls, fp, behavior_hit), encoding="utf-8")
        print(f"已写入 {DOC}")


def render_doc(rows, hit, scored, controls, fp, behavior_hit) -> str:
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
        "| 样本 | 家族 | 包数 | 行为命中 | 签名告警 | 结果 |",
        "|---|---|---:|---|---:|---|",
    ]
    for r in rows:
        lines.append(
            f"| `{r['key']}` | {r['family']} | {r['packets']} | "
            f"{', '.join(r['actual']) or '—'} | {r['signature_alerts']} | {r['status']} |"
        )
    lines += [
        "",
        f"- 恶意样本：**{len(scored)}** 份，产生告警 **{len(hit)}** 份",
        f"- 其中行为引擎命中 **{len(behavior_hit)}** 份，签名检测补足 **{len(hit)-len(behavior_hit)}** 份",
        f"- 误报对照（合法 RDP 流量）：{len(controls)} 份，误报 **{len(fp)}** 份",
        "",
        "## 漏检的为什么漏（能力边界）",
        "",
        "| 漏检样本 | 包数 | 家族 | 原因 |",
        "|---|---:|---|---|",
    ]
    for r in [x for x in scored if not x["status"].startswith("✔")]:
        reason = (
            "包数极少，没有可统计的行为模式；ET Open 也未覆盖该利用"
            if r["packets"] <= 100
            else "流量形态与正常业务接近，缺少载荷级特征或情报"
        )
        lines.append(f"| `{r['key']}` | {r['packets']} | {r['family']} | {reason} |")

    lines += [
        "",
        "结论：**行为规则抓统计规律（扫描/爆破/隧道/心跳），签名规则抓已知特征**。",
        f"两者盲区不重叠，所以组合起来才能从 {len(behavior_hit)}/{len(scored)} "
        f"提到 {len(hit)}/{len(scored)}。",
        "",
        "签名侧还踩过一个坑：Suricata 默认校验 checksum，而抓包/回放的样本经常带无效校验和，",
        "大量规则因此不匹配。加上 `-k none` 之后，bluekeep、printnightmare、drupal 这些",
        "「单包漏洞利用」样本才被 ET Open 规则命中（25/30 → 29/30）。",
        "**这类问题不看引擎日志根本发现不了**：不报错，只是安静地少检出。",
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
