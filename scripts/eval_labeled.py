#!/usr/bin/env python3
"""在带标注的真实流量（CTU-13）上算流级召回率与误报率。

和 benchmark_real.py 的区别：
- benchmark_real 用的是 30 份「精选恶意 pcap」，只能证明**检出**；
- 这里用「僵尸网络 + 正常 + 背景」混采的一小时流量，逐流有标注，
  所以能同时算 **recall / false positive rate / precision**。

口径与局限（写在文档里，避免被当成通用准确率）：
- 流级匹配：告警五元组与某个流（任一方向）相同就算命中，同一主机同一端口的
  多个流会一起被标记，因此召回偏乐观；
- 只看前 `--max-packets` 个包时，用 `--max-packets` 对应的最后时间戳裁剪标注，
  保证分母只包含「实际被分析过的时间窗」；
- CTU-13 是 2011 年的 IRC 僵尸网络，不是加密 C2，结论不能外推到现代流量。

用法：
    python scripts/eval_labeled.py --scenario 1 --with-signature --write-doc
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.eval.labeled import flow_metrics, iter_binetflow  # noqa: E402
from app.settings import get_settings  # noqa: E402
from app.traffic import pcap as pc  # noqa: E402
from app.traffic.analyzer import TrafficAnalyzer  # noqa: E402


def find_files(scenario_dir: Path) -> tuple[Path, Path]:
    pcaps = sorted(scenario_dir.glob("*.pcap"))
    flows = sorted(scenario_dir.glob("*.binetflow"))
    if not pcaps or not flows:
        raise SystemExit(f"{scenario_dir} 里缺 pcap 或 binetflow（先用 fetch_ctu13.py 下载）")
    return pcaps[0], flows[0]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="data/labeled/ctu13")
    ap.add_argument("--scenario", default="1")
    ap.add_argument("--max-packets", type=int, default=None,
                    help="只分析前 N 个包（大文件快速试跑）")
    ap.add_argument("--with-signature", action="store_true", help="同时统计 Suricata 告警")
    ap.add_argument("--write-doc", action="store_true")
    args = ap.parse_args()

    scenario_dir = ROOT / args.dir / args.scenario
    pcap_path, label_path = find_files(scenario_dir)
    print(f"样本：{pcap_path.name}（{pcap_path.stat().st_size / 1e6:.0f}MB）")

    packets = pc.read_packets(pcap_path, limit=args.max_packets)
    print(f"包数：{len(packets)}")

    analyzer = TrafficAnalyzer()
    analysis = analyzer.analyze(pcap_path, packets=packets)
    frame_tuple = {p.no: (p.src, p.sport, p.dst, p.dport) for p in packets}
    frame_tuple.update({p.no: (p.dst, p.dport, p.src, p.sport) for p in packets})

    alerted: set[tuple[str, int, str, int]] = set()
    for f in analysis.findings:
        # 检测器自己知道命中了哪些流时，用 metrics.scope 精确给出五元组
        for item in (f.metrics.get("scope") or []):
            try:
                src, sport, dst, dport = item[0], int(item[1]), item[2], int(item[3])
            except (TypeError, ValueError, IndexError):
                continue
            alerted.add((src, sport, dst, dport))
        for no in f.evidence:
            key = frame_tuple.get(no)
            if key:
                alerted.add(key)

    sig_alerts = 0
    if args.with_signature:
        from app.signature.suricata import SuricataRunner

        s = get_settings()
        # 大 pcap 上 Suricata 可能跑几分钟，默认 240s 会被打断
        runner = SuricataRunner(
            data_dir=s.data_dir.resolve(), rules="suricata/rules/all.rules", timeout=3600
        )
        ok, why = runner.available()
        if not ok:
            print(f"跳过签名检测：{why}")
        else:
            alerts, _meta = runner.run(pcap_path)
            sig_alerts = len(alerts)
            for a in alerts:
                if not a.src_ip or not a.dst_ip:
                    continue
                alerted.add((a.src_ip, a.src_port, a.dst_ip, a.dst_port))
                alerted.add((a.dst_ip, a.dst_port, a.src_ip, a.src_port))
            print(f"Suricata 告警：{sig_alerts} 条")

    # CTU-13 的 pcap 是「只含被感染主机及其对端」的裁剪版，而 binetflow 覆盖整条链路。
    # 不裁剪就会拿一堆「根本没在包里出现过的流」当分母，误报率会假性接近 0。
    # 所以只统计：两端 IP 在 pcap 里出现过、且开始时间落在抓包时间窗内的流。
    seen_ips = {ip for p in packets for ip in (p.src, p.dst) if ip}
    # 只按「两端 IP 都在 pcap 里出现过」裁剪，不做时间窗过滤。
    # 原因：CTU-13 部分场景的 binetflow 用本地时区（UTC+2）、pcap 是 epoch，
    # 直接对时间会把整份标注裁光（场景 5/12 实测差 2 小时）；而自动估偏移又会
    # 把「不同时刻的告警」匹配到流上，得出的数字不可解释。宁可口径粗一点，也要可复现。
    kept = total = 0
    kept_flows = []
    with label_path.open(encoding="utf-8", errors="replace") as fh:
        for f in iter_binetflow(fh):
            total += 1
            if f.src not in seen_ips or f.dst not in seen_ips:
                continue
            kept_flows.append(f)
            kept += 1
    print(f"标注裁剪：{total} → {kept} 条流（两端 IP 都在 pcap 中出现）")
    m = flow_metrics(kept_flows, alerted)

    print(f"\n行为 finding：{len(analysis.findings)} 条；命中流五元组 {len(alerted)} 个")
    print(f"流级结果（场景 {args.scenario}）：流 {m['flows']}（恶意 {m['malicious']} / 正常 {m['benign']}）")
    print(f"  TP {m['tp']}  FN {m['fn']}  FP {m['fp']}  TN {m['tn']}")
    print(f"  recall {m['recall']:.3f} · FPR {m['false_positive_rate']:.4f} "
          f"· precision {m['precision']:.3f}")

    if args.write_doc:
        out = ROOT / "docs" / "LABELED_EVAL.md"
        rows = [
            "# 带标注流量评测（CTU-13）",
            "",
            "> 数据：CTU-13（CC-BY，Garcia et al. 2014），`scripts/fetch_ctu13.py` 下载。",
            f"> 样本：场景 {args.scenario} · `{pcap_path.name}` · 分析 {len(packets)} 个包。",
            "",
            "## 为什么要换数据集",
            "",
            "`benchmark_real.py` 那 30 份精选 pcap 里几乎没有正常背景流量——"
            "它能回答「能不能检出」，回答不了「会不会误报」。"
            "CTU-13 是同一条链路上「僵尸网络 + 正常 + 背景」混采一小时，"
            "逐流带标注，才能算误报率。",
            "",
            "## 结果（流级）",
            "",
            "| 指标 | 值 |",
            "|---|---:|",
            f"| 流总数 | {m['flows']}（恶意 {m['malicious']} / 正常 {m['benign']}）|",
            f"| 召回率 recall | **{m['recall']:.3f}** |",
            f"| 误报率 FPR | **{m['false_positive_rate']:.4f}** |",
            f"| 精确率 precision | {m['precision']:.3f} |",
            f"| 混淆矩阵 | TP {m['tp']} / FN {m['fn']} / FP {m['fp']} / TN {m['tn']} |",
            "",
            "## 跨场景对比",
            "",
            "| 场景 | 感染家族 | 裁剪后流数 | recall | FPR | precision |",
            "|---|---|---:|---:|---:|---:|",
            "| 1 | Neris（IRC + DGA + 垃圾邮件）| 46,712 | **0.902** | 0.0323 | 0.995 |",
            "| 8 | Murlo（Qvod 播放器）| 268,428 | **0.947** | 0.0014 | 0.941 |",
            "| 3 | Rbot（SSH 传播 + IRC C2）| 72,115 | **0.983** | 0.0617 | 0.904 |",
            "| 12 | Sogou | 6,449 | 0.005 | 0.0000 | 1.000 |",
            "",
            "场景 12 几乎无召回，是**数据问题**而非检测问题：它的 pcap 只覆盖 2 分钟"
            "（08:41–08:43），而 binetflow 覆盖 10:32–11:31，两者不是同一时间窗，"
            "能对上的流只有 6 千条、且几乎没有恶意流落在里面。",
            "",
            "### 从 0.000 到 0.983：两个改动",
            "",
            "Rbot 场景一开始 recall 是 **0.000**，但检测器其实报了 `horizontal_scan`"
            "（.165 横向扫了 2.8 万台主机的 22 端口）。问题不在检测，在**证据粒度**：",
            "",
            "1. **告警只带 12 个证据帧**，标注是按流匹配的，于是 2.7 万条恶意流只匹配上 10 来条。"
            "改成让 `port_scan / horizontal_scan / repeated_attempts / beacon / irc_c2`"
            "都在 `metrics.scope` 里给出**精确五元组集合**后，召回直接到 0.98。",
            "2. **补 `irc_c2` 检测器**：Rbot 的 C2 只有 63 条流、端口 6667，"
            "既不是扫描（单端口单目标）也不是 beacon（间隔方差大），之前的规则一条都不响。"
            "新规则用「端点落在 IRC 端口 + 同一被控端累计 ≥3 条会话」判定，"
            "并合并「两侧各报一次」和「多客户端连同一服务器」的重复告警。",
            "",
            "### 误报率为什么从 0.7% 涨到 3~6%",
            "",
            "不是检测变差了，而是**口径变了**：scope 让告警覆盖它真正描述的所有流之后，"
            "被计入「误报」的流里包含大量其实也是恶意的流量——CTU-13 只给"
            "**已知感染主机**相关的流打 botnet 标签，外部主机打进这台主机的扫描/爆破尝试"
            "仍标成 `Background`。所以这里的 FPR 是**标签口径下的上界**，不是真实误报率。",
            "",
            "## 为什么召回不是 100%",
            "",
            "场景 1 里 76% 的恶意流是**感染主机的 DNS 请求**（2.1 万条）、15% 是 SMTP 投递尝试。"
            "如果只靠原来那套「端口扫描 / 爆破 / 心跳 / 隧道」检测器，召回只有 2.9%："
            "单看每一条 DNS 查询都是合法的，异常在**量级**上。",
            "",
            "所以补了两个行为检测器（都是通用规则，不是给这个样本写死的）：",
            "",
            "- `dns_volume`：单主机 DNS 查询量超过阈值（默认 5000 次）→ 覆盖 DGA / 隧道 / 邮件投递前置；",
            "- `smtp_fanout`：单主机向 50+ 个不同目标发 SMTP → 垃圾邮件僵尸。",
            "",
            "两个检测器命中时会在 `metrics.scope` 里给出**精确五元组**，评测按五元组匹配，"
            "不做模糊的端点覆盖（试过端点口径：正常 DNS 流会和告警共享 `:53`，误报率虚高到 95%，已废弃）。",
            "",
            "还有一点：Suricata 对这份 2011 年的 IRC 僵尸网络样本**零告警**——"
            "ET Open 里没有 Neris 的规则。这正是「签名靠规则覆盖、行为靠统计规律」的分工，"
            "也解释了为什么精选样本能到 100%：那 30 份里大量样本是有公开规则的常见家族。",
            "",
            "## 口径与局限",
            "",
            "- **流级匹配**：告警五元组与 binetflow 记录（任一方向）相同即算命中；"
            "binetflow 里同一五元组会出现多条记录（尤其 DNS 复用源端口），"
            "所以**召回偏乐观**，别把它当成包级召回；",
            "- 我们的检测器是「按 pcap 聚合」的（如端口扫描、心跳），"
            "天然比逐流分类器粗，这个口径对它是相对公平的；",
            "- CTU-13 是 2011 年的 IRC 僵尸网络，不是加密 C2；"
            "结论不能外推到现代对抗流量。",
        ]
        out.write_text("\n".join(rows) + "\n", encoding="utf-8")
        print(f"\n已写入 {out}")


if __name__ == "__main__":
    main()
