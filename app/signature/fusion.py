"""多 Agent 融合：行为检测 + 签名检测 → 统一的攻击结论。

融合不只是「把两个结果拼在一起」，要做三件事：
1. **归并**：同一条攻击在两个 Agent 眼里形态不同（行为=重试 42 次，签名=TELNET root login），
   必须按实体（IP）关联起来，而不是各说各话；
2. **定级**：两个 Agent 都命中 → 高置信；只有签名 → 中高；只有行为 → 中；
3. **排序**：按攻击阶段（侦察 → 凭据 → 利用 → C2 → 外传）排，而不是按告警条数。

注意关联方式：真实 pcap 里两个 Agent 的方向可能是反的
（行为：攻击者 → 受害者:23；签名：受害者 → 攻击者:端口），所以用实体交集而不是五元组相等。
"""

from __future__ import annotations

from typing import Any

from app.signature.suricata import SignatureAlert, aggregate_alerts

STAGE_ORDER = {"recon": 1, "credential_attack": 2, "exploitation": 3, "c2": 4, "exfil": 5, "anomaly": 6}
STAGE_LABEL = {
    "recon": "侦察", "credential_attack": "凭据攻击", "exploitation": "漏洞利用",
    "c2": "命令控制", "exfil": "数据外传", "anomaly": "异常行为",
}

BEHAVIOR_STAGE = {
    "port_scan": "recon", "horizontal_scan": "recon",
    "repeated_attempts": "credential_attack",
    "beacon": "c2", "beacon_payload": "c2", "irc_c2": "c2",
    "dns_tunnel": "exfil",
    "dns_volume": "c2", "smtp_fanout": "exfil",
    "cleartext_http": "c2", "suspicious_http": "c2",
    "exploit_payload": "exploitation",
    "prompt_injection": "anomaly",
}

SIGNATURE_HINTS = (
    ("exploit", "exploitation"), ("cve-", "exploitation"), ("overflow", "exploitation"),
    ("scan", "recon"), ("brute", "credential_attack"), ("login", "credential_attack"),
    ("password", "credential_attack"), ("c2", "c2"), ("trojan", "c2"), ("malware", "c2"),
    ("botnet", "c2"), ("mirai", "c2"), ("backdoor", "c2"), ("exfil", "exfil"),
    ("tunnel", "exfil"),
)


def stage_of_signature(sig: str) -> str:
    low = sig.lower()
    if "et info" in low or "gpl info" in low:      # 信息类规则不参与定级
        return "anomaly"
    for needle, stage in SIGNATURE_HINTS:
        if needle in low:
            return stage
    return "anomaly"


def _match_strength(behavior: dict, flow: dict) -> int:
    """0=不相关, 1=同 IP（弱）, 2=同 IP+端口（强）。

    真实 pcap 里两个 Agent 的方向常常相反（行为：攻击者→受害:23；签名：受害→攻击者:随机端口），
    所以不能用五元组相等。但只按 IP 关联又会把同一受害者的所有流都合并，
    因此优先端口级匹配，端口对不上才退化为 IP 级。
    """
    b_dst = (behavior.get("dst_ip", ""), behavior.get("dst_port", 0) or 0)
    f_eps = {(flow["src_ip"], flow["src_port"] or 0), (flow["dst_ip"], flow["dst_port"] or 0)}
    if b_dst[0] and b_dst in f_eps:
        return 2
    b_src = (behavior.get("src_ip", ""), 0)
    if b_src[0] and any(b_src[0] == ip for ip, _ in f_eps):
        return 1
    if b_dst[0] and b_dst[0] in {flow["src_ip"], flow["dst_ip"]}:
        return 1
    return 0


def fuse(behavior: list[dict], alerts: list[SignatureAlert]) -> dict[str, Any]:
    flows = aggregate_alerts(alerts)
    used: set[int] = set()
    findings: list[dict] = []

    for b in behavior:
        strong: list[dict] = []
        weak: list[dict] = []
        for i, flow in enumerate(flows):
            if i in used:
                continue
            strength = _match_strength(b, flow)
            if strength == 2:
                strong.append((i, flow))
            elif strength == 1:
                weak.append((i, flow))

        matched = strong[:3] if strong else weak[:1]      # 有强匹配就不吃弱匹配
        for i, _ in matched:
            used.add(i)
        matched_flows = [f for _, f in matched]

        sig_pairs = {f"{t['sid']}:{t['signature']}" for f in matched_flows for t in f["top"]}
        sig_ids = sorted({t["sid"] for f in matched_flows for t in f["top"]})
        sig_stages = {stage_of_signature(f"{t['sid']}:{t['signature']}")
                      for f in matched_flows for t in f["top"]}
        stages = {BEHAVIOR_STAGE.get(b["kind"], "anomaly")} | (sig_stages - {"anomaly"})

        corroborated = bool(matched)
        confidence = (0.90 if corroborated else 0.55) + min(0.05, 0.01 * len(sig_ids))
        findings.append(
            {
                "id": b["id"],
                "title": b["title"],
                "stage": max(stages, key=lambda s: STAGE_ORDER[s]),
                "confidence": round(min(confidence, 0.99), 2),
                "agents": ["behavior"] + (["signature"] if corroborated else []),
                "src_ip": b.get("src_ip", ""),
                "dst_ip": b.get("dst_ip", ""),
                "dst_port": b.get("dst_port", 0),
                "behavior_kinds": [b["kind"]],
                "signature_ids": sig_ids,
                "signatures": sorted(sig_pairs)[:5],
                "evidence_packets": sorted(
                    set(b.get("evidence") or []) | {t["first_pkt"] for f in matched_flows for t in f["top"]}
                )[:12],
                "detail": b.get("detail", ""),
            }
        )

    # 纯签名命中：按 (src,dst) 合并，只留告警量最大的几条
    rest = [f for i, f in enumerate(flows) if i not in used]
    by_pair: dict[tuple[str, str], dict] = {}
    for flow in rest:
        key = (flow["src_ip"], flow["dst_ip"])
        agg = by_pair.setdefault(
            key,
            {"src_ip": flow["src_ip"], "dst_ip": flow["dst_ip"], "dst_port": flow["dst_port"],
             "total": 0, "sids": {}, "first_pkt": []},
        )
        agg["total"] += flow["total_alerts"]
        agg["first_pkt"] += [t["first_pkt"] for t in flow["top"] if t["first_pkt"]]
        for t in flow["top"]:
            agg["sids"].setdefault(t["sid"], t)

    for i, (key, agg) in enumerate(sorted(by_pair.items(), key=lambda kv: -kv[1]["total"])[:3], 1):
        top = sorted(agg["sids"].values(), key=lambda t: -t["count"])[:5]
        stages = {stage_of_signature(t["signature"]) for t in top}
        effective = stages - {"anomaly"}
        info_only = not effective
        findings.append(
            {
                "id": f"S{i}",
                "title": f"签名命中：{top[0]['signature'][:60]}",
                "stage": max(effective, key=lambda s: STAGE_ORDER[s]) if effective else "anomaly",
                "confidence": round((0.60 if info_only else 0.75) + min(0.05, 0.01 * len(top)), 2),
                "agents": ["signature"],
                "src_ip": agg["src_ip"],
                "dst_ip": agg["dst_ip"],
                "dst_port": agg["dst_port"],
                "behavior_kinds": [],
                "signature_ids": sorted(t["sid"] for t in top),
                "signatures": [f"{t['sid']}:{t['signature']}" for t in top],
                "evidence_packets": sorted({p for p in agg["first_pkt"] if p})[:12],
                "detail": (
                    f"Suricata 共 {agg['total']} 条告警、{len(agg['sids'])} 条不同规则；"
                    f"行为规则未命中同类模式（这类攻击缺少可统计的行为特征）。"
                ),
            }
        )

    findings.sort(key=lambda f: (STAGE_ORDER[f["stage"]], -f["confidence"]))
    for i, f in enumerate(findings, 1):
        f["id"] = f"F{i}"
    return {
        "findings": findings[:10],
        "stats": {
            "behavior_findings": len(behavior),
            "signature_alerts": len(alerts),
            "signature_flows": len(flows),
            "corroborated": sum(1 for f in findings if len(f["agents"]) == 2),
            "behavior_only": sum(1 for f in findings if f["agents"] == ["behavior"]),
            "signature_only": sum(1 for f in findings if f["agents"] == ["signature"]),
        },
        "signature_flows": flows[:8],
    }


def findings_block(findings: list[dict]) -> str:
    if not findings:
        return "两个检测器都没有命中。"
    lines = []
    for f in findings:
        stage = STAGE_LABEL.get(f["stage"], f["stage"])
        lines.append(
            f"[{f['id']}] {stage} · 置信度 {f['confidence']:.2f} · 来源={'+'.join(f['agents'])}\n"
            f"    {f['title']}\n"
            f"    {f['detail']}\n"
            f"    证据包号：{', '.join(f'#{n}' for n in f['evidence_packets'][:8]) or '无'}"
        )
        if f["signatures"]:
            lines.append(f"    签名命中：{'; '.join(f['signatures'])}")
    return "\n".join(lines)
