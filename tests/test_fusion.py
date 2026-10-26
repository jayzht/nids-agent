"""多 Agent 融合测试：实体关联、置信度、攻击阶段、告警聚合。"""

from __future__ import annotations

import json
from pathlib import Path

from app.signature.fusion import fuse, stage_of_signature
from app.signature.suricata import SignatureAlert, aggregate_alerts

FIX = Path(__file__).parent / "fixtures" / "eve_sample.jsonl"


def load_alerts() -> list[SignatureAlert]:
    out = []
    for line in FIX.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        o = json.loads(line)
        a = o["alert"]
        out.append(SignatureAlert(
            sid=a["signature_id"], signature=a["signature"], category=a.get("category", ""),
            severity={1: "high", 2: "medium", 3: "low"}.get(a.get("severity", 3), "low"),
            src_ip=o.get("src_ip", ""), src_port=o.get("src_port", 0),
            dst_ip=o.get("dest_ip", ""), dst_port=o.get("dest_port", 0),
            proto=o.get("proto", ""), pcap_cnt=o.get("pcap_cnt", 0),
            timestamp=o.get("timestamp", ""),
        ))
    return out


def behavior_finding(**kw) -> dict:
    base = {
        "id": "F1", "kind": "repeated_attempts", "severity": "high",
        "title": "1.1.1.1 对 2.2.2.2:23 反复建连 42 次", "detail": "口令爆破特征",
        "metrics": {}, "evidence": [10, 20, 30], "knowledge_queries": [],
        "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "dst_port": 23,
    }
    base.update(kw)
    return base


def test_stage_mapping():
    assert stage_of_signature("GPL TELNET root login") == "credential_attack"
    assert stage_of_signature("ET EXPLOIT CVE-2019-0708") == "exploitation"
    assert stage_of_signature("ET INFO BusyBox Banner") == "anomaly"
    assert stage_of_signature("ET SCAN port sweep") == "recon"


def test_aggregate_alerts_compresses():
    alerts = load_alerts()
    flows = aggregate_alerts(alerts)
    assert len(flows) <= len(alerts)
    assert sum(f["total_alerts"] for f in flows) == len(alerts)


def test_corroboration_merges_two_agents():
    alerts = [a for a in load_alerts() if a.dst_port == 23 or a.src_port == 23]
    # 让签名流与行为 finding 命中同一个 (ip, port)
    alerts = [
        SignatureAlert(sid=2100719, signature="GPL TELNET root login", category="x",
                       severity="medium", src_ip="2.2.2.2", src_port=23,
                       dst_ip="1.1.1.1", dst_port=40000, proto="TCP",
                       pcap_cnt=15, timestamp="")
    ]
    result = fuse([behavior_finding()], alerts)
    top = result["findings"][0]
    assert set(top["agents"]) == {"behavior", "signature"}
    assert top["confidence"] >= 0.9
    assert top["stage"] == "credential_attack"
    assert 15 in top["evidence_packets"]


def test_behavior_only_when_no_signature():
    result = fuse([behavior_finding()], [])
    top = result["findings"][0]
    assert top["agents"] == ["behavior"]
    assert top["confidence"] < 0.7


def test_signature_only_when_no_behavior():
    alerts = [SignatureAlert(sid=2010935, signature="ET SCAN Potential SSH Scan",
                             category="scan", severity="medium", src_ip="9.9.9.9",
                             src_port=5555, dst_ip="8.8.8.8", dst_port=22,
                             proto="TCP", pcap_cnt=7, timestamp="")]
    result = fuse([], alerts)
    top = result["findings"][0]
    assert top["agents"] == ["signature"]
    assert top["stage"] == "recon"
    assert 7 in top["evidence_packets"]


def test_info_only_signature_has_lower_confidence():
    alerts = [SignatureAlert(sid=2064198, signature="ET INFO BusyBox Banner Observed",
                             category="info", severity="low", src_ip="1.1.1.1",
                             src_port=1234, dst_ip="2.2.2.2", dst_port=23,
                             proto="TCP", pcap_cnt=3, timestamp="")]
    result = fuse([], alerts)
    assert result["findings"][0]["confidence"] <= 0.65


def test_findings_sorted_by_stage():
    behavior = [
        behavior_finding(id="F1", kind="port_scan", dst_port=22),
        behavior_finding(id="F2", kind="dns_tunnel", dst_ip="8.8.8.8", dst_port=53),
    ]
    result = fuse(behavior, [])
    stages = [f["stage"] for f in result["findings"]]
    assert stages.index("recon") < stages.index("exfil")


def test_signature_flow_claimed_only_once():
    """两条行为 finding 都指向同一受害 IP 时，签名流不能被重复认领。"""
    from app.signature.suricata import SignatureAlert

    alerts = [SignatureAlert(sid=2100719, signature="GPL TELNET root login", category="x",
                             severity="medium", src_ip="2.2.2.2", src_port=23,
                             dst_ip="1.1.1.1", dst_port=40000, proto="TCP",
                             pcap_cnt=15, timestamp="")]
    behavior = [
        behavior_finding(id="F1", dst_ip="2.2.2.2", dst_port=23),
        behavior_finding(id="F2", dst_ip="2.2.2.2", dst_port=23),
    ]
    result = fuse(behavior, alerts)
    corroborated = [f for f in result["findings"] if len(f["agents"]) == 2]
    assert len(corroborated) == 1


def test_behavior_without_entities_still_works():
    result = fuse([behavior_finding(src_ip="", dst_ip="", dst_port=0)], [])
    assert result["findings"][0]["agents"] == ["behavior"]
