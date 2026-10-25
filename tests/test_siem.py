"""SIEM 接入层测试：多格式解析、去重、聚合。"""

from __future__ import annotations

from app.siem.parsers import parse_alert, parse_batch
from app.siem.store import AlertStore


def test_parse_suricata_eve():
    a = parse_alert({
        "timestamp": "2025-01-01T00:00:01.000000+0000",
        "event_type": "alert",
        "src_ip": "10.0.0.5", "dest_ip": "10.0.0.9", "dest_port": 23, "proto": "TCP",
        "alert": {"signature": "ET SCAN Potential SSH Scan", "severity": 2, "category": "scan"},
    })
    assert a and a.source == "suricata" and a.severity == "medium"
    assert a.src_ip == "10.0.0.5" and a.dst_port == 23


def test_parse_wazuh():
    a = parse_alert({
        "id": "1", "timestamp": "2025-01-01T00:00:00Z",
        "rule": {"description": "Multiple authentication failures", "level": 12},
        "data": {"srcip": "192.168.1.7"},
    })
    assert a and a.source == "wazuh" and a.severity == "high" and a.src_ip == "192.168.1.7"


def test_parse_ecs():
    a = parse_alert({
        "@timestamp": "2025-01-01T00:00:00Z",
        "event": {"kind": "alert", "id": "abc"},
        "rule": {"name": "Suspicious PowerShell", "severity": "high"},
        "source": {"ip": "10.1.1.1"}, "destination": {"ip": "10.2.2.2", "port": 443},
        "network": {"transport": "tcp"},
    })
    assert a and a.source == "ecs" and a.src_ip == "10.1.1.1" and a.dst_port == 443


def test_parse_generic_and_unknown():
    assert parse_alert({"rule": "custom rule", "severity": "low"}).severity == "low"
    assert parse_alert({"hello": "world"}) is None


def test_parse_batch_from_raw_lines():
    text = '\n'.join([
        '{"event_type":"alert","src_ip":"1.1.1.1","alert":{"signature":"a","severity":1}}',
        'not json at all',
        '{"event_type":"alert","src_ip":"2.2.2.2","alert":{"signature":"b","severity":3}}',
    ])
    alerts = parse_batch(text)
    assert len(alerts) == 2 and alerts[0].src_ip == "1.1.1.1"


def test_dedupe_same_alert():
    store = AlertStore()
    from app.siem.parsers import Alert

    a = Alert(id="1", ts=1000.0, source="suricata", rule="scan", severity="high",
              src_ip="1.1.1.1", dst_ip="2.2.2.2", dst_port=23)
    b = Alert(id="2", ts=1001.0, source="suricata", rule="scan", severity="high",
              src_ip="1.1.1.1", dst_ip="2.2.2.2", dst_port=23)
    res = store.ingest([a, b])
    assert res["accepted"] == 1 and res["duplicates"] == 1


def test_incidents_group_by_src():
    store = AlertStore()
    from app.siem.parsers import Alert

    # 三条不同规则（同规则同窗口会被去重，这是预期行为）
    for i, rule in enumerate(["scan", "bruteforce", "malware_download"]):
        store.ingest([Alert(id=str(i), ts=1000.0 + i, source="suricata", rule=rule,
                            severity="high", src_ip="1.1.1.1", dst_ip="2.2.2.2", dst_port=23)])
    incidents = store.incidents(window=3600)
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc["alert_count"] == 3 and inc["distinct_rules"] == 3
    assert "扫描" in store.incident_question(inc) or "1.1.1.1" in store.incident_question(inc)
