"""SIEM 存储层测试：多格式解析、去重、聚合、持久化、结论回写。"""

from __future__ import annotations

import sqlite3

import pytest

from app.siem.parsers import Alert, parse_alert, parse_batch
from app.siem.store import AlertStore


@pytest.fixture()
def store(tmp_path):
    return AlertStore(tmp_path / "siem.db")


def make_alert(**kw) -> Alert:
    base = dict(id="1", ts=1000.0, source="suricata", rule="scan", severity="high",
                src_ip="1.1.1.1", dst_ip="2.2.2.2", dst_port=23, proto="TCP",
                signature="", payload="")
    base.update(kw)
    return Alert(**base)


# ---------------------------------------------------------------- 解析
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


# ---------------------------------------------------------------- 存储
def test_ingest_and_dedupe(store):
    r = store.ingest([make_alert(ts=1000.0), make_alert(ts=1001.0)])
    assert r["accepted"] == 1 and r["duplicates"] == 1
    assert store.total_alerts() == 1


def test_dedupe_survives_new_store_instance(tmp_path):
    db = tmp_path / "s.db"
    AlertStore(db).ingest([make_alert(ts=1000.0)])
    second = AlertStore(db)
    r = second.ingest([make_alert(ts=1001.0)])
    assert r["duplicates"] == 1
    assert second.total_alerts() == 1


def test_persistence_across_reopen(tmp_path):
    db = tmp_path / "p.db"
    s1 = AlertStore(db)
    s1.ingest([make_alert(ts=1000.0), make_alert(ts=2000.0, rule="other")])
    s1.refresh_incidents(window=3600)
    s2 = AlertStore(db)
    assert s2.total_alerts() == 2
    assert len(s2.incidents(window=3600, refresh=False)) == 1


def test_list_filters(store):
    store.ingest([
        make_alert(ts=1000.0, severity="high", src_ip="1.1.1.1"),
        make_alert(ts=1001.0, severity="low", src_ip="9.9.9.9"),
    ])
    assert len(store.list(severity="high")) == 1
    assert store.list(src_ip="9.9.9.9")[0]["src_ip"] == "9.9.9.9"


def test_incidents_group_by_src(store):
    for i, rule in enumerate(["scan", "bruteforce", "malware_download"]):
        store.ingest([make_alert(ts=1000.0 + i, rule=rule)])
    incidents = store.incidents(window=3600)
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc["alert_count"] == 3 and inc["distinct_rules"] == 3
    assert "1.1.1.1" in store.incident_question(inc)


def test_incident_status_preserved_on_refresh(store):
    store.ingest([make_alert()])
    store.refresh_incidents(window=3600)
    inc_id = store.incidents(window=3600)[0]["id"]
    store.update_status(inc_id, "closed", "已确认误报")
    store.incidents(window=3600)          # 再次刷新不应覆盖状态
    inc = store.get_incident(inc_id)
    assert inc["status"] == "closed" and inc["status_note"] == "已确认误报"


def test_save_analysis_writes_back(store):
    store.ingest([make_alert()])
    store.refresh_incidents(window=3600)
    inc_id = store.incidents(window=3600)[0]["id"]

    saved = store.save_analysis(inc_id, {
        "verdict": "answered", "answer": "## 结论\n疑似扫描",
        "citations": [{"index": 1, "path": "suricata/rules/flow-keywords.md"}],
        "fusion": {"corroborated": 1}, "elapsed": 12.5,
    }, model="qwen3:8b")
    assert saved["status"] == "triaged"

    inc = store.get_incident(inc_id)
    assert inc["status"] == "triaged"
    assert inc["analysis_count"] == 1
    assert inc["analyses"][0]["verdict"] == "answered"
    assert "疑似扫描" in inc["analyses"][0]["report"]
    assert inc["analyses"][0]["citations"][0]["path"].endswith("flow-keywords.md")


def test_update_status_rejects_invalid(store):
    store.ingest([make_alert()])
    store.refresh_incidents(window=3600)
    inc_id = store.incidents(window=3600)[0]["id"]
    with pytest.raises(ValueError):
        store.update_status(inc_id, "hacked")
    with pytest.raises(KeyError):
        store.update_status("nope", "closed")


def test_incident_contains_alerts(store):
    store.ingest([make_alert(ts=1000.0)])
    store.refresh_incidents(window=3600)
    inc = store.get_incident(store.incidents(window=3600)[0]["id"])
    assert inc["alerts"] and inc["alerts"][0]["src_ip"] == "1.1.1.1"


def test_db_schema_has_expected_tables(tmp_path):
    db = tmp_path / "schema.db"
    AlertStore(db)
    with sqlite3.connect(db) as conn:
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"alerts", "incidents", "analyses"} <= tables


def test_stats_shape(store):
    store.ingest([make_alert()])
    stats = store.stats()
    assert stats["alerts"] == 1 and "incidents" in stats and stats["analyses"] == 0
