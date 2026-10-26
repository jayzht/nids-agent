"""HTTP 接口测试：不依赖 LLM 的端点全覆盖，含 SIEM 闭环。"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api import siem as siem_module
from app.main import app
from app.siem.parsers import parse_alert
from app.siem.store import AlertStore


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def store(tmp_path, monkeypatch):
    s = AlertStore(tmp_path / "api.db")
    monkeypatch.setattr(siem_module, "get_siem_store", lambda: s)
    return s


def seed_incident(store) -> str:
    store.ingest([
        parse_alert({
            "event_type": "alert", "src_ip": "10.9.9.9", "dest_ip": "10.8.8.8",
            "dest_port": 22, "proto": "TCP",
            "alert": {"signature": "ET SCAN SSH", "severity": 2, "signature_id": 2010935},
            "timestamp": "2025-01-01T00:00:00Z",
        })
    ])
    return store.incidents()[0]["id"]


# ---------------------------------------------------------------- 基础
def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200 and r.json()["ok"] is True


def test_info_has_engines(client):
    d = client.get("/api/info").json()
    assert d["llm"]["model"] and d["embedding"]["model"]
    assert "retrieval" in d and "chunking" in d


def test_detectors_report_availability(client):
    d = client.get("/api/traffic/detectors").json()
    assert d["behavior"]["available"] is True
    assert "available" in d["signature"]


def test_traffic_pcaps_listing(client):
    d = client.get("/api/traffic/pcaps").json()
    assert isinstance(d, list) and d


def test_traffic_findings_preview(client):
    r = client.get("/api/traffic/findings/samples/port_scan.pcap")
    assert r.status_code == 200
    d = r.json()
    assert d["packets"] == 160 and d["findings"][0]["kind"] == "port_scan"


def test_traffic_findings_missing_file(client):
    assert client.get("/api/traffic/findings/samples/nope.pcap").status_code == 404


def test_traffic_findings_path_traversal(client):
    r = client.get("/api/traffic/findings/..%2F..%2FREADME.md")
    assert r.status_code in (404, 422)


def test_eval_dataset_endpoint(client):
    d = client.get("/api/eval/dataset?kb=fastapi").json()
    assert d["num"] > 0 and "question" in d["items"][0]


def test_web_index_served(client):
    r = client.get("/")
    assert r.status_code == 200 and "DevRAG" in r.text


# ---------------------------------------------------------------- SIEM
def test_siem_ingest_and_incidents(client, store):
    payload = {
        "event_type": "alert", "src_ip": "10.9.9.9", "dest_ip": "10.8.8.8",
        "dest_port": 22, "proto": "TCP",
        "alert": {"signature": "ET SCAN SSH", "severity": 2, "signature_id": 2010935},
        "pcap_cnt": 5, "timestamp": "2025-01-01T00:00:00Z",
    }
    r = client.post("/api/siem/ingest", json=payload)
    assert r.status_code == 200 and r.json()["accepted"] == 1

    alerts = client.get("/api/siem/alerts").json()
    assert alerts["alerts"][0]["src_ip"] == "10.9.9.9"

    inc = client.get("/api/siem/incidents").json()["incidents"]
    assert inc and inc[0]["src_ip"] == "10.9.9.9"


def test_siem_ingest_eve_lines(client, store):
    lines = (
        '{"event_type":"alert","src_ip":"1.2.3.4","alert":{"signature":"a","severity":1}}\n'
        '{"event_type":"alert","src_ip":"1.2.3.5","alert":{"signature":"b","severity":3}}\n'
    )
    r = client.post("/api/siem/ingest", content=lines, headers={"Content-Type": "text/plain"})
    assert r.status_code == 200 and r.json()["accepted"] == 2


def test_siem_ingest_rejects_garbage(client, store):
    assert client.post("/api/siem/ingest", json={"foo": "bar"}).status_code == 400


def test_siem_incident_detail(client, store):
    inc_id = seed_incident(store)
    d = client.get(f"/api/siem/incidents/{inc_id}").json()
    assert d["src_ip"] == "10.9.9.9" and d["alerts"] and d["status"] == "open"


def test_siem_incident_404(client, store):
    assert client.get("/api/siem/incidents/nope").status_code == 404


def test_siem_patch_status(client, store):
    inc_id = seed_incident(store)
    r = client.patch(f"/api/siem/incidents/{inc_id}", json={"status": "closed", "note": "误报"})
    assert r.status_code == 200
    d = client.get(f"/api/siem/incidents/{inc_id}").json()
    assert d["status"] == "closed" and d["status_note"] == "误报"


def test_siem_patch_invalid_status(client, store):
    inc_id = seed_incident(store)
    assert client.patch(f"/api/siem/incidents/{inc_id}", json={"status": "bad"}).status_code == 422


def test_siem_stats(client, store):
    store.ingest([parse_alert({
        "event_type": "alert", "src_ip": "1.1.1.1",
        "alert": {"signature": "x", "severity": 1}})])
    d = client.get("/api/siem/stats").json()
    assert d["alerts"] == 1 and "by_severity" in d


def test_siem_analyze_unknown_incident(client, store):
    assert client.post("/api/siem/incidents/nope/analyze").status_code == 404


def test_siem_analyze_writes_back(client, store, monkeypatch):
    """用假 Agent 验证「研判结论回写」这条闭环，不依赖 LLM。"""

    class FakeAgent:
        async def astream(self, question, kbs=None, session_id=None):
            yield {"type": "final", "answer": "## 结论\n疑似 SSH 扫描", "verdict": "answered",
                   "citations": [{"index": 1, "path": "suricata/rules/flow-keywords.md"}],
                   "fusion": {"corroborated": 1}, "elapsed": 3.2, "steps": []}

    monkeypatch.setattr(siem_module, "get_rag_agent", lambda: FakeAgent())
    inc_id = seed_incident(store)
    r = client.post(f"/api/siem/incidents/{inc_id}/analyze?stream=false")
    assert r.status_code == 200

    d = client.get(f"/api/siem/incidents/{inc_id}").json()
    assert d["status"] == "triaged"
    assert d["analysis_count"] == 1
    assert d["analyses"][0]["verdict"] == "answered"
    assert "疑似 SSH 扫描" in d["analyses"][0]["report"]
