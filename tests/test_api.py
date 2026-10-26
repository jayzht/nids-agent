"""HTTP 接口测试：不依赖 LLM 的端点全覆盖。

需要 data/index 下已有知识库（lifespan 会预热）；没有也能跑，
预热失败只是日志告警，不影响这些端点。
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_info_has_engines(client):
    d = client.get("/api/info").json()
    assert d["llm"]["model"]
    assert d["embedding"]["model"]
    assert "retrieval" in d and "chunking" in d


def test_detectors_report_availability(client):
    d = client.get("/api/traffic/detectors").json()
    assert d["behavior"]["available"] is True
    assert "available" in d["signature"]


def test_traffic_pcaps_listing(client):
    d = client.get("/api/traffic/pcaps").json()
    assert isinstance(d, list) and d
    assert any(x["name"].endswith(".pcap") for x in d)


def test_traffic_findings_preview(client):
    r = client.get("/api/traffic/findings/samples/port_scan.pcap")
    assert r.status_code == 200
    d = r.json()
    assert d["packets"] == 160
    assert d["findings"][0]["kind"] == "port_scan"


def test_traffic_findings_missing_file(client):
    assert client.get("/api/traffic/findings/samples/nope.pcap").status_code == 404


def test_traffic_findings_path_traversal(client):
    r = client.get("/api/traffic/findings/..%2F..%2FREADME.md")
    assert r.status_code in (404, 422)


def test_siem_ingest_and_incidents(client):
    from app.api import siem as siem_module

    siem_module.store = type(siem_module.store)()      # 每个测试用干净的 store
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


def test_siem_ingest_eve_lines(client):
    from app.api import siem as siem_module

    siem_module.store = type(siem_module.store)()
    lines = (
        '{"event_type":"alert","src_ip":"1.2.3.4","alert":{"signature":"a","severity":1}}\n'
        '{"event_type":"alert","src_ip":"1.2.3.5","alert":{"signature":"b","severity":3}}\n'
    )
    r = client.post("/api/siem/ingest", content=lines, headers={"Content-Type": "text/plain"})
    assert r.status_code == 200 and r.json()["accepted"] == 2


def test_siem_ingest_rejects_garbage(client):
    r = client.post("/api/siem/ingest", json={"foo": "bar"})
    assert r.status_code == 400


def test_eval_dataset_endpoint(client):
    d = client.get("/api/eval/dataset?kb=fastapi").json()
    assert d["num"] > 0
    assert "question" in d["items"][0]


def test_web_index_served(client):
    r = client.get("/")
    assert r.status_code == 200 and "DevRAG" in r.text
