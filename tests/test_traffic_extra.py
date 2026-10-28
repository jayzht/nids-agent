"""流量层的补充测试：新样本、异常输入、缓存、路径安全。"""

from __future__ import annotations

import pytest

from app.traffic import pcap as pc
from app.traffic.analyzer import TrafficAnalyzer
from app.traffic.tools import TrafficService

pytestmark = pytest.mark.skipif(not pc.tshark_available(), reason="需要 tshark")

FIX = __import__("pathlib").Path(__file__).parent / "fixtures" / "pcaps"


def kinds(name: str) -> set[str]:
    return {f.kind for f in TrafficAnalyzer().analyze(FIX / name).findings}


def test_horizontal_scan_detected():
    assert "horizontal_scan" in kinds("horizontal_scan.pcap")


def test_bruteforce_detected():
    assert "repeated_attempts" in kinds("bruteforce.pcap")


def test_bruteforce_targets_ssh_port():
    analysis = TrafficAnalyzer().analyze(FIX / "bruteforce.pcap")
    finding = next(f for f in analysis.findings if f.kind == "repeated_attempts")
    assert finding.dst_port == 22
    assert finding.src_ip == "192.168.1.71"


def test_empty_pcap_raises():
    with pytest.raises(ValueError):
        TrafficAnalyzer().analyze(FIX / "empty.pcap")


def test_truncated_pcap_raises():
    with pytest.raises((ValueError, RuntimeError)):
        TrafficAnalyzer().analyze(FIX / "truncated.pcap")


def test_service_caches_analysis():
    svc = TrafficService(FIX)
    a = svc.analyze("port_scan.pcap")
    b = svc.analyze("port_scan.pcap")
    assert a is b


def test_service_lists_all_samples():
    svc = TrafficService(FIX)
    names = {x["name"] for x in svc.list_pcaps()}
    assert {"port_scan.pcap", "beacon_c2.pcap", "prompt_injection.pcap"} <= names


def test_service_absolute_path_rejected():
    svc = TrafficService(FIX)
    with pytest.raises(FileNotFoundError):
        svc.resolve("/etc/passwd")


def test_findings_have_entities_for_network_attacks():
    analysis = TrafficAnalyzer().analyze(FIX / "port_scan.pcap")
    f = analysis.findings[0]
    assert f.src_ip and f.dst_ip and f.dst_port


def test_prompt_block_mentions_metrics():
    analysis = TrafficAnalyzer().analyze(FIX / "horizontal_scan.pcap")
    block = analysis.to_prompt_block()
    assert "关键指标" in block


def test_exploit_payload_detects_deserialization_and_ignores_benign():
    """载荷特征要能抓反序列化，又不能在正常请求上误报。"""
    from app.traffic.analyzer import TrafficAnalyzer

    a = TrafficAnalyzer()
    http = [
        {"no": 1, "method": "POST", "host": "10.0.0.5:7001",
         "uri": "/wls-wsat/CoordinatorPortType11", "ua": "Mozilla/5.0"},
        {"no": 2, "method": "POST", "host": "shop.example.com",
         "uri": "/api/orders", "ua": "Mozilla/5.0"},
    ]
    bodies = {
        1: '<soapenv:Envelope><work:WorkContext>java.beans.XMLDecoder</work:WorkContext></soapenv:Envelope>',
        2: '{"item": "book", "qty": 2}',
    }
    findings = a.detect_exploit_payload(http, bodies)
    assert findings, "反序列化载荷必须命中"
    assert all(f.kind == "exploit_payload" and f.severity == "high" for f in findings)
    assert all(f.metrics["frame"] == 1 for f in findings)
    assert a.detect_exploit_payload(http, {}) == []


def test_read_http_bodies_handles_multiline_payload(monkeypatch, tmp_path):
    """body 里的换行会破坏 `-T fields` 的按行解析，所以必须走 JSON 输出。"""
    import json

    from app.traffic import pcap as pc

    payload = (
        '<soapenv:Envelope>\n<work:WorkContext>'
        "java.beans.XMLDecoder</work:WorkContext>\n</soapenv:Envelope>"
    )
    canned = [
        {
            "_source": {"layers": {
                "frame": {"frame.number": "4"},
                "http": {"http.file_data": payload, "http.request.method": "POST"},
            }},
        },
        # 没有 body 的请求（GET）应该被跳过
        {"_source": {"layers": {"frame": {"frame.number": "5"}, "http": {"http.request": "1"}}}},
    ]
    monkeypatch.setattr(pc, "_run", lambda cmd: json.dumps(canned))
    bodies = pc.read_http_bodies(tmp_path / "x.pcap")
    assert bodies == {4: payload}, bodies
    assert "\n" in bodies[4], "多行 body 必须完整保留（这正是 -T fields 会丢掉的部分）"


def test_read_http_bodies_survives_broken_output(tmp_path, monkeypatch):
    """tshark 输出坏掉时不能抛异常，只是没有载荷可查。"""
    from app.traffic import pcap as pc

    monkeypatch.setattr(pc, "_run", lambda cmd: "not json at all")
    assert pc.read_http_bodies(tmp_path / "x.pcap") == {}
