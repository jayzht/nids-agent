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
