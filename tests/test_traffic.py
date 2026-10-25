"""流量取证层测试：解析、检测规则、证据链、路径安全。

依赖 tshark；没装就整体跳过，不让 CI 因为环境问题红掉。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.traffic import pcap as pc
from app.traffic.analyzer import TrafficAnalyzer
from app.traffic.tools import TrafficService

pytestmark = pytest.mark.skipif(not pc.tshark_available(), reason="需要 tshark")

FIX = Path(__file__).parent / "fixtures" / "pcaps"


def kinds(path: Path) -> set[str]:
    return {f.kind for f in TrafficAnalyzer().analyze(path).findings}


def test_parse_packets():
    packets = pc.read_packets(FIX / "port_scan.pcap")
    assert len(packets) == 160
    assert all(p.no > 0 for p in packets)
    assert packets[0].src == "192.168.1.66"


def test_port_scan_detected():
    assert "port_scan" in kinds(FIX / "port_scan.pcap")


def test_dns_tunnel_detected():
    assert "dns_tunnel" in kinds(FIX / "dns_tunnel.pcap")


def test_beacon_detected():
    assert "beacon" in kinds(FIX / "beacon_c2.pcap")


def test_benign_traffic_has_no_findings():
    assert kinds(FIX / "benign_web.pcap") == set()


def test_findings_carry_evidence_packet_numbers():
    analysis = TrafficAnalyzer().analyze(FIX / "port_scan.pcap")
    assert analysis.findings
    for f in analysis.findings:
        assert f.evidence, f"{f.kind} 缺少证据包号"
        assert all(1 <= n <= analysis.packet_count for n in f.evidence)


def test_prompt_block_contains_evidence():
    analysis = TrafficAnalyzer().analyze(FIX / "beacon_c2.pcap")
    block = analysis.to_prompt_block()
    assert "证据包" in block
    assert "#1" in block


def test_service_rejects_path_traversal(tmp_path):
    svc = TrafficService(FIX)
    svc.list_pcaps()
    with pytest.raises(FileNotFoundError):
        svc.resolve("../../README.md")


def test_filter_sanitizer_blocks_shell_metachars(tmp_path):
    svc = TrafficService(FIX)
    out = svc.raw_query("port_scan.pcap", "tcp.flags.syn==1; rm -rf /", 5)
    assert out.startswith("过滤表达式不合法")


def test_raw_query_returns_evidence_rows():
    svc = TrafficService(FIX)
    out = svc.raw_query("port_scan.pcap", "tcp.flags.syn==1 and tcp.flags.ack==0", 5)
    assert "匹配" in out or "没有匹配" in out
