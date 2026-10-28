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


def test_dns_volume_flags_only_high_volume_hosts():
    """DNS 量级异常：感染主机 5 万查询要报，普通终端几十次要静默。"""
    from app.traffic.analyzer import TrafficAnalyzer

    a = TrafficAnalyzer()
    dns = [
        {"no": i, "name": f"h{i}.example", "src": "10.0.0.5", "dst": "10.0.0.1",
         "sport": 1025 + i, "dport": 53, "response": False, "rcode": "0"}
        for i in range(6000)
    ] + [
        {"no": 9000 + i, "name": f"ok{i}.example", "src": "10.0.0.9", "dst": "10.0.0.1",
         "sport": 40000 + i, "dport": 53, "response": False, "rcode": "0"}
        for i in range(30)
    ]
    findings = a.detect_dns_volume(dns, threshold=5000)
    assert len(findings) == 1, "只应命中高量级那台主机"
    f = findings[0]
    assert f.kind == "dns_volume"
    assert f.metrics["queries"] == 6000
    assert len(f.metrics["scope"]) == 6000, "scope 要给出精确五元组，供带标注评测匹配"


def test_smtp_fanout_needs_many_distinct_targets():
    from app.traffic.analyzer import TrafficAnalyzer
    from app.traffic.models import Flow

    a = TrafficAnalyzer()

    def flow(src, dst, dport):
        return Flow(
            key=f"{src}|{dst}:{dport}", a_ip=src, a_port=50000, b_ip=dst, b_port=dport,
            first_ts=0.0, last_ts=1.0, initiator=src, responder=dst, target_port=dport,
        )

    spam = [flow("10.0.0.5", f"8.8.8.{i}", 25) for i in range(60)]
    benign = [flow("10.0.0.9", "smtp.internal", 25) for _ in range(20)]
    findings = a.detect_smtp_fanout(spam + benign, min_targets=50)
    assert len(findings) == 1
    assert findings[0].metrics["targets"] == 60


def _flow(src, sport, dst, dport, ts):
    from app.traffic.models import Flow

    return Flow(
        key=f"{src}:{sport}|{dst}:{dport}", a_ip=src, a_port=sport,
        b_ip=dst, b_port=dport, first_ts=ts, last_ts=ts + 1,
        initiator=src, responder=dst, target_port=dport,
    )


def test_irc_c2_detects_low_volume_periodic_channel():
    """低频 IRC C2：只有几条流、端口 6667，扫描/洪泛类规则都不会响，必须由 irc_c2 抓住。"""
    from app.traffic.analyzer import TrafficAnalyzer

    a = TrafficAnalyzer()
    flows = [_flow("10.0.0.7", 1027 + i, "38.229.70.20", 6667, 1000 + 60 * i) for i in range(4)]
    flows += [_flow("10.0.0.9", 50000, "93.184.216.34", 80, 1000 + i) for i in range(10)]

    findings = a.detect_irc_c2(flows)
    assert len(findings) == 1, "只有挂 IRC 端口的主机该被报"
    f = findings[0]
    assert f.src_ip == "10.0.0.7" and f.severity == "high", "60s 规律间隔应判 high"
    assert f.metrics["periodic"] is True
    assert f.metrics["scope"], "要给出精确五元组，否则带标注评测匹配不到"


def test_irc_c2_ignores_single_visit_and_普通站点():
    from app.traffic.analyzer import TrafficAnalyzer

    a = TrafficAnalyzer()
    flows = [_flow("10.0.0.7", 41000, "1.2.3.4", 6667, 1000)]      # 只连一次
    flows += [_flow("10.0.0.8", 41001, "5.6.7.8", 443, 1001 + i) for i in range(20)]
    assert a.detect_irc_c2(flows) == []


def test_irc_c2_collapses_symmetric_and_multi_client_noise():
    """同一条通道从两侧各报一次、以及多个客户端连同一 IRC 服务器，都要合并成一条。"""
    from app.traffic.analyzer import TrafficAnalyzer

    a = TrafficAnalyzer()
    # 被控端 10.0.0.7 与 C2 服务器 1.1.1.1:6667，服务器反向也各有一条
    flows = [_flow("10.0.0.7", 2000 + i, "1.1.1.1", 6667, 100 + 30 * i) for i in range(5)]
    flows += [_flow("1.1.1.1", 6667, "10.0.0.7", 2000 + i, 101 + 30 * i) for i in range(5)]
    # 另外两个主机零星连同一服务器
    flows += [_flow("10.0.0.8", 3000 + i, "1.1.1.1", 6667, 200 + 40 * i) for i in range(3)]
    findings = a.detect_irc_c2(flows)
    assert len(findings) == 1, [f.title for f in findings]
    assert findings[0].src_ip == "10.0.0.7", "应保留连接数最多的被控端视角"


def test_fanout_attempts_catches_completed_handshake_scan():
    """握手会完成的爆破扇出（Mirai 形态）：horizontal_scan 会漏，这条必须抓到。"""
    from app.traffic.analyzer import TrafficAnalyzer
    from app.traffic.models import Flow

    a = TrafficAnalyzer()

    def f(dst, dport, packets=2, bytes_=120):
        return Flow(
            key=f"10.0.0.5|{dst}:{dport}", a_ip="10.0.0.5", a_port=40000,
            b_ip=dst, b_port=dport, first_ts=0.0, last_ts=1.0,
            initiator="10.0.0.5", responder=dst, target_port=dport,
            packets=packets, bytes=bytes_, has_syn=True, has_psh=True,
        )

    flows = [f(f"45.1.{i // 250}.{i % 250}", 23) for i in range(120)]
    findings = a.detect_fanout_attempts(flows, min_hosts=50)
    assert len(findings) == 1
    assert findings[0].metrics["hosts"] == 120
    assert findings[0].metrics["scope_rules"] == [{"src": "10.0.0.5", "dport": 23}]


def test_fanout_ignores_normal_browsing():
    """正常上网：目标多但会话有大流量、且不止一个端口，不该报。"""
    from app.traffic.analyzer import TrafficAnalyzer
    from app.traffic.models import Flow

    a = TrafficAnalyzer()

    def f(dst, dport, packets):
        return Flow(
            key=f"10.0.0.9|{dst}:{dport}", a_ip="10.0.0.9", a_port=40000,
            b_ip=dst, b_port=dport, first_ts=0.0, last_ts=1.0,
            initiator="10.0.0.9", responder=dst, target_port=dport,
            packets=packets, bytes=packets * 500, has_syn=True, has_psh=True,
        )

    flows = [f(f"93.184.216.{i % 250}", 443, 200) for i in range(120)]
    flows += [f(f"1.2.3.{i % 250}", 80, 150) for i in range(120)]
    assert a.detect_fanout_attempts(flows, min_hosts=50) == []
