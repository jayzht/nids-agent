"""ATT&CK 映射测试：静态表、关键词、语义兜底、覆盖度汇总。"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from app.signature.attack import (
    BEHAVIOR_MAP,
    TECHNIQUES,
    AttackMapper,
    coverage_block,
    describe,
    from_behavior,
    from_signature,
    summarize,
    technique_ids,
)


def finding(**kw) -> dict:
    base = {"id": "F1", "title": "t", "detail": "d", "behavior_kinds": [], "signatures": []}
    base.update(kw)
    return base


def test_every_behavior_kind_is_mapped():
    kinds = {"port_scan", "horizontal_scan", "repeated_attempts", "beacon", "dns_tunnel",
             "cleartext_http", "suspicious_http", "prompt_injection"}
    assert kinds <= set(BEHAVIOR_MAP)


def test_behavior_mapping_targets_exist_in_dictionary():
    for tids in BEHAVIOR_MAP.values():
        for tid in tids:
            assert tid in TECHNIQUES, tid


def test_from_behavior():
    assert "T1046" in from_behavior("port_scan")
    assert from_behavior("unknown_kind") == []


def test_from_signature_keywords():
    assert from_signature("ET SCAN Potential SSH Scan") == "T1046"
    assert from_signature("GPL TELNET root login") == "T1110"
    assert from_signature("ET EXPLOIT CVE-2019-0708") == "T1190"
    assert from_signature("Mirai botnet activity") == "T1071"
    assert from_signature("completely unrelated") is None


def test_technique_id_regex():
    text = "命中 T1046 与 T1059.001，另外 AML.T0051 也应识别"
    assert technique_ids(text) == ["T1046", "T1059.001", "AML.T0051"]


def test_describe_unknown_id():
    d = describe("T9999")
    assert d["id"] == "T9999" and d["tactic"] == "unknown"


def test_enrich_static_high_confidence():
    mapper = AttackMapper()
    out = asyncio.run(mapper.enrich([finding(behavior_kinds=["port_scan"])]))
    ids = {a["id"] for a in out[0]["attack"]}
    assert {"T1046", "T1595"} <= ids
    assert all(a["confidence"] == "high" for a in out[0]["attack"])


def test_enrich_signature_medium_confidence():
    mapper = AttackMapper()
    out = asyncio.run(mapper.enrich([finding(signatures=["2100719:GPL TELNET root login"])]))
    assert out[0]["attack"][0]["id"] == "T1110"
    assert out[0]["attack"][0]["confidence"] == "medium"


def test_enrich_semantic_fallback():
    class FakeRetriever:
        async def search(self, *a, **kw):
            return [SimpleNamespace(chunk=SimpleNamespace(
                path="mitre/techniques/T1059-command-and-scripting-interpreter.md"))]

    mapper = AttackMapper(FakeRetriever())
    out = asyncio.run(mapper.enrich([finding(behavior_kinds=["mystery"], signatures=["weird"])]))
    assert out[0]["attack"][0]["id"] == "T1059"
    assert out[0]["attack"][0]["confidence"] == "low"


def test_enrich_without_retriever_and_no_match():
    out = asyncio.run(AttackMapper().enrich([finding()]))
    assert out[0]["attack"] == []


def test_summarize_orders_by_tactic():
    findings = [
        finding(id="F1", behavior_kinds=["dns_tunnel"]),      # exfil
        finding(id="F2", behavior_kinds=["port_scan"]),       # reconnaissance
    ]
    cov = summarize(asyncio.run(AttackMapper().enrich(findings)))
    assert cov["total"] >= 3
    tactics = [t["tactic"] for t in cov["techniques"]]
    assert tactics[0].startswith("TA0043") or tactics[0].startswith("TA0007")


def test_coverage_block_renders():
    cov = summarize([{"id": "F1", "attack": [
        {"id": "T1046", "name": "Network Service Discovery",
         "tactic": "TA0007 Discovery", "confidence": "high"}]}])
    block = coverage_block(cov)
    assert "T1046" in block and "TA0007" in block


def test_coverage_block_empty():
    assert "未能映射" in coverage_block({"total": 0, "techniques": [], "tactics": {}})
