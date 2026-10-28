"""检测结果 → MITRE ATT&CK 技术映射。

为什么不做成一张硬编码 if-else 表：
- 行为检测的 kind 是有限的，静态表精度最高（扫描就是 T1046，没什么可争的）；
- 但签名规则的文本是开放的（5 万条 ET 规则），靠关键词只能覆盖一部分；
- 所以最后用「ATT&CK 知识库做语义检索」兜底——我们本来就有 721 篇技术文档，
  让签名文本去检索最相关的技术，这比再写 200 条关键词规则更省事。

置信度分三档：
    high   静态映射（kind → 技术，确定性）
    medium 关键词命中（signature 里出现 scan/brute/exploit 等）
    low    语义检索兜底（可能不准，报告里要标注「推测」）
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------- 技术字典
TECHNIQUES: dict[str, dict[str, str]] = {
    "T1046": {"name": "Network Service Discovery", "tactic": "TA0007 Discovery"},
    "T1595": {"name": "Active Scanning", "tactic": "TA0043 Reconnaissance"},
    "T1110": {"name": "Brute Force", "tactic": "TA0006 Credential Access"},
    "T1110.001": {"name": "Password Guessing", "tactic": "TA0006 Credential Access"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "TA0001 Initial Access"},
    "T1210": {"name": "Exploitation of Remote Services", "tactic": "TA0008 Lateral Movement"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "TA0002 Execution"},
    "T1059.001": {"name": "PowerShell", "tactic": "TA0002 Execution"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "TA0006 Credential Access"},
    "T1003.001": {"name": "LSASS Memory", "tactic": "TA0006 Credential Access"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "TA0011 Command and Control"},
    "T1071.001": {"name": "Web Protocols", "tactic": "TA0011 Command and Control"},
    "T1071.004": {"name": "DNS", "tactic": "TA0011 Command and Control"},
    "T1573": {"name": "Encrypted Channel", "tactic": "TA0011 Command and Control"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "TA0011 Command and Control"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "TA0010 Exfiltration"},
    "T1048.003": {"name": "Exfiltration Over Unencrypted Non-C2 Protocol", "tactic": "TA0010 Exfiltration"},
    "T1021": {"name": "Remote Services", "tactic": "TA0008 Lateral Movement"},
    "T1021.001": {"name": "Remote Desktop Protocol", "tactic": "TA0008 Lateral Movement"},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "TA0008 Lateral Movement"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "TA0040 Impact"},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "TA0040 Impact"},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "TA0003 Persistence"},
    "T1055": {"name": "Process Injection", "tactic": "TA0005 Defense Evasion"},
    "T1566": {"name": "Phishing", "tactic": "TA0001 Initial Access"},
    # ATLAS：AI 系统专用，不是 ATT&CK Enterprise 的技术
    "AML.T0051": {"name": "LLM Prompt Injection", "tactic": "ATLAS (AI 系统)"},
}

TACTIC_ORDER = {
    "TA0043 Reconnaissance": 0, "TA0042 Resource Development": 1, "TA0001 Initial Access": 2,
    "TA0002 Execution": 3, "TA0003 Persistence": 4, "TA0004 Privilege Escalation": 5,
    "TA0005 Defense Evasion": 6, "TA0006 Credential Access": 7, "TA0007 Discovery": 8,
    "TA0008 Lateral Movement": 9, "TA0009 Collection": 10, "TA0011 Command and Control": 11,
    "TA0010 Exfiltration": 12, "TA0040 Impact": 13, "ATLAS (AI 系统)": 14,
}

# ------------------------------------------------------- 行为检测 → 技术
BEHAVIOR_MAP: dict[str, list[str]] = {
    "port_scan": ["T1046", "T1595"],
    "horizontal_scan": ["T1046", "T1210"],
    "repeated_attempts": ["T1110.001"],
    "beacon": ["T1071", "T1573"],
    "irc_c2": ["T1071", "T1573"],
    "beacon_payload": ["T1071", "T1573"],
    "dns_tunnel": ["T1071.004", "T1048.003"],
    # 只引用字典里确实有的技术编号（测试会校验映射目标存在）
    "dns_volume": ["T1071.004", "T1048.003"],
    "smtp_fanout": ["T1048"],
    "cleartext_http": ["T1071.001"],
    "suspicious_http": ["T1071.001", "T1105"],
    "exploit_payload": ["T1190"],
    "prompt_injection": ["AML.T0051"],
}

# ---------------------------------------------------- 签名文本 → 技术
KEYWORD_HINTS: list[tuple[str, str]] = [
    ("ransom", "T1486"),
    ("shadow", "T1490"),
    ("mimikatz", "T1003.001"),
    ("lsass", "T1003.001"),
    ("credential", "T1003"),
    ("brute", "T1110"),
    ("login", "T1110"),
    ("password", "T1110"),
    ("auth failure", "T1110"),
    ("powershell", "T1059.001"),
    ("wmic", "T1059"),
    ("shellcode", "T1055"),
    ("exploit", "T1190"),
    ("cve-", "T1190"),
    ("overflow", "T1190"),
    ("webshell", "T1505"),
    ("phish", "T1566"),
    ("psexec", "T1021.002"),
    ("smb", "T1021.002"),
    ("rdp", "T1021.001"),
    ("lateral", "T1021"),
    ("scan", "T1046"),
    ("botnet", "T1071"),
    ("mirai", "T1071"),
    ("trojan", "T1071"),
    ("backdoor", "T1071"),
    ("rat ", "T1071"),
    ("c2", "T1071"),
    ("dns tunnel", "T1048.003"),
    ("tftp", "T1105"),
    ("download", "T1105"),
]

_TECH_ID_RE = re.compile(r"(T\d{4}(?:\.\d{3})?|AML\.T\d{4})")


def technique_ids(text: str) -> list[str]:
    return _TECH_ID_RE.findall(text or "")


def from_behavior(kind: str) -> list[str]:
    return list(BEHAVIOR_MAP.get(kind, []))


def from_signature(signature: str) -> str | None:
    low = (signature or "").lower()
    for needle, tid in KEYWORD_HINTS:
        if needle in low:
            return tid
    return None


def describe(tid: str) -> dict[str, str]:
    meta = TECHNIQUES.get(tid, {})
    return {
        "id": tid,
        "name": meta.get("name", tid),
        "tactic": meta.get("tactic", "unknown"),
    }


class AttackMapper:
    def __init__(self, retriever=None) -> None:
        self.retriever = retriever

    async def _semantic(self, text: str) -> str | None:
        """用 ATT&CK 知识库做语义兜底（只在静态/关键词都没命中时调用）。"""
        if not self.retriever:
            return None
        try:
            hits = await self.retriever.search(
                text, kbs=["ids"], k=1, prefixes=["mitre/techniques"]
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("ATT&CK semantic mapping failed: %s", exc)
            return None
        if not hits:
            return None
        ids = technique_ids(hits[0].chunk.path)
        return ids[0] if ids else None

    async def enrich(self, findings: list[dict]) -> list[dict]:
        for f in findings:
            mapped: dict[str, dict] = {}

            kinds = f.get("behavior_kinds") or ([f["kind"]] if f.get("kind") else [])
            for kind in kinds:
                for tid in from_behavior(kind):
                    mapped.setdefault(tid, {"confidence": "high", "source": "behavior"})

            for sig in f.get("signatures") or []:
                tid = from_signature(sig)
                if tid:
                    mapped.setdefault(tid, {"confidence": "medium", "source": "signature"})

            if not mapped:
                text = f"{f.get('title', '')} {f.get('detail', '')}".strip()
                tid = await self._semantic(text)
                if tid:
                    mapped.setdefault(tid, {"confidence": "low", "source": "semantic"})

            f["attack"] = [
                {**describe(tid), **meta} for tid, meta in mapped.items()
            ]
            f["attack"].sort(key=lambda x: TACTIC_ORDER.get(x["tactic"], 99))
        return findings


def summarize(findings: list[dict]) -> dict:
    """覆盖度汇总：技术、战术、以及「杀伤链走到哪一步」。"""
    tech: dict[str, dict] = {}
    for f in findings:
        for a in f.get("attack") or []:
            row = tech.setdefault(
                a["id"],
                {"id": a["id"], "name": a["name"], "tactic": a["tactic"],
                 "count": 0, "confidence": a["confidence"], "findings": []},
            )
            row["count"] += 1
            row["findings"].append(f.get("id", ""))
            # 置信度取最高的一档
            rank = {"high": 0, "medium": 1, "low": 2}
            if rank.get(a["confidence"], 3) < rank.get(row["confidence"], 3):
                row["confidence"] = a["confidence"]

    techniques = sorted(tech.values(), key=lambda x: TACTIC_ORDER.get(x["tactic"], 99))
    tactics: dict[str, int] = {}
    for t in techniques:
        tactics[t["tactic"]] = tactics.get(t["tactic"], 0) + 1
    return {
        "techniques": techniques,
        "tactics": tactics,
        "total": len(techniques),
        "max_tactic": max(TACTIC_ORDER.get(t["tactic"], 0) for t in techniques) if techniques else 0,
    }


def coverage_block(coverage: dict) -> str:
    if not coverage.get("total"):
        return "（未能映射到 ATT&CK 技术）"
    lines = [
        f"共映射 {coverage['total']} 个技术，覆盖 {len(coverage['tactics'])} 个战术：",
    ]
    for t in coverage["techniques"]:
        lines.append(
            f"  - {t['id']} {t['name']}（{t['tactic']}）"
            f" 命中 {t['count']} 次，置信度 {t['confidence']}"
        )
    return "\n".join(lines)
