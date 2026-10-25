"""流量取证的数据模型。

设计原则和 pcap-hunter 一致：**确定性证据优先**。
所有 Finding 都必须带 `evidence`（包序号），这样 LLM 写的每一句结论都能被回溯验证。
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Packet:
    no: int
    ts: float
    length: int
    src: str
    dst: str
    sport: int
    dport: int
    proto: str          # TCP / UDP / DNS / HTTP / TLS ...
    flags: str          # SYN / SA / A / PA / FA / R / RA ...
    info: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Flow:
    key: str                    # 端点对：a_ip:a_port <-> b_ip:b_port
    a_ip: str
    a_port: int
    b_ip: str
    b_port: int
    packets: int = 0
    bytes: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    syn_count: int = 0
    rst_count: int = 0
    fin_count: int = 0
    syn_only: bool = True       # 只有 SYN，没有后续握手 → 扫描特征
    evidence: list[int] = field(default_factory=list)
    # 方向与行为特征（由 analyzer 计算）
    initiator: str = ""
    responder: str = ""
    target_port: int = 0
    has_syn: bool = False
    has_psh: bool = False

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)


@dataclass
class Finding:
    id: str                     # F1 / F2 ...
    kind: str                   # port_scan / dns_tunnel / beacon / suspicious_http ...
    severity: str               # high / medium / low
    title: str
    detail: str
    metrics: dict[str, Any] = field(default_factory=dict)
    evidence: list[int] = field(default_factory=list)   # 包序号
    knowledge_queries: list[str] = field(default_factory=list)  # 该去知识库查什么

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Analysis:
    file: str
    path: str
    packet_count: int
    byte_count: int
    first_ts: float
    last_ts: float
    protocols: dict[str, int]
    top_talkers: list[dict[str, Any]]
    flows: list[Flow]
    findings: list[Finding]
    dns_queries: list[dict[str, Any]]
    http_requests: list[dict[str, Any]]
    tls_sni: list[dict[str, Any]]

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)

    def summary_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "packets": self.packet_count,
            "bytes": self.byte_count,
            "duration": round(self.duration, 2),
            "protocols": self.protocols,
            "flows": len(self.flows),
            "findings": [f.to_dict() for f in self.findings],
            "top_talkers": self.top_talkers,
        }

    def to_prompt_block(self, max_flows: int = 12) -> str:
        """给 LLM 的确定性事实块（不含任何模型推断）。"""
        lines = [
            f"文件：{self.file}",
            f"包数：{self.packet_count}，字节：{self.byte_count}，时间跨度：{self.duration:.1f}s",
            f"协议分布：{self.protocols}",
            "",
            "Top 会话（按字节）：",
        ]
        for f in self.top_talkers[:max_flows]:
            lines.append(
                f"  - {f['src']}:{f['sport']} -> {f['dst']}:{f['dport']} "
                f"{f['packets']}包/{f['bytes']}字节"
            )
        if self.findings:
            lines.append("")
            lines.append("规则引擎命中的可疑行为（含证据包号）：")
            for fd in self.findings:
                lines.append(
                    f"  - [{fd.id}] {fd.title}（{fd.severity}）证据包: "
                    f"{', '.join(f'#{n}' for n in fd.evidence[:6])}"
                )
                lines.append(f"    {fd.detail}")
                if fd.metrics:
                    lines.append(f"    关键指标：{fd.metrics}")
        else:
            lines.append("\n规则引擎未命中已知可疑模式。")
        return "\n".join(lines)
