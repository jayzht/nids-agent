"""流量取证服务：把确定性分析包装成 Agent 可调用的「工具」。

与 WireMCP 的分工一样：
- 工具层负责「取事实」——tshark 过滤器、会话表、DNS 记录，输出结构化文本；
- LLM 层负责「讲道理」——为什么可疑、对应哪种攻击、该看哪条文档。
这样模型编不出包里没有的东西。
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from app.traffic import pcap as pc
from app.traffic.analyzer import TrafficAnalyzer
from app.traffic.models import Analysis

_FILTER_OK = re.compile(r"""^[A-Za-z0-9_.:=<>!()\[\]"' \-&|]{1,200}$""")


class TrafficService:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.analyzer = TrafficAnalyzer()
        self._cache: dict[tuple[str, float, int], Analysis] = {}

    # ---------------- 文件 ----------------
    def list_pcaps(self) -> list[dict]:
        return pc.find_pcaps(self.root) if self.root.exists() else []

    def resolve(self, name: str) -> Path:
        """只允许访问 root 下的文件，防路径穿越。"""
        candidate = (self.root / name).resolve()
        root = self.root.resolve()
        if not str(candidate).startswith(str(root)) or not candidate.is_file():
            raise FileNotFoundError(f"找不到流量文件：{name}")
        return candidate

    def analyze(self, name: str) -> Analysis:
        path = self.resolve(name)
        key = (str(path), path.stat().st_mtime, path.stat().st_size)
        if key not in self._cache:
            self._cache[key] = self.analyzer.analyze(path)
        return self._cache[key]

    # ---------------- 证据渲染 ----------------
    @staticmethod
    def findings_block(analysis: Analysis) -> str:
        if not analysis.findings:
            return "规则引擎未命中任何已知可疑模式。"
        lines = []
        for f in analysis.findings:
            lines.append(
                f"[{f.id}] {f.severity.upper()} · {f.kind} · {f.title}\n"
                f"    {f.detail}\n"
                f"    证据包号：{', '.join(f'#{n}' for n in f.evidence)}"
            )
        return "\n".join(lines)

    @staticmethod
    def flows_block(analysis: Analysis, top: int = 8) -> str:
        lines = ["会话（按字节排序）："]
        for f in analysis.flows[:top]:
            lines.append(
                f"  {f.initiator}:{f.a_port if f.initiator == f.a_ip else f.b_port} -> "
                f"{f.responder}:{f.target_port} "
                f"{f.packets}包/{f.bytes}字节 syn={f.syn_count} rst={f.rst_count} "
                f"psh={'Y' if f.has_psh else 'N'} 包号={f.evidence[:3]}"
            )
        return "\n".join(lines)

    @staticmethod
    def dns_block(analysis: Analysis, limit: int = 12) -> str:
        queries = [d for d in analysis.dns_queries if not d["response"]]
        if not queries:
            return "没有 DNS 查询。"
        lines = [f"DNS 查询（{len(queries)} 条，展示前 {limit}）："]
        seen = set()
        for q in queries:
            if q["name"] in seen:
                continue
            seen.add(q["name"])
            lines.append(f"  #{q['no']} {q['name']}")
            if len(seen) >= limit:
                break
        return "\n".join(lines)

    @staticmethod
    def http_block(analysis: Analysis, limit: int = 10) -> str:
        if not analysis.http_requests:
            return "没有解析到 HTTP 请求。"
        lines = [f"HTTP 请求（{len(analysis.http_requests)} 条，展示前 {limit}）："]
        for r in analysis.http_requests[:limit]:
            lines.append(f"  #{r['no']} {r['method']} {r['host']}{r['uri']} UA={r['ua'][:60]}")
        return "\n".join(lines)

    def raw_query(self, name: str, display_filter: str, limit: int = 20) -> str:
        """按 tshark 显示过滤器取额外证据（限制字符集，避免奇怪输入）。"""
        if not _FILTER_OK.match(display_filter):
            return "过滤表达式不合法（只允许字段名、比较符和引号）。"
        path = self.resolve(name)
        try:
            rows = pc.read_fields(
                path,
                ["frame.number", "_ws.col.Protocol", "ip.src", "ip.dst", "tcp.flags", "_ws.col.Info"],
                display_filter=display_filter,
                limit=limit,
            )
        except RuntimeError as exc:
            return f"查询失败：{exc}"
        if not rows:
            return "该过滤条件下没有匹配的包。"
        lines = [f"匹配 {len(rows)} 个包（最多展示 {limit}）："]
        for no, proto, src, dst, flags, info in rows:
            lines.append(f"  #{no} {proto} {src}->{dst} {flags} {info[:80]}")
        return "\n".join(lines)

    def overview(self, analysis: Analysis) -> dict[str, Any]:
        return analysis.summary_dict()
