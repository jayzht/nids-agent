"""确定性流量分析：协议分布、会话、扫描/隧道/beacon/可疑 HTTP 的规则检测。

这一层的定位和 pcap-hunter 一致：**LLM 不可用时也要能出结论**。
所有判定都是可解释的阈值规则，命中后必须给出证据包号 —— 这是后面「结论可回溯」的基础。
"""

from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from app.traffic import pcap as pc
from app.traffic.models import Analysis, Finding, Flow

# 常见扫描器 / 自动化工具 UA（生产环境应该用情报库，这里给可解释的基线）
_HTTP_PORTS = {80, 8000, 8080, 8081, 8888, 3128, 8008}

SUSPICIOUS_UA = (
    "msie 6.0", "python-requests/2.", "curl/7.", "wget/1.", "nikto", "sqlmap",
    "nmap", "masscan", "gobuster", "dirbuster", "zgrab", "nuclei",
)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


class TrafficAnalyzer:
    def detect_port_scan(self, flows: list[Flow]) -> list[Finding]:
        by_src: dict[str, list[Flow]] = defaultdict(list)
        for f in flows:
            if not f.has_syn or f.has_psh:
                continue          # 只算「发了 SYN 但没有后续数据」的尝试
            by_src[f.initiator].append(f)

        findings: list[Finding] = []
        for src, candidates in by_src.items():
            ports = {f.target_port for f in candidates}
            dst_ips = {f.responder for f in candidates}
            if len(ports) < 20 or len(dst_ips) > 5:
                continue
            severity = "high" if len(ports) >= 50 else "medium"
            evidence = sorted({f.evidence[0] for f in candidates if f.evidence})[:12]
            findings.append(
                Finding(
                    id="", kind="port_scan", severity=severity,
                    title=f"{src} 对 {', '.join(sorted(dst_ips))} 发起端口扫描",
                    detail=(
                        f"共 {len(ports)} 个不同目标端口（{min(ports)}-{max(ports)}），"
                        f"均未完成握手（无 PSH 数据），"
                        f"符合 TCP SYN 扫描特征；平均每个端口 {len(candidates) / max(len(ports), 1):.1f} 个包。"
                    ),
                    metrics={"distinct_ports": len(ports),
                             "port_min": min(ports), "port_max": max(ports),
                             "targets": sorted(dst_ips), "attempts": len(candidates)},
                    evidence=evidence,
                    knowledge_queries=[
                        "TCP SYN port scan detection suricata rule",
                        "Zeek conn.log scanning detection",
                    ],
                )
            )
        return findings

    def detect_dns_tunnel(self, dns: list[dict]) -> list[Finding]:
        queries = [d for d in dns if not d["response"]]
        by_domain: dict[str, list[dict]] = defaultdict(list)
        for q in queries:
            labels = q["name"].rstrip(".").split(".")
            if len(labels) < 2:
                continue
            base = ".".join(labels[-2:])
            by_domain[base].append(q)

        findings: list[Finding] = []
        for base, items in by_domain.items():
            long_names = [q for q in items if len(q["name"].split(".")[0]) >= 20]
            unique = {q["name"] for q in long_names}
            if len(unique) < 15:
                continue
            entropies = [shannon_entropy(q["name"].split(".")[0]) for q in long_names]
            avg_entropy = sum(entropies) / len(entropies)
            findings.append(
                Finding(
                    id="", kind="dns_tunnel", severity="high" if avg_entropy > 4.3 else "medium",
                    title=f"疑似 DNS 隧道：{base}",
                    detail=(
                        f"共 {len(unique)} 个超长唯一子域名（首标签 ≥20 字符），"
                        f"平均香农熵 {avg_entropy:.2f} bit/char。正常业务域名通常远低于这个值，"
                        f"这种模式常见于 DNS 隧道外传或 C2 回连。"
                    ),
                    metrics={"unique_long_names": len(unique), "avg_entropy": round(avg_entropy, 2),
                             "base_domain": base},
                    evidence=[q["no"] for q in long_names[:12]],
                    knowledge_queries=[
                        "DNS tunneling detection suricata dns_query",
                        "Zeek dns.log query fields entropy",
                    ],
                )
            )
        return findings

    def detect_beacon(self, flows: list[Flow], packets) -> list[Finding]:
        syn_times: dict[tuple[str, str, int], list[tuple[float, int]]] = defaultdict(list)
        for p in packets:
            if "SYN" in p.flags and "ACK" not in p.flags:
                syn_times[(p.src, p.dst, p.dport)].append((p.ts, p.no))

        findings: list[Finding] = []
        for (src, dst, dport), hits in syn_times.items():
            if len(hits) < 6:
                continue
            times = sorted(t for t, _ in hits)
            gaps = [b - a for a, b in zip(times, times[1:])]
            mean = statistics.fmean(gaps)
            if mean < 5:
                continue
            cv = statistics.pstdev(gaps) / mean
            if cv > 0.25:
                continue
            findings.append(
                Finding(
                    id="", kind="beacon", severity="high",
                    title=f"疑似周期性外联（beacon）：{src} → {dst}:{dport}",
                    detail=(
                        f"{len(hits)} 次连接，平均间隔 {mean:.1f}s，变异系数 {cv:.2f}"
                        f"（间隔高度规律）。人工操作不会这么规律，这是 C2 心跳的典型特征。"
                    ),
                    metrics={"connections": len(hits), "mean_interval": round(mean, 2),
                             "cv": round(cv, 3), "target": f"{dst}:{dport}"},
                    evidence=[no for _, no in sorted(hits)[:10]],
                    knowledge_queries=[
                        "beaconing detection periodic C2 traffic",
                        "suricata flow keyword established rule",
                    ],
                )
            )
        return findings

    def detect_suspicious_http(self, http: list[dict]) -> list[Finding]:
        findings: list[Finding] = []
        by_ua: dict[str, list[dict]] = defaultdict(list)
        for r in http:
            ua = (r["ua"] or "").lower()
            if any(s in ua for s in SUSPICIOUS_UA):
                by_ua[r["ua"]].append(r)
        for ua, items in by_ua.items():
            findings.append(
                Finding(
                    id="", kind="suspicious_http", severity="medium",
                    title=f"可疑 User-Agent：{ua[:60]}",
                    detail=(
                        f"共 {len(items)} 个 HTTP 请求使用了扫描器/自动化工具常见的 UA，"
                        f"目标主机：{', '.join(sorted({i['host'] for i in items if i['host']})[:4])}。"
                    ),
                    metrics={"requests": len(items), "ua": ua[:80]},
                    evidence=[i["no"] for i in items[:10]],
                    knowledge_queries=[
                        "suricata http.user_agent sticky buffer rule",
                        "detect malicious user agent HTTP request",
                    ],
                )
            )
        return findings

    def detect_cleartext_http(self, path: Path) -> list[Finding]:
        """443/8443 端口上出现明文 HTTP —— 要么是配置错误，要么是 C2 伪装。"""
        rows = pc.read_cleartext_http(path)
        # 标准 HTTP 端口上的明文是正常的，只关心「不该出现明文」的端口
        rows = [r for r in rows if r.get("dport") not in _HTTP_PORTS]
        if not rows:
            return []
        uas = {r["ua"] for r in rows if r["ua"]}
        suspicious = [u for u in uas if any(s in u.lower() for s in SUSPICIOUS_UA)]
        return [
            Finding(
                id="", kind="cleartext_http",
                severity="high" if suspicious else "medium",
                title="TLS 端口上出现明文 HTTP 通信",
                detail=(
                    f"在非 HTTP 端口捕获到 {len(rows)} 个明文 HTTP 请求，"
                    f"User-Agent：{', '.join(sorted(uas)[:3]) or '未提供'}。"
                    f"443 端口出现明文 HTTP 通常意味着协议伪装或中间件配置错误。"
                ),
                metrics={"requests": len(rows), "user_agents": sorted(uas)[:5]},
                evidence=[r["no"] for r in rows[:10]],
                knowledge_queries=[
                    "suricata http.user_agent sticky buffer rule",
                    "detect C2 beacon over HTTP",
                ],
            )
        ]

    # ------------------------------------------------------------------
    def analyze(self, path: Path) -> Analysis:
        packets = pc.read_packets(path)
        if not packets:
            raise ValueError(f"{path.name} 里没有可解析的数据包")

        flows_map: dict[str, Flow] = {}
        for p in packets:
            a, b = (p.src, p.sport), (p.dst, p.dport)
            lo, hi = sorted([a, b])
            key = f"{lo[0]}:{lo[1]}|{hi[0]}:{hi[1]}"
            flow = flows_map.get(key)
            if flow is None:
                # 第一条包的发送方 = 发起方（pcap 里连接总是从发起方开始）
                flow = Flow(
                    key=key, a_ip=lo[0], a_port=lo[1], b_ip=hi[0], b_port=hi[1],
                    first_ts=p.ts, last_ts=p.ts,
                    initiator=p.src,
                    responder=p.dst,
                    target_port=p.dport,
                )
                flows_map[key] = flow
            flow.packets += 1
            flow.bytes += p.length
            flow.first_ts = min(flow.first_ts, p.ts)
            flow.last_ts = max(flow.last_ts, p.ts)
            if "SYN" in p.flags:
                flow.syn_count += 1
                flow.has_syn = True
            if "RST" in p.flags:
                flow.rst_count += 1
            if "FIN" in p.flags:
                flow.fin_count += 1
            if "PSH" in p.flags:
                flow.has_psh = True
            if len(flow.evidence) < 6:
                flow.evidence.append(p.no)

        flows = sorted(flows_map.values(), key=lambda f: -f.bytes)
        protocols = dict(Counter(p.proto for p in packets).most_common(10))
        talks = [
            {"src": f.a_ip, "sport": f.a_port, "dst": f.b_ip, "dport": f.b_port,
             "packets": f.packets, "bytes": f.bytes}
            for f in flows[:10]
        ]

        dns = pc.read_dns(path) if any("DNS" in p.proto for p in packets) else []
        http = pc.read_http(path) if any("HTTP" in p.proto for p in packets) else []
        sni = pc.read_tls_sni(path)

        findings: list[Finding] = []
        findings += self.detect_port_scan(flows)
        findings += self.detect_dns_tunnel(dns)
        findings += self.detect_beacon(flows, packets)
        findings += self.detect_suspicious_http(http)
        findings += self.detect_cleartext_http(path)
        order = {"high": 0, "medium": 1, "low": 2}
        findings.sort(key=lambda f: order.get(f.severity, 3))
        for i, f in enumerate(findings, 1):
            f.id = f"F{i}"

        return Analysis(
            file=path.name,
            path=str(path),
            packet_count=len(packets),
            byte_count=sum(p.length for p in packets),
            first_ts=packets[0].ts,
            last_ts=max(p.ts for p in packets),
            protocols=protocols,
            top_talkers=talks,
            flows=flows,
            findings=findings,
            dns_queries=dns,
            http_requests=http,
            tls_sni=sni,
        )
