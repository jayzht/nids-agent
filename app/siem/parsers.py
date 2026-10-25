"""SIEM 接入：把不同来源的告警归一化成同一种 Alert。

真实环境里告警来源千奇百怪：
    Suricata  -> eve.json（一行一个 JSON）
    Wazuh     -> rule.description / rule.level
    Elastic   -> ECS 字段（event.kind=alert）
    自研/脚本  -> 随便什么 JSON
这一层的职责就是把这些都压成 {rule, severity, src, dst, ...}，
后面的事（去重、聚合、研判）就只跟这一个模型打交道。
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


@dataclass
class Alert:
    id: str
    ts: float
    source: str
    rule: str
    severity: str
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int = 0
    proto: str = ""
    signature: str = ""
    payload: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("raw", None)
        return d

    def dedupe_key(self, window: float = 300.0) -> tuple:
        return (self.rule, self.src_ip, self.dst_ip, self.dst_port, int(self.ts // window))


def _norm_sev(value: Any, default: str = "medium") -> str:
    if isinstance(value, str):
        v = value.strip().lower()
        if v in SEVERITY_ORDER:
            return v
        # suricata 用 1/2/3，wazuh 用 0-15 的 level
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    if n in (1, 2, 3) and isinstance(value, int):
        return {1: "high", 2: "medium", 3: "low"}[n]
    if n >= 10:
        return "high"
    if n >= 5:
        return "medium"
    return "low"


def _ts(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            from datetime import datetime

            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            pass
    return time.time()


def parse_alert(obj: dict[str, Any]) -> Alert | None:
    """自动识别格式。字段名不同，但语义就那几样。"""
    if not isinstance(obj, dict):
        return None

    # ---- Suricata eve.json ----
    if "event_type" in obj and isinstance(obj.get("alert"), dict):
        a = obj["alert"]
        return Alert(
            id=str(obj.get("flow_id") or obj.get("timestamp") or ""),
            ts=_ts(obj.get("timestamp")),
            source="suricata",
            rule=str(a.get("signature", "")),
            severity=_norm_sev(a.get("severity", 3)),
            src_ip=str(obj.get("src_ip", "")),
            dst_ip=str(obj.get("dest_ip", "")),
            dst_port=int(obj.get("dest_port") or 0),
            proto=str(obj.get("proto", "")),
            signature=str(a.get("signature", "")),
            payload=str(obj.get("payload", ""))[:500],
            raw=obj,
        )

    # ---- Wazuh ----
    if "rule" in obj and isinstance(obj.get("rule"), dict) and "description" in obj["rule"]:
        data = obj.get("data") or {}
        return Alert(
            id=str(obj.get("id", "")),
            ts=_ts(obj.get("timestamp")),
            source="wazuh",
            rule=str(obj["rule"].get("description", "")),
            severity=_norm_sev(obj["rule"].get("level", 5)),
            src_ip=str(data.get("srcip") or data.get("src_ip") or ""),
            dst_ip=str(data.get("dstip") or data.get("dst_ip") or ""),
            dst_port=int(data.get("dstport") or 0),
            proto=str(data.get("protocol", "")),
            signature=str(obj["rule"].get("id", "")),
            raw=obj,
        )

    # ---- Elastic ECS ----
    if obj.get("event", {}).get("kind") == "alert" if isinstance(obj.get("event"), dict) else False:
        src = obj.get("source") or {}
        dst = obj.get("destination") or {}
        rule = obj.get("rule") or {}
        net = obj.get("network") or {}
        return Alert(
            id=str(obj.get("event", {}).get("id", "")),
            ts=_ts(obj.get("@timestamp")),
            source="ecs",
            rule=str(rule.get("name") or rule.get("description") or ""),
            severity=_norm_sev(rule.get("severity"), "medium"),
            src_ip=str(src.get("ip", "")),
            dst_ip=str(dst.get("ip", "")),
            dst_port=int(dst.get("port") or 0),
            proto=str(net.get("transport", "")),
            payload=str(obj.get("message", ""))[:500],
            raw=obj,
        )

    # ---- 通用 / 自研 ----
    if "rule" in obj and isinstance(obj["rule"], str):
        return Alert(
            id=str(obj.get("id", "")),
            ts=_ts(obj.get("timestamp") or obj.get("ts")),
            source=str(obj.get("source", "generic")),
            rule=obj["rule"],
            severity=_norm_sev(obj.get("severity", "medium")),
            src_ip=str(obj.get("src_ip", "")),
            dst_ip=str(obj.get("dst_ip", "")),
            dst_port=int(obj.get("dst_port") or 0),
            proto=str(obj.get("proto", "")),
            payload=str(obj.get("payload", ""))[:500],
            raw=obj,
        )
    return None


def parse_batch(payload: Any) -> list[Alert]:
    """支持三种入参：单条 dict、dict 列表、eve.json 风格的原始文本。"""
    import json

    if isinstance(payload, str):
        alerts = []
        for line in payload.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            a = parse_alert(obj)
            if a:
                alerts.append(a)
        return alerts

    items = payload if isinstance(payload, list) else [payload]
    out = []
    for obj in items:
        if isinstance(obj, str):
            out.extend(parse_batch(obj))
            continue
        a = parse_alert(obj)
        if a:
            out.append(a)
    return out
