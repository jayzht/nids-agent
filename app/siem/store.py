"""告警存储：去重 → 聚合 incident。

为什么要有这一层：
Suricata 对一次扫描可能吐出几万条告警，直接把原始告警丢给 LLM 既贵又没用。
工业做法是先按「实体 + 规则 + 时间窗」去重聚合，再对少数 incident 做研判。
"""

from __future__ import annotations

import time
import uuid
from collections import deque
from typing import Any, Iterable

from app.siem.parsers import SEVERITY_ORDER, Alert

WEIGHT = {"high": 10, "medium": 5, "low": 2, "info": 1}


class AlertStore:
    def __init__(self, maxlen: int = 2000) -> None:
        self.alerts: deque[Alert] = deque(maxlen=maxlen)
        self._seen: dict[tuple, float] = {}
        self.stats = {"received": 0, "accepted": 0, "duplicates": 0, "dropped": 0}

    def ingest(self, alerts: Iterable[Alert], dedupe_window: float = 300.0) -> dict:
        accepted = 0
        dup = 0
        for a in alerts:
            self.stats["received"] += 1
            key = a.dedupe_key(dedupe_window)
            if key in self._seen:
                dup += 1
                continue
            self._seen[key] = a.ts
            self.alerts.append(a)
            accepted += 1
        self.stats["accepted"] += accepted
        self.stats["duplicates"] += dup
        return {"accepted": accepted, "duplicates": dup, "total": len(self.alerts)}

    def list(self, limit: int = 100, severity: str | None = None,
             src_ip: str | None = None) -> list[Alert]:
        items = list(self.alerts)[::-1]
        if severity:
            items = [a for a in items if a.severity == severity]
        if src_ip:
            items = [a for a in items if a.src_ip == src_ip]
        return items[:limit]

    def incidents(self, window: float = 900.0, min_alerts: int = 1) -> list[dict[str, Any]]:
        """按源 IP + 时间窗聚合成 incident。"""
        buckets: dict[tuple[str, int], list[Alert]] = {}
        for a in self.alerts:
            if not a.src_ip:
                continue
            buckets.setdefault((a.src_ip, int(a.ts // window)), []).append(a)

        out: list[dict[str, Any]] = []
        for (src, bucket), items in buckets.items():
            if len(items) < min_alerts:
                continue
            items.sort(key=lambda x: x.ts)
            rules: dict[str, int] = {}
            for a in items:
                rules[a.rule] = rules.get(a.rule, 0) + 1
            severity = min((a.severity for a in items), key=lambda s: SEVERITY_ORDER.get(s, 9))
            score = sum(WEIGHT.get(a.severity, 1) for a in items) + len(rules) * 3
            out.append(
                {
                    "id": f"{src}-{bucket}",
                    "src_ip": src,
                    "alert_count": len(items),
                    "distinct_rules": len(rules),
                    "rules": sorted(rules.items(), key=lambda kv: -kv[1])[:6],
                    "severity": severity,
                    "score": score,
                    "first_ts": items[0].ts,
                    "last_ts": items[-1].ts,
                    "dst_ips": sorted({a.dst_ip for a in items if a.dst_ip})[:6],
                    "sources": sorted({a.source for a in items}),
                    "alert_ids": [a.id for a in items[:20]],
                }
            )
        out.sort(key=lambda x: -x["score"])
        return out

    def incident_question(self, incident: dict[str, Any]) -> str:
        rules = "、".join(f"{r}×{n}" for r, n in incident["rules"])
        return (
            f"SIEM 在过去一段时间聚合到一起告警：源 IP {incident['src_ip']}，"
            f"共 {incident['alert_count']} 条告警、{incident['distinct_rules']} 种规则（{rules}），"
            f"目标 {', '.join(incident['dst_ips']) or '未知'}。"
            f"请判断这最可能是什么类型的攻击，说明判断依据，并给出处置建议和对应的检测规则写法。"
        )


def new_id() -> str:
    return uuid.uuid4().hex[:12]


def now_ts() -> float:
    return time.time()
