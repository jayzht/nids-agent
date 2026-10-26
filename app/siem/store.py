"""SIEM 存储层：SQLite 持久化 + incident 状态机 + 研判结论回写。

为什么从内存换 SQLite：
- 之前重启就丢数据，也没法回答「这条告警后来怎么处理的」；
- 闭环的关键不是「能分析」，而是「分析结果落回工单」——status / verdict / report 都要能查。

表结构：
    alerts     原始告警（dedupe_key 唯一，去重靠数据库而不是进程内存）
    incidents  聚合后的事件（status: open → triaged → closed）
    analyses   每次研判的完整结果（一个 incident 可以多次研判）
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Iterable

from app.siem.parsers import SEVERITY_ORDER, Alert

WEIGHT = {"high": 10, "medium": 5, "low": 2, "info": 1}
VALID_STATUS = {"open", "triaged", "closed"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  source TEXT NOT NULL,
  rule TEXT NOT NULL,
  severity TEXT NOT NULL,
  src_ip TEXT DEFAULT '',
  dst_ip TEXT DEFAULT '',
  dst_port INTEGER DEFAULT 0,
  proto TEXT DEFAULT '',
  signature TEXT DEFAULT '',
  payload TEXT DEFAULT '',
  dedupe_key TEXT NOT NULL UNIQUE,
  created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts(src_ip);

CREATE TABLE IF NOT EXISTS incidents (
  id TEXT PRIMARY KEY,
  src_ip TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  alert_count INTEGER NOT NULL,
  distinct_rules INTEGER NOT NULL,
  severity TEXT NOT NULL,
  score INTEGER NOT NULL,
  first_ts REAL DEFAULT 0,
  last_ts REAL DEFAULT 0,
  rules_json TEXT DEFAULT '[]',
  dst_ips_json TEXT DEFAULT '[]',
  sources_json TEXT DEFAULT '[]',
  alert_ids_json TEXT DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'open',
  verdict TEXT DEFAULT '',
  status_note TEXT DEFAULT '',
  analysis_count INTEGER NOT NULL DEFAULT 0,
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);

CREATE TABLE IF NOT EXISTS analyses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id TEXT NOT NULL,
  verdict TEXT DEFAULT '',
  report TEXT DEFAULT '',
  citations_json TEXT DEFAULT '[]',
  fusion_json TEXT DEFAULT '{}',
  model TEXT DEFAULT '',
  elapsed REAL DEFAULT 0,
  created_at REAL NOT NULL,
  FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_analyses_incident ON analyses(incident_id);
"""


class AlertStore:
    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        # 进程内计数器只用于观测本次运行的吞吐，真实数据都在 SQLite 里
        self.session = {"received": 0, "accepted": 0, "duplicates": 0}

    # ------------------------------------------------------------ 基础设施
    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript(SCHEMA)

    # ---------------------------------------------------------------- 写入
    def ingest(self, alerts: Iterable[Alert], dedupe_window: float = 300.0) -> dict:
        accepted = dup = received = 0
        now = time.time()
        with self._conn() as conn:
            for a in alerts:
                received += 1
                key = "|".join([
                    a.rule, a.src_ip, a.dst_ip, str(a.dst_port), str(int(a.ts // dedupe_window)),
                ])
                cur = conn.execute(
                    """INSERT OR IGNORE INTO alerts
                       (ts, source, rule, severity, src_ip, dst_ip, dst_port, proto,
                        signature, payload, dedupe_key, created_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (a.ts, a.source, a.rule, a.severity, a.src_ip, a.dst_ip, a.dst_port,
                     a.proto, a.signature, a.payload, key, now),
                )
                if cur.rowcount:
                    accepted += 1
                else:
                    dup += 1
        self.session["received"] += received
        self.session["accepted"] += accepted
        self.session["duplicates"] += dup
        return {"received": received, "accepted": accepted, "duplicates": dup,
                "total": self.total_alerts()}

    def total_alerts(self) -> int:
        with self._conn() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])

    # ---------------------------------------------------------------- 读取
    @staticmethod
    def _row_to_alert(row: sqlite3.Row) -> dict:
        return {
            "id": f"a{row['id']}", "ts": row["ts"], "source": row["source"],
            "rule": row["rule"], "severity": row["severity"], "src_ip": row["src_ip"],
            "dst_ip": row["dst_ip"], "dst_port": row["dst_port"], "proto": row["proto"],
            "signature": row["signature"], "payload": row["payload"],
        }

    def list(self, limit: int = 100, severity: str | None = None,
             src_ip: str | None = None) -> list[dict]:
        sql = "SELECT * FROM alerts"
        clauses, params = [], []
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if src_ip:
            clauses.append("src_ip = ?")
            params.append(src_ip)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY ts DESC, id DESC LIMIT ?"
        params.append(limit)
        with self._conn() as conn:
            return [self._row_to_alert(r) for r in conn.execute(sql, params)]

    def stats(self) -> dict:
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            by_sev = {r["severity"]: r["n"] for r in conn.execute(
                "SELECT severity, COUNT(*) AS n FROM alerts GROUP BY severity")}
            inc = {r["status"]: r["n"] for r in conn.execute(
                "SELECT status, COUNT(*) AS n FROM incidents GROUP BY status")}
            analyses = conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
        return {
            "alerts": total, "by_severity": by_sev, "incidents": inc,
            "analyses": analyses, "session": self.session, "db": str(self.db_path),
        }

    # --------------------------------------------------------------- incident
    def refresh_incidents(self, window: float = 900.0, min_alerts: int = 1) -> None:
        rows = self.list(limit=100_000)
        buckets: dict[tuple[str, int], list[dict]] = {}
        for a in rows:
            if not a["src_ip"]:
                continue
            buckets.setdefault((a["src_ip"], int(a["ts"] // window)), []).append(a)

        now = time.time()
        with self._conn() as conn:
            for (src, bucket), items in buckets.items():
                if len(items) < min_alerts:
                    continue
                items.sort(key=lambda x: x["ts"])
                rules: dict[str, int] = {}
                for a in items:
                    rules[a["rule"]] = rules.get(a["rule"], 0) + 1
                severity = min((a["severity"] for a in items),
                               key=lambda s: SEVERITY_ORDER.get(s, 9))
                score = sum(WEIGHT.get(a["severity"], 1) for a in items) + len(rules) * 3
                conn.execute(
                    """INSERT INTO incidents
                       (id, src_ip, window_start, alert_count, distinct_rules, severity, score,
                        first_ts, last_ts, rules_json, dst_ips_json, sources_json,
                        alert_ids_json, created_at, updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(id) DO UPDATE SET
                         alert_count=excluded.alert_count,
                         distinct_rules=excluded.distinct_rules,
                         severity=excluded.severity,
                         score=excluded.score,
                         first_ts=excluded.first_ts,
                         last_ts=excluded.last_ts,
                         rules_json=excluded.rules_json,
                         dst_ips_json=excluded.dst_ips_json,
                         sources_json=excluded.sources_json,
                         alert_ids_json=excluded.alert_ids_json,
                         updated_at=excluded.updated_at""",
                    (f"{src}-{bucket}", src, bucket, len(items), len(rules), severity, score,
                     items[0]["ts"], items[-1]["ts"],
                     json.dumps(sorted(rules.items(), key=lambda kv: -kv[1])[:6], ensure_ascii=False),
                     json.dumps(sorted({a["dst_ip"] for a in items if a["dst_ip"]})[:6], ensure_ascii=False),
                     json.dumps(sorted({a["source"] for a in items}), ensure_ascii=False),
                     json.dumps([a["id"] for a in items[:20]], ensure_ascii=False),
                     now, now),
                )

    @staticmethod
    def _row_to_incident(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"], "src_ip": row["src_ip"], "window_start": row["window_start"],
            "alert_count": row["alert_count"], "distinct_rules": row["distinct_rules"],
            "severity": row["severity"], "score": row["score"],
            "first_ts": row["first_ts"], "last_ts": row["last_ts"],
            "rules": [tuple(x) for x in json.loads(row["rules_json"])],
            "dst_ips": json.loads(row["dst_ips_json"]),
            "sources": json.loads(row["sources_json"]),
            "alert_ids": json.loads(row["alert_ids_json"]),
            "status": row["status"], "verdict": row["verdict"],
            "status_note": row["status_note"], "analysis_count": row["analysis_count"],
            "updated_at": row["updated_at"],
        }

    def incidents(self, window: float = 900.0, min_alerts: int = 1,
                  status: str | None = None, refresh: bool = True) -> list[dict]:
        if refresh:
            self.refresh_incidents(window=window, min_alerts=min_alerts)
        sql = "SELECT * FROM incidents"
        params: list[Any] = []
        if status:
            sql += " WHERE status = ?"
            params.append(status)
        sql += " ORDER BY (status='closed') ASC, score DESC, last_ts DESC LIMIT 200"
        with self._conn() as conn:
            return [self._row_to_incident(r) for r in conn.execute(sql, params)]

    def get_incident(self, incident_id: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
            if not row:
                return None
            inc = self._row_to_incident(row)
            inc["alerts"] = [
                self._row_to_alert(r) for r in conn.execute(
                    """SELECT * FROM alerts
                       WHERE src_ip = ? AND ts >= ? AND ts < ?
                       ORDER BY ts LIMIT 200""",
                    (inc["src_ip"], inc["first_ts"], inc["last_ts"] + 1e-6),
                )
            ]
            inc["analyses"] = [
                {
                    "id": r["id"], "verdict": r["verdict"], "report": r["report"],
                    "citations": json.loads(r["citations_json"]),
                    "fusion": json.loads(r["fusion_json"]),
                    "model": r["model"], "elapsed": r["elapsed"], "created_at": r["created_at"],
                }
                for r in conn.execute(
                    "SELECT * FROM analyses WHERE incident_id = ? ORDER BY id DESC",
                    (incident_id,),
                )
            ]
            return inc

    # --------------------------------------------------------------- 回写
    def save_analysis(self, incident_id: str, final: dict, model: str = "") -> dict:
        """把 Agent 的研判结论写回工单：存全文 + 更新状态。"""
        now = time.time()
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO analyses
                   (incident_id, verdict, report, citations_json, fusion_json, model, elapsed, created_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (incident_id, final.get("verdict", ""), final.get("answer", ""),
                 json.dumps(final.get("citations", []), ensure_ascii=False),
                 json.dumps(final.get("fusion", {}), ensure_ascii=False),
                 model, float(final.get("elapsed", 0) or 0), now),
            )
            conn.execute(
                """UPDATE incidents
                   SET status = CASE WHEN status = 'open' THEN 'triaged' ELSE status END,
                       verdict = ?, analysis_count = analysis_count + 1, updated_at = ?
                   WHERE id = ?""",
                (final.get("verdict", ""), now, incident_id),
            )
        return {"ok": True, "incident_id": incident_id, "status": "triaged"}

    def update_status(self, incident_id: str, status: str, note: str = "") -> dict:
        if status not in VALID_STATUS:
            raise ValueError(f"status 必须是 {sorted(VALID_STATUS)}")
        now = time.time()
        with self._conn() as conn:
            cur = conn.execute(
                "UPDATE incidents SET status = ?, status_note = ?, updated_at = ? WHERE id = ?",
                (status, note, now, incident_id),
            )
            if cur.rowcount == 0:
                raise KeyError(incident_id)
        return {"ok": True, "incident_id": incident_id, "status": status}

    # --------------------------------------------------------------- 工具
    def incident_question(self, incident: dict) -> str:
        rules = "、".join(f"{r}×{n}" for r, n in incident["rules"])
        return (
            f"SIEM 在过去一段时间聚合到一起告警：源 IP {incident['src_ip']}，"
            f"共 {incident['alert_count']} 条告警、{incident['distinct_rules']} 种规则（{rules}），"
            f"目标 {', '.join(incident['dst_ips']) or '未知'}。"
            f"请判断这最可能是什么类型的攻击，说明判断依据，并给出处置建议和对应的检测规则写法。"
        )
