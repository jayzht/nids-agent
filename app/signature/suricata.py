"""签名检测 Agent：直接调用真实 Suricata（docker）+ ET Open 规则。

为什么用真 Suricata 而不是自己写规则匹配：
- 规则引擎的难点在协议解析、流状态、阈值跟踪，这些重造一遍只会更差；
- ET Open 有 5 万多条社区规则，是「签名检测」这条腿的真实水平；
- 面试时可以说「我用 Suricata 8.0.7 + ET Open 跑真实 pcap」，而不是「我写了个 if 判断」。

不可用时（没 docker / 没镜像 / 没规则）优雅降级为「签名检测不可用」，
行为检测照常工作。
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

SEV = {1: "high", 2: "medium", 3: "low"}


@dataclass
class SignatureAlert:
    sid: int
    signature: str
    category: str
    severity: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str
    pcap_cnt: int
    timestamp: str

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def key(self) -> tuple:
        return (self.src_ip, self.dst_ip, self.dst_port, self.sid)


class SuricataRunner:
    def __init__(
        self,
        data_dir: Path,
        image: str = "jasonish/suricata:latest",
        rules: str = "suricata/rules/all.rules",
        work: str = "suricata/logs",
        timeout: int = 240,
    ) -> None:
        self.data_dir = data_dir
        self.image = image
        self.rules_rel = rules
        self.work_rel = work
        self.timeout = timeout
        self._cache: dict[tuple, list[SignatureAlert]] = {}

    # ---------------- 可用性 ----------------
    def available(self) -> tuple[bool, str]:
        if not shutil.which("docker"):
            return False, "未安装 docker"
        try:
            subprocess.run(["docker", "info"], capture_output=True, timeout=10, check=True)
        except Exception:  # noqa: BLE001
            return False, "docker 守护进程不可用"
        try:
            out = subprocess.run(
                ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
                capture_output=True, text=True, timeout=15,
            ).stdout
            if self.image not in out:
                return False, f"缺少镜像 {self.image}"
        except Exception:  # noqa: BLE001
            return False, "无法列出镜像"
        if not (self.data_dir / self.rules_rel).exists():
            return False, f"缺少规则文件 {self.rules_rel}（先跑 scripts/fetch_suricata_rules.py）"
        return True, "ok"

    # ---------------- 执行 ----------------
    def run(self, pcap_path: Path) -> tuple[list[SignatureAlert], dict]:
        pcap_path = pcap_path.resolve()
        cache_key = (str(pcap_path), pcap_path.stat().st_mtime, pcap_path.stat().st_size)
        if cache_key in self._cache:
            return self._cache[cache_key], {"cached": True}

        ok, reason = self.available()
        if not ok:
            return [], {"available": False, "reason": reason}

        rel = pcap_path.relative_to(self.data_dir.resolve()).as_posix()
        run_dir = self.work_rel + f"/run-{int(time.time() * 1000)}"
        (self.data_dir / run_dir).mkdir(parents=True, exist_ok=True)
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{self.data_dir}:/data",
            self.image,
            "-r", f"/data/{rel}",
            "-S", f"/data/{self.rules_rel}",
            "-l", f"/data/{run_dir}",
        ]
        t0 = time.time()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        except subprocess.TimeoutExpired:
            return [], {"available": True, "error": f"Suricata 超时（{self.timeout}s）"}

        eve = self.data_dir / run_dir / "eve.json"
        alerts: list[SignatureAlert] = []
        if eve.exists():
            for line in eve.read_text(encoding="utf-8", errors="replace").splitlines():
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if obj.get("event_type") != "alert":
                    continue
                a = obj.get("alert") or {}
                alerts.append(
                    SignatureAlert(
                        sid=int(a.get("signature_id") or 0),
                        signature=str(a.get("signature", "")),
                        category=str(a.get("category", "")),
                        severity=SEV.get(int(a.get("severity") or 3), "low"),
                        src_ip=str(obj.get("src_ip", "")),
                        src_port=int(obj.get("src_port") or 0),
                        dst_ip=str(obj.get("dest_ip", "")),
                        dst_port=int(obj.get("dest_port") or 0),
                        proto=str(obj.get("proto", "")),
                        pcap_cnt=int(obj.get("pcap_cnt") or 0),
                        timestamp=str(obj.get("timestamp", "")),
                    )
                )
        # 清掉运行目录，避免日志堆积（eve.json 可能几 MB）
        shutil.rmtree(self.data_dir / run_dir, ignore_errors=True)

        meta = {
            "available": True,
            "alerts": len(alerts),
            "seconds": round(time.time() - t0, 1),
            "stderr_tail": (proc.stderr or "")[-300:] if proc.returncode != 0 else "",
        }
        self._cache[cache_key] = alerts
        return alerts, meta


def aggregate_alerts(alerts: list[SignatureAlert], top_per_flow: int = 5) -> list[dict]:
    """把成千上万条告警压成「每个 (src,dst) 下 top N 条签名」。

    dnscat2 一次就能出 4837 条告警，不聚合根本没法喂给 LLM。
    """
    grouped: dict[tuple[str, int, str, int], dict[int, dict]] = {}
    for a in alerts:
        flow = (a.src_ip, a.src_port, a.dst_ip, a.dst_port)
        bucket = grouped.setdefault(flow, {})
        item = bucket.get(a.sid)
        if item is None:
            bucket[a.sid] = {
                "sid": a.sid, "signature": a.signature, "category": a.category,
                "severity": a.severity, "count": 1, "first_pkt": a.pcap_cnt,
            }
        else:
            item["count"] += 1

    out = []
    for (src, sport, dst, dport), bucket in grouped.items():
        top = sorted(bucket.values(), key=lambda x: -x["count"])[:top_per_flow]
        out.append(
            {
                "src_ip": src, "src_port": sport, "dst_ip": dst, "dst_port": dport,
                "total_alerts": sum(v["count"] for v in bucket.values()),
                "distinct_sids": len(bucket),
                "top": top,
            }
        )
    out.sort(key=lambda x: -x["total_alerts"])
    return out
