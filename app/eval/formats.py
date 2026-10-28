"""带标注流量的统一表示：一个「规范化流」，多种数据格式。

设计要点（这是被用户问出来才改对的）：

> 「为什么每上一个新数据集都要写适配器？会不会每次都要写？」

会——如果把某个数据集的列名写进评测代码，就会。所以这里分成三层：

1. **规范化格式**（本模块的 `LabeledFlow`）：只有 5 个字段——
   `src, sport, dst, dport, label`，外加可选的 `ts / packets`。
   评测器（`flow_metrics`）只认这一种，永远不需要为数据集改代码。
2. **格式转换器**（`FORMATS` 注册表）：**按格式**实现，不按数据集。
   binetflow 一个转换器就同时覆盖 CTU-13 和 411 个 CTU-Malware-Capture 抓包；
   Zeek conn 日志一个转换器覆盖 IoT-23 的全部 23 个场景。
   日常新增数据集 = **0 行代码**（自动识别格式）。
3. **标签归一**（`normalize_malicious`）：`flow=From-Botnet-V42-TCP`、
   `C&C-HeartBeat`、`Malicious`、`1` 这些写法都映射成「恶意/正常」。
   词表覆盖不到的写在 `--label-map` 里，也不用改代码。

自动识别顺序：`#separator/#fields` → Zeek conn；`StartTime,` 打头 → binetflow；
其余当作 CSV，用 `--columns` 给列名映射（不给就用默认猜测并报错提示）。
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

# ---------------------------------------------------------------- 规范化表示

BENIGN_TOKENS = {"", "-", "benign", "background", "normal", "0", "false", "none", "unknown"}
MALICIOUS_TOKENS = (
    "botnet", "malicious", "attack", "c&c", "c2", "cc", "trojan", "exploit",
    "scan", "spam", "ddos", "malware", "worm", "ransom", "mining", "cryptojack",
    "filedownload", "heartbeat",
)


@dataclass(frozen=True)
class LabeledFlow:
    """规范化后的标注流：评测器只认这个结构。"""

    src: str
    sport: int
    dst: str
    dport: int
    label: str
    packets: int = 0
    start_ts: float = 0.0

    @property
    def malicious(self) -> bool:
        return normalize_malicious(self.label)

    @property
    def tuple_both(self):
        return (self.src, self.sport, self.dst, self.dport), (self.dst, self.dport, self.src, self.sport)


def normalize_malicious(label: str) -> bool:
    """把各家标注映射成「是否恶意」。

    规则：先看是否明显的正常词；再匹配恶意词；都不中按正常处理（评测里
    会打印未知标签清单，方便发现词表缺口，而不是静默算错）。
    """
    low = (label or "").strip().lower()
    if low in BENIGN_TOKENS:
        return False
    if low.startswith("flow="):
        low = low[len("flow="):]
    if low in BENIGN_TOKENS:
        return False
    if any(tok in low for tok in MALICIOUS_TOKENS):
        return True
    return False


# ---------------------------------------------------------------- 各格式解析

# CTU 的 binetflow：官方 README 写 14 列，实际文件常多一列 `Dir`（15 列），
# 后来的抓包还多 `SrcPkts`（16 列）。所以一律按表头取索引。
_BINETFLOW_DEFAULTS = {
    "starttime": 0, "srcaddr": 3, "sport": 4, "dstaddr": 5, "dport": 6,
    "totpkts": 10, "label": 13,
}
_BINETFLOW_KEYS = ("starttime", "srcaddr", "sport", "dstaddr", "dport", "totpkts", "label")


def from_binetflow(lines) -> Iterator[LabeledFlow]:
    idx = dict(_BINETFLOW_DEFAULTS)
    for line in lines:
        line = line.strip().lstrip("\ufeff")
        if not line:
            continue
        if line.lower().startswith("starttime"):
            names = [h.strip().lower() for h in line.split(",")]
            for key in _BINETFLOW_KEYS:
                if key in names:
                    idx[key] = names.index(key)
            continue
        parts = line.split(",")
        if len(parts) <= max(idx.values()):
            continue
        label = parts[idx["label"]].strip()
        if not label:
            continue
        try:
            sport = int(parts[idx["sport"]])
            dport = int(parts[idx["dport"]])
            packets = int(parts[idx["totpkts"]])
        except (ValueError, IndexError):
            continue
        yield LabeledFlow(
            src=parts[idx["srcaddr"]].strip(), sport=sport,
            dst=parts[idx["dstaddr"]].strip(), dport=dport,
            label=label, packets=packets,
            start_ts=parse_time(parts[idx["starttime"]]),
        )


_ZEEK_DEFAULTS = {
    "ts": "ts", "orig_h": "id.orig_h", "orig_p": "id.orig_p",
    "resp_h": "id.resp_h", "resp_p": "id.resp_p", "label": "label",
}


def _split_tail(parts: list[str], want: int) -> list[str]:
    """补齐「表头声明了 N 列、数据行却把最后几列用空格粘在一起」的情况。

    IoT-23 的标注脚本就是这么干的：前 21 列是 TAB 分隔的 Zeek conn 字段，
    末尾 `tunnel_parents / label / detailed-label` 三列用**三个空格**追加，
    于是整行按 TAB 只切出 21 段，最后一段是 `(empty)   Malicious   C&C`。
    不处理的话标签会被解析成一整串，恶意/正常全判错（实测撞到过）。
    """
    if len(parts) >= want:
        return parts
    tail = parts[-1]
    pieces = re.split(r" {2,}", tail.strip())
    if len(pieces) <= 1:
        return parts
    return parts[:-1] + pieces


def from_zeek_conn(lines) -> Iterator[LabeledFlow]:
    """Zeek conn.log（IoT-23 的 `*-zeek-conn-log.labeled` 就是这种）。

    文件头是 `#separator` / `#fields` 注释行，数据是 TSV。字段名就是表头，
    所以不用写死列号；最后一列通常叫 `label`。
    """
    sep = "\t"
    fields: list[str] | None = None
    for line in lines:
        if line.startswith("#separator"):
            raw = line.split(" ", 1)[1].strip() if " " in line else "\\x09"
            sep = {"\\x09": "\t", "\\x20": " "}.get(raw, "\t")
            continue
        if line.startswith("#fields"):
            raw = line.split(sep)[1:] if sep in line else line.split("\t")[1:]
            fields = [f.strip() for f in raw]
            # 表头最后一个字段可能把多列用空格粘在一起（见 _split_tail）
            fields = _split_tail(fields, len(fields) + 2)
            continue
        if line.startswith("#") or not line.strip():
            continue
        if fields is None:
            fields = list(_ZEEK_DEFAULTS.values())
        parts = _split_tail(line.rstrip("\n").split(sep), len(fields))
        if len(parts) < len(fields):
            continue
        row = dict(zip(fields, parts))
        label = _label_of(row, fields)
        if not label:
            continue
        try:
            src = row[_ZEEK_DEFAULTS["orig_h"]]
            dst = row[_ZEEK_DEFAULTS["resp_h"]]
            sport = int(float(row[_ZEEK_DEFAULTS["orig_p"]] or 0))
            dport = int(float(row[_ZEEK_DEFAULTS["resp_p"]] or 0))
        except (KeyError, ValueError):
            continue
        yield LabeledFlow(
            src=src, sport=sport, dst=dst, dport=dport, label=label,
            start_ts=_to_float(row.get(_ZEEK_DEFAULTS["ts"], "")),
        )


PLACEHOLDERS = {"", "-", "(empty)", "null", "none"}


def _label_of(row: dict, fields: list[str]) -> str:
    """标签优先取 `label`，缺失时退回 `detailed-label`；占位符不算标签。"""
    for name in ("label", "detailed-label"):
        value = _pick(row, fields, name)
        value = (value or "").strip().strip('"')
        if value and value.lower() not in PLACEHOLDERS:
            return value
    return ""


def _pick(row: dict, fields: list[str], name: str) -> str | None:
    """取某列的值：优先精确名，其次「列名以 label 结尾」（IoT-23 最后一列可能叫 `tunnel label`）。"""
    if name in row:
        return row[name]
    for f in reversed(fields):
        if f.endswith(name):
            return row.get(f)
    return None


def _to_float(value: str) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def from_csv(lines, columns: dict[str, str] | None = None) -> Iterator[LabeledFlow]:
    """通用 CSV：`--columns src=...,sport=...,dst=...,dport=...,label=...`。

    覆盖「有标注但没有固定格式」的一类数据集（很多公开集的 flow CSV 都是这种）。
    """
    cols = {"src": "src", "sport": "sport", "dst": "dst", "dport": "dport",
            "label": "label", "ts": "ts", "packets": "packets"}
    cols.update(columns or {})
    reader = csv.DictReader(io.StringIO("".join(lines)))
    for row in reader:
        try:
            label = (row.get(cols["label"]) or "").strip()
            if not label:
                continue
            yield LabeledFlow(
                src=(row.get(cols["src"]) or "").strip(),
                sport=int(float(row.get(cols["sport"]) or 0)),
                dst=(row.get(cols["dst"]) or "").strip(),
                dport=int(float(row.get(cols["dport"]) or 0)),
                label=label,
                packets=int(float(row.get(cols.get("packets") or "0") or 0)),
                start_ts=_to_float(row.get(cols.get("ts") or "") or ""),
            )
        except (TypeError, ValueError):
            continue


# ---------------------------------------------------------------- 注册与识别

FORMATS: dict[str, Callable[..., Iterator[LabeledFlow]]] = {
    "binetflow": from_binetflow,
    "zeek_conn": from_zeek_conn,
    "csv": from_csv,
}


def detect_format(path: Path) -> str:
    """靠文件头猜格式，避免「每换一个数据集就要人指定一次」。"""
    with path.open(encoding="utf-8", errors="replace") as fh:
        for _ in range(20):
            line = fh.readline()
            if not line:
                break
            low = line.lower()
            if low.startswith("#separator") or low.startswith("#fields"):
                return "zeek_conn"
            if low.startswith("starttime"):
                return "binetflow"
            if not line.strip():
                continue
    return "csv"


def load_flows(
    path: Path, fmt: str | None = None, columns: dict[str, str] | None = None
) -> tuple[str, Iterator[LabeledFlow]]:
    """返回 (使用的格式, 流迭代器)。新数据集只要格式已知，调用方零改动。"""
    fmt = fmt or detect_format(path)

    def gen():
        with path.open(encoding="utf-8", errors="replace") as fh:
            fn = FORMATS[fmt]
            yield from (fn(fh, columns) if fmt == "csv" else fn(fh))

    return fmt, gen()


def parse_time(value: str) -> float:
    """binetflow 的 StartTime → Unix 时间戳（按 UTC 解释）。

    必须 UTC：binetflow 是 UTC，pcap 里是 epoch；按本地时区会整体偏 8 小时。
    """
    from datetime import datetime, timezone

    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
                "%Y/%m/%d %H:%M:%S.%f", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(value.strip(), fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return 0.0


# ---------------------------------------------------------------- 覆盖范围

def rule_matches(flow: LabeledFlow, rule: dict) -> bool:
    """检测器给出的覆盖规则是否命中这条流。

    规则里的字段（`src / sport / dst / dport`）都可缺省，缺省 = 不限定。
    告警涉及几十万条流时，一条 `{"src": "10.0.0.5", "dport": 23}` 比
    逐个五元组既省内存又更快。
    """
    for key, value in rule.items():
        if key == "src" and flow.src != value:
            return False
        if key == "dst" and flow.dst != value:
            return False
        if key == "sport" and flow.sport != int(value):
            return False
        if key == "dport" and flow.dport != int(value):
            return False
    return True


def covered(flow: LabeledFlow, alerted: set[tuple[str, int, str, int]], rules: list[dict]) -> bool:
    """一个流是否被任一告警覆盖：精确五元组（双向）或规则匹配。"""
    if any(t in alerted for t in flow.tuple_both):
        return True
    return any(rule_matches(flow, r) for r in rules)


# ---------------------------------------------------------------- 评测指标


def flow_metrics(
    flows, alerted: set[tuple[str, int, str, int]], rules: list[dict] | None = None
) -> dict[str, float | int]:
    """流级混淆矩阵；精确五元组（双向）或覆盖规则命中即算检出。"""
    rules = rules or []
    tp = fn = fp = tn = n = 0
    for f in flows:
        n += 1
        hit = covered(f, alerted, rules)
        if f.malicious:
            tp += hit
            fn += not hit
        else:
            fp += hit
            tn += not hit

    def div(a: float, b: float) -> float:
        return a / b if b else 0.0

    return {
        "flows": n, "malicious": tp + fn, "benign": fp + tn,
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "recall": div(tp, tp + fn),
        "false_positive_rate": div(fp, fp + tn),
        "precision": div(tp, tp + fp),
    }
