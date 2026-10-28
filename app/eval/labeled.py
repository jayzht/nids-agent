"""带标注流量的评测：CTU-13 的 binetflow 标注 ↔ 我们的告警。

为什么单独放在 eval 里：项目原有的 30 份精选 pcap 只能证明「能检出」，
证明不了「不误报」——里面几乎没有正常背景流量。CTU-13 每个场景都是
「僵尸网络 + 正常 + 背景」混采一小时，逐流带标注，才能算精确率。

标注格式（CSV，无表头说明）：
    StartTime,Dur,Proto,SrcAddr,Sport,DstAddr,Dport,State,sTos,dTos,
    TotPkts,TotBytes,SrcBytes,Label
Label 形如 `flow=From-Botnet-V42-TCP` / `flow=Background` / `flow=From-Normal`。

匹配方式（故意保守）：告警的 (src, sport, dst, dport) 与某个流的五元组
**任一方向**相同，就把该流记为「被检出」。这是粗粒度匹配，会在
「同一主机同一端口的多个流」上高估召回，所以文档里必须写清这个局限。
"""

from __future__ import annotations

from dataclasses import dataclass

BINETFLOW_COLUMNS = (
    "StartTime", "Dur", "Proto", "SrcAddr", "Sport", "DstAddr", "Dport",
    "State", "sTos", "dTos", "TotPkts", "TotBytes", "SrcBytes", "Label",
)

# CTU-13 的实际文件比 README 多一列 `Dir`（`   ->`），共 15 列；
# 所以解析按**表头**取索引，而不是写死列号——两种布局都能吃。
_INDEX_DEFAULTS = {
    "starttime": 0, "srcaddr": 3, "sport": 4, "dstaddr": 5, "dport": 6,
    "totpkts": 10, "label": 13,
}


def _header_index(header: str) -> dict[str, int]:
    names = [h.strip().lower() for h in header.split(",")]
    idx = dict(_INDEX_DEFAULTS)
    for key in ("starttime", "srcaddr", "sport", "dstaddr", "dport", "totpkts", "label"):
        if key in names:
            idx[key] = names.index(key)
    return idx


@dataclass(frozen=True)
class LabeledFlow:
    src: str
    sport: int
    dst: str
    dport: int
    label: str
    packets: int
    start_ts: float = 0.0

    @property
    def malicious(self) -> bool:
        low = self.label.lower()
        return "botnet" in low or "malicious" in low or "attack" in low

    @property
    def tuple_both(self) -> tuple[tuple[str, int, str, int], tuple[str, int, str, int]]:
        return (self.src, self.sport, self.dst, self.dport), (self.dst, self.dport, self.src, self.sport)


def parse_time(value: str) -> float:
    """binetflow 的 StartTime（`2011-08-10 10:00:00.123456`）→ Unix 时间戳。"""
    from datetime import datetime, timezone

    # 必须是 UTC：binetflow 的时间是 UTC，而 pcap 里是 epoch。
    # 按本地时区解析会整体偏 8 小时，时间窗裁剪就会把真实流全裁掉（踩过）。
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
                "%Y/%m/%d %H:%M:%S.%f", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(value.strip(), fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return 0.0


def iter_binetflow(lines):
    """流式解析 binetflow（CTU-13 的标注文件有 380MB / 280 万行，不能整体读进内存）。

    列按表头定位：官方 README 写 14 列，实际文件多一个 `Dir` 列（15 列）。
    """
    idx = dict(_INDEX_DEFAULTS)
    for line in lines:
        line = line.strip().lstrip("\ufeff")
        if not line:
            continue
        if line.lower().startswith("starttime"):
            idx = _header_index(line)
            continue
        parts = line.split(",")
        need = max(idx.values())
        if len(parts) <= need:
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
            src=parts[idx["srcaddr"]].strip(),
            sport=sport,
            dst=parts[idx["dstaddr"]].strip(),
            dport=dport,
            label=label,
            packets=packets,
            start_ts=parse_time(parts[idx["starttime"]]),
        )


def parse_binetflow(text: str) -> list[LabeledFlow]:
    """解析成列表（测试与小文件用；大文件请用 iter_binetflow）。"""
    return list(iter_binetflow(text.splitlines()))


def flow_metrics(
    flows, alerted: set[tuple[str, int, str, int]]
) -> dict[str, float | int]:
    """流级别混淆矩阵与指标。

    注意口径：这里算的是「流」而不是「包」，一个流被任一告警命中就算检出。
    """
    tp = fn = fp = tn = 0
    n = 0
    for f in flows:
        n += 1
        hit = any(t in alerted for t in f.tuple_both)
        if f.malicious:
            tp += hit
            fn += not hit
        else:
            fp += hit
            tn += not hit

    def div(a: float, b: float) -> float:
        return a / b if b else 0.0

    return {
        "flows": n,
        "malicious": tp + fn,
        "benign": fp + tn,
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "recall": div(tp, tp + fn),
        "false_positive_rate": div(fp, fp + tn),
        "precision": div(tp, tp + fp),
    }
