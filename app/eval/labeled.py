"""兼容层：老的 `app.eval.labeled` 接口转发到 `app.eval.formats`。

历史原因：最初只有 CTU-13 一种格式，解析和评测写在一起；后来被问「每上一个
新数据集都要写适配器吗」，才拆成「规范化表示 + 格式转换器」。这里保留旧名字，
避免已有脚本和测试大改。
"""

from __future__ import annotations

from app.eval.formats import (  # noqa: F401
    FORMATS,
    LabeledFlow,
    detect_format,
    flow_metrics,
    from_binetflow,
    from_csv,
    from_zeek_conn,
    load_flows,
    normalize_malicious,
    parse_time,
)


def iter_binetflow(lines):
    """向后兼容：按 binetflow 解析（CTU-13 / CTU-Malware-Capture 都是这个格式）。"""
    yield from from_binetflow(lines)


def parse_binetflow(text: str) -> list[LabeledFlow]:
    return list(from_binetflow(text.splitlines()))
