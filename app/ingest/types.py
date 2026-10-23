"""文档 / 片段的数据结构，索引落盘与 API 返回都用它。"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Document:
    doc_id: str
    kb: str
    path: str            # 相对于原始目录的路径，如 tutorial/query-params.md
    title: str
    text: str
    source_url: str = ""
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class Chunk:
    chunk_id: str
    doc_id: str
    kb: str
    path: str
    title: str
    heading_path: str    # "Tutorial > Query Parameters" —— 模型看的是这个上下文
    text: str            # 正文（未加标题前缀）
    embed_text: str      # 实际送去向量化/BM25 的文本（标题 + 正文）
    tokens: int
    source_url: str = ""
    seq: int = 0         # 在文档内的序号

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Chunk":
        return cls(**d)

    @property
    def display_title(self) -> str:
        return self.heading_path or self.title
