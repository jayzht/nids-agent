"""评估指标：检索层看召回，生成层看引用与关键词覆盖。

为什么不用 RAGAS 全家桶：
- 依赖重、默认调 OpenAI；
- 面试时被问「faithfulness 怎么算的」答不上来最尴尬。
这里自己实现，指标口径随时能解释清楚。
"""

from __future__ import annotations

import math
from collections.abc import Iterable


def _match(doc_path: str, expected: Iterable[str]) -> bool:
    return any(e and e in doc_path for e in expected)


def recall_at_k(doc_paths: list[str], expected: Iterable[str], k: int) -> float:
    """Top-K 里有没有命中期望文档（每道题 0/1，最后取平均）。"""
    return 1.0 if any(_match(p, expected) for p in doc_paths[:k]) else 0.0


def mrr(doc_paths: list[str], expected: Iterable[str]) -> float:
    for i, p in enumerate(doc_paths, 1):
        if _match(p, expected):
            return 1.0 / i
    return 0.0


def ndcg_at_k(doc_paths: list[str], expected: Iterable[str], k: int) -> float:
    """只有一个相关文档时的 nDCG：DCG@k / IDCG(1)。"""
    for i, p in enumerate(doc_paths[:k], 1):
        if _match(p, expected):
            return 1.0 / math.log2(i + 1)
    return 0.0


def keyword_coverage(answer: str, must_include: Iterable[str]) -> float:
    """答案里覆盖了多少个「必须提到的关键词」—— 低成本的事实正确性代理指标。"""
    items = [k for k in must_include if k]
    if not items:
        return 1.0
    low = answer.lower()
    hit = sum(1 for k in items if k.lower() in low)
    return hit / len(items)


def citation_precision(citations: list[dict], expected: Iterable[str]) -> float:
    """引用里有多大比例来自期望文档 —— 用来抓「引用了但引错地方」。"""
    if not citations:
        return 0.0
    good = sum(1 for c in citations if _match(c.get("path", ""), expected))
    return good / len(citations)


def aggregate(rows: list[dict]) -> dict:
    if not rows:
        return {}
    keys = [k for k in rows[0] if isinstance(rows[0][k], (int, float))]
    return {k: round(sum(r[k] for r in rows) / len(rows), 4) for k in keys}
