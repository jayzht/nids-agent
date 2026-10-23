"""BM25 稀疏检索（自己实现，不引第三方包）。

面试常被问「为什么有了向量检索还要 BM25」：
- 向量检索擅长语义，但对**专有名词 / API 名 / 错误码 / 版本号**（如 `HTTPBearer`、`422`）不敏感；
- BM25 靠精确词项匹配，正好补上这块，两者融合（RRF）是工业界默认做法。

实现是标准 Okapi BM25，用倒排表只对含查询词的文档算分，10w 片段量级够用。
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict

import numpy as np


class BM25:
    def __init__(self, corpus: list[list[str]], k1: float = 1.5, b: float = 0.75) -> None:
        self.k1 = k1
        self.b = b
        self.n_docs = len(corpus)
        self.doc_len = np.asarray([len(toks) for toks in corpus], dtype=np.float32)
        self.avgdl = float(self.doc_len.mean()) if self.n_docs else 1.0
        self.postings: dict[str, list[tuple[int, int]]] = defaultdict(list)
        df: Counter[str] = Counter()
        for idx, toks in enumerate(corpus):
            tf = Counter(toks)
            for term, cnt in tf.items():
                self.postings[term].append((idx, cnt))
                df[term] += 1
        self.idf: dict[str, float] = {
            term: math.log(1 + (self.n_docs - n + 0.5) / (n + 0.5)) for term, n in df.items()
        }

    def search(self, query_tokens: list[str], top_k: int = 50) -> list[tuple[int, float]]:
        scores: dict[int, float] = defaultdict(float)
        for term in set(query_tokens):
            postings = self.postings.get(term)
            if not postings:
                continue
            idf = self.idf[term]
            for doc_idx, tf in postings:
                dl = float(self.doc_len[doc_idx]) or 1.0
                denom = tf + self.k1 * (1 - self.b + self.b * dl / self.avgdl)
                scores[doc_idx] += idf * tf * (self.k1 + 1) / denom
        if not scores:
            return []
        ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
        return ranked[:top_k]

    def __len__(self) -> int:
        return self.n_docs
