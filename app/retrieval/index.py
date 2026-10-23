"""知识库索引：chunks + BM25 + 向量，三件套一起落盘。

存储布局（data/index/<kb>/）：
    meta.json      # 元信息、统计、embedding 模型版本
    chunks.jsonl   # 一行一个片段（可直接 grep / 人工 review）
    vectors.npy    # (n, dim) float32，已归一化
    ids.json       # 向量行号 -> chunk_id
    bm25.pkl       # 不需要：启动时用 chunks 重建，避免索引与正文不一致
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

from app.core.text import tokenize
from app.ingest.types import Chunk
from app.retrieval.bm25 import BM25
from app.retrieval.vectorstore import NumpyVectorStore, VectorStore, build_vector_store
from app.settings import Settings


@dataclass
class Hit:
    chunk: Chunk
    score: float            # 融合后的最终分
    dense_score: float = 0.0
    sparse_score: float = 0.0
    sources: list[str] = field(default_factory=list)
    rank: int = 0

    def to_public(self) -> dict[str, Any]:
        c = self.chunk
        return {
            "chunk_id": c.chunk_id,
            "kb": c.kb,
            "doc_id": c.doc_id,
            "path": c.path,
            "title": c.title,
            "heading_path": c.heading_path,
            "text": c.text,
            "source_url": c.source_url,
            "score": round(self.score, 6),
            "dense_score": round(self.dense_score, 6),
            "sparse_score": round(self.sparse_score, 6),
            "sources": self.sources,
        }


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


class KBIndex:
    def __init__(
        self,
        meta: dict[str, Any],
        chunks: list[Chunk],
        store: VectorStore,
        settings: Settings,
    ) -> None:
        self.meta = meta
        self.chunks = chunks
        self.store = store
        self.settings = settings
        self.by_id: dict[str, int] = {c.chunk_id: i for i, c in enumerate(chunks)}
        self.bm25 = BM25([self._index_tokens(c) for c in chunks])

    @staticmethod
    def _index_tokens(chunk: Chunk) -> list[str]:
        """BM25 的字段加权（BM25F 思路）：标题词重复 2 次，权重约为正文的 3 倍。

        标题命中通常比正文命中更有信号（「Required query parameters」这一节的标题
        就说明了它在讲什么），但也不能只索引标题。
        """
        levels = [p.strip() for p in (chunk.heading_path or "").split(">") if p.strip()]
        head = " > ".join(levels[-2:])
        return tokenize(head) * 2 + tokenize(chunk.text)

    # ---------------- 构建 ----------------
    @classmethod
    def build(
        cls,
        name: str,
        title: str,
        description: str,
        chunks: list[Chunk],
        vectors: np.ndarray,
        settings: Settings,
        extra: dict[str, Any] | None = None,
    ) -> "KBIndex":
        store = build_vector_store(
            settings.vector_backend, f"kb_{name}", vectors.shape[1],
            settings.qdrant_url, settings.qdrant_api_key,
        )
        store.add([c.chunk_id for c in chunks], vectors)
        meta = {
            "name": name,
            "title": title,
            "description": description,
            "num_docs": len({c.doc_id for c in chunks}),
            "num_chunks": len(chunks),
            "embedding_model": settings.embedding_model,
            "embedding_dim": int(vectors.shape[1]) if vectors.size else 0,
            "vector_backend": settings.vector_backend,
            "created_at": now_iso(),
            "updated_at": now_iso(),
            **(extra or {}),
        }
        return cls(meta, chunks, store, settings)

    # ---------------- 检索 ----------------
    def dense_search(self, qvec: np.ndarray, k: int) -> list[tuple[int, float]]:
        out: list[tuple[int, float]] = []
        for cid, score in self.store.search(qvec, k):
            idx = self.by_id.get(cid)
            if idx is not None:
                out.append((idx, score))
        return out

    def sparse_search(self, query: str, k: int) -> list[tuple[int, float]]:
        return self.bm25.search(tokenize(query), k)

    @staticmethod
    def _minmax(scores: list[tuple[int, float]]) -> dict[int, float]:
        if not scores:
            return {}
        vals = np.asarray([x[1] for x in scores], dtype=np.float32)
        lo, hi = float(vals.min()), float(vals.max())
        span = hi - lo
        if span < 1e-9:
            return {i: 1.0 for i, _ in scores}
        return {i: (v - lo) / span for i, v in scores}

    def hybrid_search(
        self, query: str, qvec: np.ndarray, k: int, candidate_k: int
    ) -> list[Hit]:
        """稠密 + 稀疏两路召回，再融合。

        两种融合方式都实现了，用 `FUSION` 切换：
        - rrf（默认工业界方案）：只用排名，1/(k+rank)，尺度无关、几乎不用调参；
        - normalized：各自 min-max 归一化后加权求和，保留分数的「置信度」信息。

        本项目在 28 题 golden set 上扫过：RRF 在 bm25_weight=0.2 时
        recall@6 0.875 / MRR 0.681；normalized 同权重下 0.893 / 0.757。
        小样本差异不必太当真，但既然测了就用数据更好的那个。
        """
        s = self.settings
        dense = self.dense_search(qvec, candidate_k)
        sparse = self.sparse_search(query, candidate_k) if s.bm25_weight > 0 else []
        dense_map = dict(dense)
        sparse_map = dict(sparse)

        if s.fusion == "normalized":
            d_norm = self._minmax(dense)
            s_norm = self._minmax(sparse)
            w_dense, w_bm25 = 1.0 - s.bm25_weight, s.bm25_weight
            fused = {
                i: w_dense * d_norm.get(i, 0.0) + w_bm25 * s_norm.get(i, 0.0)
                for i in set(d_norm) | set(s_norm)
            }
        else:
            fused: dict[int, float] = {}
            w_dense, w_bm25 = 1.0 - s.bm25_weight, s.bm25_weight
            for rank, (idx, _) in enumerate(dense):
                fused[idx] = fused.get(idx, 0.0) + w_dense / (s.rrf_k + rank + 1)
            for rank, (idx, _) in enumerate(sparse):
                fused[idx] = fused.get(idx, 0.0) + w_bm25 / (s.rrf_k + rank + 1)

        ranked = sorted(fused.items(), key=lambda kv: kv[1], reverse=True)[:k]
        hits: list[Hit] = []
        for i, (idx, score) in enumerate(ranked):
            chunk = self.chunks[idx]
            src = []
            if idx in dense_map:
                src.append("dense")
            if idx in sparse_map:
                src.append("sparse")
            hits.append(
                Hit(
                    chunk=chunk,
                    score=score,
                    dense_score=dense_map.get(idx, 0.0),
                    sparse_score=sparse_map.get(idx, 0.0),
                    sources=src,
                    rank=i + 1,
                )
            )
        return hits

    # ---------------- 落盘 ----------------
    def save(self, root: Path) -> None:
        path = root / self.meta["name"]
        path.mkdir(parents=True, exist_ok=True)
        self.store.save(path)
        with (path / "chunks.jsonl").open("w", encoding="utf-8") as f:
            for c in self.chunks:
                f.write(json.dumps(c.to_dict(), ensure_ascii=False) + "\n")
        (path / "meta.json").write_text(
            json.dumps(self.meta, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    @classmethod
    def load(cls, path: Path, settings: Settings) -> "KBIndex":
        meta = json.loads((path / "meta.json").read_text(encoding="utf-8"))
        chunks = [
            Chunk.from_dict(json.loads(line))
            for line in (path / "chunks.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        if settings.vector_backend == "qdrant":
            store = build_vector_store(
                "qdrant", f"kb_{meta['name']}", meta.get("embedding_dim", 0),
                settings.qdrant_url, settings.qdrant_api_key, reset=False,
            )
        else:
            store = NumpyVectorStore()
            store.load(path)
        return cls(meta, chunks, store, settings)

    def stats(self) -> dict[str, Any]:
        return {
            "name": self.meta["name"],
            "title": self.meta.get("title", self.meta["name"]),
            "description": self.meta.get("description", ""),
            "num_docs": self.meta.get("num_docs", 0),
            "num_chunks": len(self.chunks),
            "embedding_model": self.meta.get("embedding_model", ""),
            "vector_backend": self.meta.get("vector_backend", "numpy"),
            "updated_at": self.meta.get("updated_at", ""),
        }
