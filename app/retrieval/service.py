"""检索服务：跨知识库查询 + 融合 + 重排。Agent 层只跟这里打交道。"""

from __future__ import annotations

import asyncio

from app.core.llm import get_embedder
from app.kb import KBManager
from app.retrieval.index import Hit
from app.retrieval.rerank import rerank
from app.settings import Settings


class Retriever:
    def __init__(self, manager: KBManager, settings: Settings) -> None:
        self.manager = manager
        self.settings = settings

    async def search(
        self,
        query: str,
        kbs: list[str] | None = None,
        k: int | None = None,
        candidate_k: int | None = None,
        rerank_mode: str | None = None,
    ) -> list[Hit]:
        s = self.settings
        k = k or s.top_k
        candidate_k = candidate_k or s.candidate_k
        targets = kbs or self.manager.names()
        if not targets:
            return []

        qvec = await get_embedder().embed_query(query)
        merged = await self._search_many(query, qvec, targets, candidate_k)
        if not merged:
            return []
        return await rerank(query, merged, k, mode=rerank_mode or s.rerank_mode)

    async def _search_many(
        self, query: str, qvec, targets: list[str], candidate_k: int
    ) -> list[Hit]:
        """多知识库：先各自召回，再用 RRF 做第二轮融合（跨库分数不可比）。"""
        s = self.settings

        async def one(name: str) -> list[Hit]:
            try:
                index = await self.manager.get_async(name)
            except Exception:  # noqa: BLE001
                return []
            return await asyncio.to_thread(
                index.hybrid_search, query, qvec, candidate_k, candidate_k
            )

        results = await asyncio.gather(*(one(n) for n in targets))
        if len(results) == 1:
            return results[0]

        fused: dict[str, Hit] = {}
        scores: dict[str, float] = {}
        for hits in results:
            for h in hits:
                key = h.chunk.chunk_id
                fused.setdefault(key, h)
                scores[key] = scores.get(key, 0.0) + 1.0 / (s.rrf_k + h.rank)
        ordered = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)[:candidate_k]
        out: list[Hit] = []
        for key, score in ordered:
            h = fused[key]
            h.score = score
            out.append(h)
        return out

    async def get_chunk(self, kb: str, chunk_id: str) -> dict | None:
        index = await self.manager.get_async(kb)
        idx = index.by_id.get(chunk_id)
        if idx is None:
            return None
        c = index.chunks[idx]
        return {
            "chunk_id": c.chunk_id,
            "doc_id": c.doc_id,
            "kb": c.kb,
            "path": c.path,
            "title": c.title,
            "heading_path": c.heading_path,
            "text": c.text,
            "source_url": c.source_url,
        }

    async def get_document(self, kb: str, doc_id: str) -> dict | None:
        """按 doc_id 取整篇文档（把该文档的片段按 seq 拼回去）。"""
        index = await self.manager.get_async(kb)
        chunks = [c for c in index.chunks if c.doc_id == doc_id]
        if not chunks:
            return None
        chunks.sort(key=lambda c: c.seq)
        return {
            "doc_id": doc_id,
            "kb": kb,
            "path": chunks[0].path,
            "title": chunks[0].title,
            "source_url": chunks[0].source_url,
            "text": "\n\n".join(c.text for c in chunks),
            "num_chunks": len(chunks),
        }
