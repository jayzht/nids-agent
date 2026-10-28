"""检索服务：跨知识库查询 + 融合 + 重排。Agent 层只跟这里打交道。"""

from __future__ import annotations

import asyncio

from app.core.llm import get_embedder
from app.kb import KBManager
from app.retrieval.index import Hit
from app.retrieval.rerank import rerank


def diversify(
    hits: list[Hit], limit: int, max_per_doc: int = 0, min_tokens: int = 0
) -> list[Hit]:
    """同文档限流 + 过滤碎片片段。

    为什么需要：论文类文档动辄几十个片段、且 heading 全是论文标题，BM25 会把
    整篇的标题词都算成高相关，结果 top-k 被一篇论文霸榜（实测占了 4/6 个坑位），
    真正回答问题的段落反而进不来。这里按 doc_id 限流，并丢掉 tokens 过小的
    碎片（作者列表、目录残行）。
    """
    out: list[Hit] = []
    per_doc: dict[str, int] = {}
    for h in hits:
        if min_tokens and h.chunk.tokens < min_tokens:
            continue
        doc = h.chunk.doc_id
        if max_per_doc and per_doc.get(doc, 0) >= max_per_doc:
            continue
        per_doc[doc] = per_doc.get(doc, 0) + 1
        out.append(h)
        if limit and len(out) >= limit:
            break
    return out
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
        prefixes: list[str] | None = None,
        rerank_query: str | None = None,
        skip_rerank: bool = False,
    ) -> list[Hit]:
        s = self.settings
        k = k or s.top_k
        candidate_k = candidate_k or s.candidate_k
        targets = kbs or self.manager.names()
        if not targets:
            return []

        if s.retrieval_mode == "sparse":
            qvec = None      # 纯 BM25，不需要 embedding 服务
        else:
            qvec = await get_embedder().embed_query(query)
        # 注意：检索深度不能为了「筛完还够数」而放大——融合分是 min-max 归一化的，
        # 池子从 20 扩到 60 会改变归一化尺度，实测 MRR 0.898 → 0.865。
        merged = await self._search_many(query, qvec, targets, candidate_k, prefixes)
        merged = diversify(merged, candidate_k, s.max_per_doc, s.min_chunk_tokens)
        if not merged:
            return []
        if skip_rerank:
            return merged[:k]
        return await rerank(
            rerank_query or query, merged, k, mode=rerank_mode or s.rerank_mode
        )

    async def _search_many(
        self,
        query: str,
        qvec,
        targets: list[str],
        candidate_k: int,
        prefixes: list[str] | None = None,
        rerank_query: str | None = None,
        skip_rerank: bool = False,
    ) -> list[Hit]:
        """多知识库：先各自召回，再用 RRF 做第二轮融合（跨库分数不可比）。"""
        s = self.settings

        async def one(name: str) -> list[Hit]:
            try:
                index = await self.manager.get_async(name)
            except Exception:  # noqa: BLE001
                return []
            return await asyncio.to_thread(
                index.hybrid_search, query, qvec, candidate_k, candidate_k, prefixes
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
