"""重排（rerank）。

两档实现，按需切换：
- lexical：零成本规则重排（标题命中、精确短语、代码问句偏好），适合本地/低延迟场景；
- llm：把候选片段丢给模型做 listwise 排序，效果更好但每次多一次 LLM 调用。
生产上更常见的是 bge-reranker / Cohere Rerank 这类 cross-encoder，接口形状与此相同。
"""

from __future__ import annotations

import logging

from app.core.text import tokenize
from app.retrieval.index import Hit

logger = logging.getLogger(__name__)


def lexical_rerank(query: str, hits: list[Hit], top_n: int) -> list[Hit]:
    """规则重排：先把融合分归一化，再加启发式加分。

    坑（踩过）：RRF 分数在 1/(k+rank) 量级（约 0.01~0.05），
    而启发式加分动辄 0.1~0.3，直接相加会让「规则」彻底压过「检索」，
    排序完全失真。所以必须先 min-max 归一化，再按权重混合。
    """
    if not hits:
        return []
    q = query.lower()
    q_tokens = {t for t in tokenize(query) if len(t) > 1}
    wants_code = any(m in query for m in ("`", "代码", "示例", "example", "how to", "怎么写"))

    raw = [h.score for h in hits]
    lo, hi = min(raw), max(raw)
    span = hi - lo

    for h in hits:
        base = (h.score - lo) / span if span > 1e-12 else 1.0   # 归一化到 [0,1]
        boost = 0.0
        heading_tokens = {t for t in tokenize(h.chunk.heading_path.lower()) if len(t) > 1}
        if q_tokens and heading_tokens:
            boost += min(len(q_tokens & heading_tokens), 4) * 0.10
        if len(q) > 4 and q in h.chunk.text.lower():
            boost += 0.25
        if wants_code and "```" in h.chunk.text:
            boost += 0.12
        # 注意：代码块天然 token 密度低，不能因为「短」就被降权
        if h.chunk.tokens < 25 and "```" not in h.chunk.text:
            base -= 0.08
        h.score = base + boost

    reranked = sorted(hits, key=lambda x: x.score, reverse=True)[:top_n]
    for i, h in enumerate(reranked):
        h.rank = i + 1
    return reranked


async def llm_rerank(query: str, hits: list[Hit], top_n: int, model: str | None = None) -> list[Hit]:
    from app.core.llm import complete_json

    if len(hits) <= 1:
        return hits[:top_n]
    lines = []
    for h in hits:
        snippet = h.chunk.text[:320].replace("\n", " ")
        lines.append(f"[{h.chunk.chunk_id}] {h.chunk.heading_path or h.chunk.title} :: {snippet}")
    prompt = (
        "用户问题：" + query + "\n\n候选片段：\n" + "\n".join(lines) +
        f"\n\n请按与问题的相关性从高到低排序，最多保留 {top_n} 条。"
        '只输出 JSON：{"order": ["chunk_id", ...]}'
    )
    data = await complete_json(prompt, system="你是检索结果重排器，只输出 JSON。", model=model)
    order = (data or {}).get("order") or []
    if not order:
        return lexical_rerank(query, hits, top_n)
    pos = {cid: i for i, cid in enumerate(order)}
    ranked = sorted(hits, key=lambda h: pos.get(h.chunk.chunk_id, 10**6))[:top_n]
    for i, h in enumerate(ranked):
        h.rank = i + 1
    return ranked


async def rerank(query: str, hits: list[Hit], top_n: int, mode: str = "lexical") -> list[Hit]:
    if mode == "llm":
        try:
            return await llm_rerank(query, hits, top_n)
        except Exception as exc:  # noqa: BLE001
            logger.warning("llm rerank failed, fallback to lexical: %s", exc)
    if mode == "none":
        hits = hits[:top_n]
        for i, h in enumerate(hits):
            h.rank = i + 1
        return hits
    return lexical_rerank(query, hits, top_n)
