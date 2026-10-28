"""重排（rerank）。

两档实现，按需切换：
- lexical：零成本规则重排（标题命中、精确短语、代码问句偏好），适合本地/低延迟场景；
- llm：把候选片段丢给模型做 listwise 排序，效果更好但每次多一次 LLM 调用。
生产上更常见的是 bge-reranker / Cohere Rerank 这类 cross-encoder，接口形状与此相同。
"""

from __future__ import annotations

import asyncio
import logging

from app.core.text import tokenize
from app.retrieval.index import Hit

logger = logging.getLogger(__name__)


_ce = None


def _get_ce():
    """延迟加载 cross-encoder（transformers 裸调用）。

    不用 sentence-transformers 的 CrossEncoder：它会给部分模型自动套 prompt
    （bge-reranker 的 config 里带 prompts 字段），实测会把排序搞反。
    这里直接 tokenizer + AutoModelForSequenceClassification，分数就是原始 logit。
    """
    global _ce
    if _ce is None:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        from app.settings import get_settings

        path = get_settings().rerank_model_path
        logger.info("loading cross-encoder from %s", path)
        tok = AutoTokenizer.from_pretrained(path)
        model = AutoModelForSequenceClassification.from_pretrained(path).eval()
        torch.set_num_threads(max(1, (torch.get_num_threads() or 8)))
        _ce = (tok, model)
    return _ce


def _score_pairs(query: str, docs: list[str], max_length: int, batch: int = 16) -> list[float]:
    import torch

    tok, model = _get_ce()
    out: list[float] = []
    with torch.inference_mode():
        for i in range(0, len(docs), batch):
            chunk = docs[i : i + batch]
            enc = tok(
                [query] * len(chunk), chunk, padding=True, truncation=True,
                max_length=max_length, return_tensors="pt",
            )
            logits = model(**enc).logits.view(-1).float()
            out.extend(logits.tolist())
    return out


async def local_rerank(query: str, hits: list[Hit], top_n: int) -> list[Hit]:
    """本地 cross-encoder 重排（bge-reranker-v2-m3）。

    交叉编码器把 query 和 doc 拼在一起打分，能区分「词面像」和「真的能回答」。
    代价是逐对推理，所以只对候选池（candidate_k）做，不碰全库。
    """
    from app.settings import get_settings

    s = get_settings()
    # 片段标题（heading_path）里常有 API 名/参数名，对 cross-encoder 是强信号
    passages = [
        f"{h.chunk.heading_path}\n{h.chunk.text}" if h.chunk.heading_path else h.chunk.text
        for h in hits
    ]
    scores = await asyncio.to_thread(_score_pairs, query, passages, s.rerank_max_length)
    base = [h.score for h in hits]
    return _blend_and_rank(hits, base, [float(x) for x in scores], s.rerank_blend, top_n)


def _blend_and_rank(
    hits: list[Hit], base: list[float], ce: list[float], blend: float, top_n: int
) -> list[Hit]:
    """把「检索融合分」和「cross-encoder 分」各自 min-max 后加权。

    两种后端（本地 logits / 云端 sigmoid）量纲不同，但归一化后可比，
    所以 local 和 http 走同一个融合函数，A/B 结果才可迁移。
    blend=1 等价于不重排，blend=0 等价于纯 cross-encoder。
    """
    def norm(vals: list[float]) -> list[float]:
        lo, hi = min(vals), max(vals)
        span = hi - lo
        return [0.5] * len(vals) if span < 1e-9 else [(v - lo) / span for v in vals]

    alpha = max(0.0, min(1.0, blend))
    nbase, nce = norm(base), norm(ce)
    for h, b, c in zip(hits, nbase, nce):
        h.score = alpha * b + (1 - alpha) * c
    ranked = sorted(hits, key=lambda h: h.score, reverse=True)[:top_n]
    for i, h in enumerate(ranked):
        h.rank = i + 1
    return ranked


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


async def http_rerank(
    query: str, hits: list[Hit], top_n: int, url: str = "", timeout: float = 30.0
) -> list[Hit]:
    """调用 rerank 服务，兼容两种协议：

    - tei：自建 TEI / scripts/rerank_server.py，`{query, texts}` -> `[{index, score}]`
    - siliconflow：Jina 风格（硅基流动等），
      `{model, query, documents, top_n}` -> `{results: [{index, relevance_score}]}`
    """
    import httpx

    from app.settings import get_settings

    s = get_settings()
    target = url or s.rerank_url
    texts = [
        f"{h.chunk.heading_path}\n{h.chunk.text}" if h.chunk.heading_path else h.chunk.text
        for h in hits
    ]
    headers: dict[str, str] = {}
    if s.rerank_api == "siliconflow":
        payload = {
            "model": s.rerank_model,
            "query": query,
            "documents": texts,
            # 取全部候选的分数：只取 top_n 的话，后面的候选在融合时没有 CE 分，
            # blend 权重就形同虚设（实测 0.3/0.5/0.7 结果完全一样，就是因为这个）
            "top_n": len(texts),
            "return_documents": False,
        }
        if s.rerank_api_key:
            headers["Authorization"] = f"Bearer {s.rerank_api_key}"
    else:
        payload = {"query": query, "texts": texts, "truncate": True, "raw_scores": False}

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(target, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()

    items = data if isinstance(data, list) else data.get("results", [])
    scores_by_index: dict[int, float] = {}
    for item in items:
        score = item.get("score", item.get("relevance_score", 0.0))
        scores_by_index[int(item["index"])] = float(score)
    if not scores_by_index:
        raise RuntimeError("rerank 服务返回空结果")

    # top_n 之外的候选没被打分，给最低分，保证不会挤进结果
    base = [h.score for h in hits]
    ce = [scores_by_index.get(i, -1e9) for i in range(len(hits))]
    return _blend_and_rank(hits, base, ce, s.rerank_blend, top_n)


async def rerank(query: str, hits: list[Hit], top_n: int, mode: str = "lexical") -> list[Hit]:
    if mode == "local":
        try:
            return await local_rerank(query, hits, top_n)
        except Exception as exc:  # noqa: BLE001
            logger.warning("local rerank failed, fallback to lexical: %s", exc)
            return lexical_rerank(query, hits, top_n)
    if mode == "http":
        try:
            return await http_rerank(query, hits, top_n)
        except Exception as exc:  # noqa: BLE001
            logger.warning("http rerank failed, fallback to lexical: %s", exc)
            return lexical_rerank(query, hits, top_n)
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
