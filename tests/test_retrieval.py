"""BM25 / 融合 / 重排的单元测试（不依赖 LLM 和网络）。"""

from __future__ import annotations

import numpy as np

from app.core.text import tokenize
from app.ingest.types import Chunk
from app.retrieval.bm25 import BM25
from app.retrieval.index import Hit, KBIndex
from app.retrieval.rerank import lexical_rerank
from app.settings import Settings


def make_chunk(
    cid: str, text: str, heading: str = "", kb: str = "kb", seq: int = 0,
    doc_id: str = "d", tokens: int = 0,
) -> Chunk:
    return Chunk(
        chunk_id=cid, doc_id=doc_id, kb=kb, path=f"{cid}.md", title="Doc",
        heading_path=heading, text=text, embed_text=f"{heading}\n{text}",
        tokens=tokens or len(text.split()), seq=seq,
    )


def test_bm25_ranks_exact_term_first():
    corpus = [
        tokenize("dependency injection with Depends"),
        tokenize("background tasks and middleware"),
        tokenize("query parameters and validation"),
    ]
    bm25 = BM25(corpus)
    ranked = bm25.search(tokenize("Depends"), top_k=3)
    assert ranked[0][0] == 0


def test_bm25_returns_empty_for_unknown_term():
    bm25 = BM25([tokenize("hello world")])
    assert bm25.search(tokenize("zzz"), top_k=3) == []


def test_chinese_bigram_tokenizer():
    toks = tokenize("依赖注入")
    assert "依赖" in toks and "注入" in toks


def test_hybrid_search_prefers_exact_keyword_over_pure_vector():
    """构造一个「向量分很高但词不相关」的陷阱，验证 BM25 权重能把对的顶上来。"""
    s = Settings(bm25_weight=0.6, rrf_k=60, vector_backend="numpy")
    chunks = [
        make_chunk("c_irrelevant", "totally unrelated content about cooking", "Cooking"),
        make_chunk("c_relevant", "HTTPBearer security scheme in FastAPI", "Security"),
    ]
    index = KBIndex({"name": "kb", "title": "t"}, chunks, store=type("S", (), {
        "search": lambda self, q, k: [("c_irrelevant", 0.9), ("c_relevant", 0.2)],
    })(), settings=s)
    index.bm25 = BM25([tokenize("totally unrelated cooking"), tokenize("HTTPBearer security FastAPI")])

    hits = index.hybrid_search("HTTPBearer", np.zeros(4, dtype=np.float32), k=2, candidate_k=2)
    assert hits[0].chunk.chunk_id == "c_relevant"
    assert "sparse" in hits[0].sources


def test_lexical_rerank_lifts_heading_and_code_match():
    """重排的职责：把「排名靠后但标题/代码高度匹配」的片段往上提，而不是推翻检索结果。"""
    base = [
        ("d0", "unrelated prose about cooking", "Misc"),
        ("d1", "unrelated prose about sports", "Misc"),
        ("d2", "unrelated prose about weather", "Misc"),
        ("d3", "```python\nDepends(get_db)\n```\nDependencies usage example", "Dependencies"),
        ("d4", "unrelated prose about music", "Misc"),
    ]
    hits = [
        Hit(make_chunk(cid, text, heading), score=0.9 - i * 0.1)
        for i, (cid, text, heading) in enumerate(base)
    ]
    ranked = lexical_rerank("Dependencies usage example", hits, top_n=5)
    new_pos = next(i for i, h in enumerate(ranked) if h.chunk.chunk_id == "d3")
    assert new_pos <= 1, f"d3 应该被提到前二，实际第 {new_pos + 1}"


def test_ndcg_and_recall_metrics():
    from app.eval.metrics import keyword_coverage, mrr, ndcg_at_k, recall_at_k

    paths = ["a/wrong.md", "tutorial/query-params.md"]
    expected = ["tutorial/query-params"]
    assert recall_at_k(paths, expected, 2) == 1.0
    assert recall_at_k(paths, expected, 1) == 0.0
    assert abs(mrr(paths, expected) - 0.5) < 1e-6
    assert ndcg_at_k(paths, expected, 2) > 0
    assert keyword_coverage("使用 Query 声明参数", ["Query", "Body"]) == 0.5


def test_metrics_with_empty_input():
    from app.eval.metrics import mrr, ndcg_at_k, recall_at_k

    assert recall_at_k([], ["x"], 5) == 0.0
    assert mrr([], ["x"]) == 0.0
    assert ndcg_at_k([], ["x"], 5) == 0.0


async def test_http_rerank_falls_back_when_service_unreachable(monkeypatch):
    """云端重排挂了不能把整条链路拖死：必须降级到规则重排，而不是抛异常或等 30s。"""
    from app.retrieval import rerank as R
    from app.settings import get_settings

    s = get_settings()
    monkeypatch.setattr(s, "rerank_mode", "http")
    monkeypatch.setattr(s, "rerank_url", "http://127.0.0.1:9/rerank")  # 必然拒连
    monkeypatch.setattr(s, "rerank_timeout", 2.0)

    hits = [
        Hit(make_chunk("a", "unrelated prose about cooking", "Misc"), score=0.9),
        Hit(make_chunk("b", "```python\nDepends(get_db)\n```", "Dependencies"), score=0.5),
    ]
    ranked = await R.rerank("Dependencies usage example", hits, top_n=2, mode="http")
    assert [h.chunk.chunk_id for h in ranked] == [
        h.chunk.chunk_id for h in R.lexical_rerank("Dependencies usage example", hits, top_n=2)
    ], "服务不可用时应当降级成规则重排，而不是抛异常或返回原序"
    assert [h.rank for h in ranked] == [1, 2]


def test_diversify_caps_per_doc_and_drops_fragments():
    """一篇论文不能霸榜；作者列表这类碎片片段不进候选。"""
    from app.retrieval.service import diversify

    body = " ".join(["word"] * 200)
    hits = [
        Hit(make_chunk(f"p{i}", body, "Paper Title", doc_id="paper", tokens=300), score=0.9 - i / 100)
        for i in range(4)
    ]
    hits.append(Hit(make_chunk("a1", "Authors: A, B, C", "Paper Title", doc_id="paper", tokens=10),
                    score=0.83))
    hits.append(Hit(make_chunk("z1", "zeek conn.log fields", "Zeek", doc_id="zeek", tokens=200),
                    score=0.6))

    out = diversify(hits, limit=5, max_per_doc=2, min_tokens=32)
    ids = [h.chunk.chunk_id for h in out]
    assert ids == ["p0", "p1", "z1"], ids


class _IndexLike:
    """只测 neighbors 的纯逻辑，不需要向量库。"""

    from app.retrieval.index import KBIndex as _KB

    neighbors = _KB.neighbors

    def __init__(self, chunks):
        self.chunks = chunks
        self.by_id = {c.chunk_id: i for i, c in enumerate(chunks)}


def test_neighbors_are_seq_adjacent_and_same_doc():
    chunks = [
        make_chunk(f"c{i}", f"text {i}", f"Doc > S{i}", seq=i, doc_id="doc1", tokens=100)
        for i in range(4)
    ]
    idx = _IndexLike(chunks)
    assert [c.chunk_id for c in idx.neighbors("c1", window=1)] == ["c0", "c2"]
    assert [c.chunk_id for c in idx.neighbors("c3", window=2)] == ["c1", "c2"]
    assert idx.neighbors("missing") == []

    # 同一文档里 seq 相同但 doc_id 不同的片段不能被当成邻居
    other = make_chunk("x0", "other", "Other", seq=0, doc_id="doc2", tokens=100)
    idx2 = _IndexLike(chunks + [other])
    assert "x0" not in [c.chunk_id for c in idx2.neighbors("c1", window=1)]
