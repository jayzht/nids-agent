"""BM25 / 融合 / 重排的单元测试（不依赖 LLM 和网络）。"""

from __future__ import annotations

import numpy as np

from app.core.text import tokenize
from app.ingest.types import Chunk
from app.retrieval.bm25 import BM25
from app.retrieval.index import Hit, KBIndex
from app.retrieval.rerank import lexical_rerank
from app.settings import Settings


def make_chunk(cid: str, text: str, heading: str = "", kb: str = "kb", seq: int = 0) -> Chunk:
    return Chunk(
        chunk_id=cid, doc_id="d", kb=kb, path=f"{cid}.md", title="Doc",
        heading_path=heading, text=text, embed_text=f"{heading}\n{text}",
        tokens=len(text.split()), seq=seq,
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
