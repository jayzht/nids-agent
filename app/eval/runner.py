"""评估执行器：支持「只测检索」和「端到端」两种模式。

- retrieval：快（纯本地，不用 LLM），用来调 chunk size / top_k / 权重；
- end2end：慢（每题跑一遍 Agent + 一次 LLM 裁判），用来验证最终回答质量。
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from app.core.llm import complete_json
from app.eval import metrics
from app.kb import KBManager
from app.retrieval.service import Retriever

logger = logging.getLogger(__name__)
DATASET = Path(__file__).parent / "dataset.jsonl"

JUDGE_SYSTEM = "你是严格的技术问答评审。只输出 JSON。"
JUDGE_USER = """问题：{question}
参考答案要点：{must_include}
模型回答：
{answer}

请打分：
- faithfulness：回答是否完全基于给定资料、没有编造（0-1）
- relevance：是否切题（0-1）
- clarity：可读性（0-1）
输出 JSON：{{"faithfulness": 0.9, "relevance": 0.8, "clarity": 0.9, "reason": "..."}}"""


def load_dataset(kb: str | None = None) -> list[dict[str, Any]]:
    rows = []
    for line in DATASET.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        if kb and item.get("kb") != kb:
            continue
        rows.append(item)
    return rows


async def run_eval(
    retriever: Retriever,
    manager: KBManager,
    kb: str | None = None,
    mode: str = "retrieval",
    top_k: int = 6,
) -> dict[str, Any]:
    rows = load_dataset(kb)
    if not rows:
        return {"error": "评估集为空", "num_questions": 0}

    results: list[dict[str, Any]] = []
    t0 = time.time()

    for item in rows:
        question = item["question"]
        # 线上链路会先改写查询（中文 -> 英文 + 关键词化），评估要对齐这一步
        query = item.get("search_query") or question
        expected = item.get("expected_docs", [])
        target_kb = item.get("kb")

        hits = await retriever.search(
            query,
            kbs=[target_kb] if target_kb else None,
            k=top_k,
            rerank_query=question if retriever.settings.rerank_use_question else None,
        )
        doc_paths = [h.chunk.path for h in hits]
        row: dict[str, Any] = {
            "id": item.get("id"),
            "question": question,
            "query": query,
            "kb": target_kb,
            "retrieved": doc_paths,
            f"recall@{top_k}": metrics.recall_at_k(doc_paths, expected, top_k),
            "hit@1": metrics.recall_at_k(doc_paths, expected, 1),
            "hit@3": metrics.recall_at_k(doc_paths, expected, 3),
            "mrr": metrics.mrr(doc_paths, expected),
            f"ndcg@{top_k}": metrics.ndcg_at_k(doc_paths, expected, top_k),
        }

        if mode == "end2end":
            from app.agent.graph import RAGAgent
            from app.settings import get_settings

            agent = RAGAgent(retriever, manager, get_settings())
            final: dict[str, Any] = {}
            async for ev in agent.astream(question, kbs=[target_kb] if target_kb else None):
                if ev["type"] == "final":
                    final = ev
            answer = final.get("answer", "")
            cites = final.get("citations", [])
            row.update(
                {
                    "answer": answer,
                    "citations": len(cites),
                    "keyword_coverage": metrics.keyword_coverage(
                        answer, item.get("must_include", [])
                    ),
                    "citation_precision": metrics.citation_precision(cites, expected),
                    "verdict": final.get("verdict", ""),
                }
            )
            judge = await complete_json(
                JUDGE_USER.format(
                    question=question,
                    must_include=", ".join(item.get("must_include", [])) or "（无）",
                    answer=answer[:3000],
                ),
                system=JUDGE_SYSTEM,
                fallback={},
            )
            if isinstance(judge, dict):
                for key in ("faithfulness", "relevance", "clarity"):
                    try:
                        row[key] = float(judge.get(key, 0.0))
                    except (TypeError, ValueError):
                        row[key] = 0.0
                row["judge_reason"] = str(judge.get("reason", ""))[:300]

        results.append(row)

    return {
        "mode": mode,
        "kb": kb or "all",
        "num_questions": len(results),
        "top_k": top_k,
        "elapsed": round(time.time() - t0, 1),
        "summary": metrics.aggregate(
            [{k: v for k, v in r.items() if isinstance(v, (int, float))} for r in results]
        ),
        "details": results,
    }
