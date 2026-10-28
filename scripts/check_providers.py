"""体检脚本：一次性验证 LLM / embedding / rerank 三个后端是否可用、是否与索引匹配。

用法：
    .venv/bin/python scripts/check_providers.py            # 检查 .env 里配的全部
    .venv/bin/python scripts/check_providers.py --kb ids   # 指定要比对的索引

为什么需要它：换 API 供应商时最容易踩的两个坑是
1) embedding 维度/模型和索引不一致 —— 不报错的检索会静默变差；
2) rerank 协议不对 —— 有的服务是 texts/score（TEI），有的是 documents/relevance_score（Jina 风格）。
这两件事都是「配错了也能跑，但结果变差」，所以必须有脚本显式验证。
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx  # noqa: E402

from app.settings import get_settings  # noqa: E402

OK = "✅"
BAD = "❌"
WARN = "⚠️ "


async def check_llm(s) -> tuple[bool, str]:
    if not s.llm_api_key:
        return False, "LLM_API_KEY 为空"
    started = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=s.llm_timeout) as c:
            r = await c.post(
                f"{s.llm_base_url.rstrip('/')}/chat/completions",
                headers={"Authorization": f"Bearer {s.llm_api_key}"},
                json={
                    "model": s.llm_model,
                    "messages": [{"role": "user", "content": "只回复 ok"}],
                    "max_tokens": 8,
                },
            )
            r.raise_for_status()
            text = r.json()["choices"][0]["message"]["content"].strip()
        ms = (time.perf_counter() - started) * 1000
        return True, f"{s.llm_model} · {ms:.0f}ms · 回复 {text!r}"
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {str(exc)[:200]}"


async def check_embedding(s, kb: str | None) -> tuple[bool, str]:
    if not s.embedding_api_key and "127.0.0.1" not in s.embedding_base_url:
        return False, "EMBEDDING_API_KEY 为空"
    started = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=s.llm_timeout) as c:
            r = await c.post(
                f"{s.embedding_base_url.rstrip('/')}/embeddings",
                headers={"Authorization": f"Bearer {s.embedding_api_key}"},
                json={"model": s.embedding_model, "input": ["端口扫描怎么检测", "port scan detection"]},
            )
            r.raise_for_status()
            data = r.json()["data"]
        dim = len(data[0]["embedding"])
        ms = (time.perf_counter() - started) * 1000
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {str(exc)[:200]}"

    detail = f"{s.embedding_model} · {dim} 维 · {ms:.0f}ms"

    # 与索引比对：维度不一致 = 必须重建索引，否则检索静默变差
    meta = _index_meta(s, kb)
    if meta:
        want_dim = meta.get("embedding_dim")
        want_model = meta.get("embedding_model")
        detail += f" | 索引 {meta['name']}: {want_model} / {want_dim} 维"
        if want_dim and dim != want_dim:
            return False, detail + f" → 维度不一致（差 {dim - want_dim:+d}），需要重建索引"
        if want_model and want_model != s.embedding_model:
            return True, detail + f" → 模型名不同（{want_model} vs {s.embedding_model}），确认是同一模型再说"
        detail += " → 匹配"
    if not s.embedding_dim:
        detail += " | EMPTY：.env 里 embedding_dim 未设置，建议设成 " + str(dim)
    return True, detail


async def check_rerank(s) -> tuple[bool, str]:
    if s.rerank_mode == "none":
        return True, "未启用（RERANK_MODE=none）"
    docs = [
        "suricata 的 eve.json 里 flow 事件的字段说明",
        "用 tshark 提取 http.user_agent 字段做统计",
        "如何用 Ollama 部署本地大模型",
    ]
    query = "怎么从 http 流量里取 user_agent"

    if s.rerank_mode == "local":
        # 本地 cross-encoder：真正加载一次权重，最容易出错的是路径不对
        try:
            from app.retrieval.rerank import _score_pairs

            started = time.perf_counter()
            scores = await asyncio.to_thread(_score_pairs, query, docs, 512)
            ms = (time.perf_counter() - started) * 1000
        except Exception as exc:  # noqa: BLE001
            return False, f"local · {type(exc).__name__}: {str(exc)[:200]}"
        order = sorted(range(len(docs)), key=lambda i: scores[i], reverse=True)
        good = order[0] in (0, 1) and order[-1] == 2
        detail = f"local · {s.rerank_model_path} · {ms:.0f}ms · 排序 {order}"
        return (True, detail + " → 匹配") if good else (False, detail + " → 排序异常，检查权重")

    started = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=s.rerank_timeout) as c:
            headers = {}
            if s.rerank_api == "siliconflow":
                payload = {
                    "model": s.rerank_model,
                    "query": query,
                    "documents": docs,
                    "top_n": 3,
                    "return_documents": False,
                }
                if s.rerank_api_key:
                    headers["Authorization"] = f"Bearer {s.rerank_api_key}"
            else:
                payload = {"query": query, "texts": docs, "truncate": True, "raw_scores": False}
            r = await c.post(s.rerank_url, json=payload, headers=headers)
            r.raise_for_status()
            data = r.json()
    except Exception as exc:  # noqa: BLE001
        return False, f"{s.rerank_api} · {type(exc).__name__}: {str(exc)[:200]}"

    items = data if isinstance(data, list) else data.get("results", [])
    if not items:
        return False, f"{s.rerank_api} · 返回空结果：{json.dumps(data)[:200]}"
    order = [int(i["index"]) for i in items]
    scores = [float(i.get("score", i.get("relevance_score", 0.0))) for i in items]
    ms = (time.perf_counter() - started) * 1000
    # docs[0] 和 docs[1] 都相关，docs[2]（本地部署）与查询无关，应当排在最后
    good = order and order[0] in (0, 1) and (len(order) < 3 or order[-1] == 2)
    detail = (
        f"{s.rerank_api} · {s.rerank_model} · {ms:.0f}ms · "
        f"排序 {order} 分数 {[round(x, 3) for x in scores]}"
    )
    return good, detail if good else detail + " → 排序异常，检查协议/模型"


def _index_meta(s, kb: str | None) -> dict | None:
    root = s.kb_root
    if kb:
        candidates = [root / kb]
    else:
        candidates = sorted(p for p in root.iterdir() if (p / "meta.json").exists()) if root.exists() else []
        # 默认优先 ids（本项目的 NIDS 主库）
        candidates.sort(key=lambda p: (p.name != "ids", p.name))
    for path in candidates:
        f = path / "meta.json"
        if f.exists():
            return json.loads(f.read_text(encoding="utf-8"))
    return None


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kb", default=None, help="要比对 embedding 的索引名（默认 ids）")
    args = ap.parse_args()

    s = get_settings()
    print(f"LLM        : {s.llm_base_url} / {s.llm_model}")
    print(f"Embedding  : {s.embedding_base_url} / {s.embedding_model}")
    print(f"Retrieval  : {s.retrieval_mode} | Rerank: {s.rerank_mode}")
    print("-" * 72)

    results = {}
    results["llm"] = await check_llm(s)
    results["embedding"] = await check_embedding(s, args.kb)
    results["rerank"] = await check_rerank(s)

    failed = 0
    for name, (ok, detail) in results.items():
        print(f"{OK if ok else BAD} {name:<10} {detail}")
        failed += 0 if ok else 1
    print("-" * 72)

    if s.retrieval_mode == "hybrid" and not results["embedding"][0]:
        print(f"{WARN}RETRIEVAL_MODE=hybrid 但 embedding 不可用：检索会失败，改成 sparse 或修好 embedding")
    if failed:
        print(f"{BAD} {failed} 项未通过")
    else:
        print(f"{OK} 全部通过")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
