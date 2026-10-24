"""LangGraph 主图：一个「带自我纠错」的 Corrective RAG。

    START
      │
    router ──chitchat──▶ chat ──▶ END
      │ question
    rewrite ◀──────────────┐
      │                    │ (检索不到 / 相关性不足时带着反馈重试)
    retrieve               │
      │                    │
    grade ──无相关─────────┘
      │ 有相关
    generate ──没有引用──▶ generate(严格模式，最多一次)
      │
    verify ──▶ finalize ──▶ END

和「一次性检索 + 生成」相比，这里多了三件事：
1. query rewrite（多查询，中→英跨语言）；
2. 检索结果由 LLM 逐条打分（0/1/2），差的结果直接扔掉，不喂给生成模型；
3. 生成后校验引用编号，未落引用时强制重生成一次 —— 这是压幻觉最有效的一步。
"""

from __future__ import annotations

import logging
import uuid
import re
import time
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from app.agent import prompts
from app.agent.state import RAGState
from app.core.llm import get_chat_model, with_no_think
from app.core.text import truncate
from app.kb import KBManager
from app.retrieval.service import Retriever
from app.settings import Settings

logger = logging.getLogger(__name__)

_GREETING_RE = re.compile(r"^(你好|您好|hi|hello|嗨|在吗|谢谢|感谢|thanks|thank you)[\s!！。.,，]*$", re.I)
_CITE_RE = re.compile(r"\[(\d+)\]")


class RAGAgent:
    def __init__(self, retriever: Retriever, manager: KBManager, settings: Settings) -> None:
        self.retriever = retriever
        self.manager = manager
        self.settings = settings
        self.graph = self._build()

    # ------------------------------------------------------------------ 图
    def _build(self):
        g = StateGraph(RAGState)
        g.add_node("router", self.node_router)
        g.add_node("chat", self.node_chat)
        g.add_node("rewrite", self.node_rewrite)
        g.add_node("retrieve", self.node_retrieve)
        g.add_node("grade", self.node_grade)
        g.add_node("generate", self.node_generate)
        g.add_node("verify", self.node_verify)
        g.add_node("finalize", self.node_finalize)
        g.add_node("no_answer", self.node_no_answer)

        g.add_edge(START, "router")
        g.add_conditional_edges(
            "router", self.route_after_router, {"chat": "chat", "rewrite": "rewrite"}
        )
        g.add_edge("chat", END)
        g.add_edge("rewrite", "retrieve")
        g.add_edge("retrieve", "grade")
        g.add_conditional_edges(
            "grade",
            self.route_after_grade,
            {"generate": "generate", "rewrite": "rewrite", "no_answer": "no_answer"},
        )
        g.add_edge("generate", "verify")
        g.add_conditional_edges(
            "verify", self.route_after_verify, {"generate": "generate", "finalize": "finalize"}
        )
        g.add_edge("finalize", END)
        g.add_edge("no_answer", END)
        return g.compile(checkpointer=MemorySaver())

    # ------------------------------------------------------------- helpers
    def _history(self, state: RAGState) -> str:
        msgs = state.get("messages") or []
        lines: list[str] = []
        for m in msgs[-self.settings.history_turns * 2 :]:
            role = "用户" if isinstance(m, HumanMessage) else "助手"
            content = m.content if isinstance(m.content, str) else str(m.content)
            if isinstance(m, HumanMessage) and content == state.get("question"):
                continue
            lines.append(f"{role}: {truncate(content, 400)}")
        return "\n".join(lines) or "（无）"

    def _kb_list_text(self) -> str:
        metas = self.manager.list_meta()
        if not metas:
            return "（无可用知识库）"
        return "\n".join(f"- {m['name']}: {m['title']} — {m['description']}" for m in metas)

    # --------------------------------------------------------------- nodes
    async def node_router(self, state: RAGState) -> dict[str, Any]:
        t0 = time.time()
        question = (state.get("question") or "").strip()
        forced = state.get("kbs") or []
        intent, need, kbs, how = "question", True, list(forced), "user"

        if not forced:
            available = self.manager.names()
            if _GREETING_RE.match(question):
                intent, need, kbs, how = "chitchat", False, [], "regex"
            elif len(available) <= 1:
                kbs, how = available, "single_kb"
            else:
                data = await self._llm_route(question, state)
                intent = data.get("intent", "question")
                need = bool(data.get("need_retrieval", True))
                picked = [k for k in (data.get("kbs") or []) if k in available]
                kbs = picked or available
                how = "llm"

        return {
            "intent": intent,
            "need_retrieval": need,
            "kbs": kbs,
            "sources": state.get("sources") or [],
            # 每轮对话重置：这些字段是「本轮」的，不能从上一次检查点里带过来
            "queries": [],
            "candidates": [],
            "relevant": [],
            "answer": "",
            "citations": [],
            "verdict": "",
            "attempts": 0,
            "gen_attempts": 0,
            "steps": [{
                "node": "router",
                "title": f"路由判定：{intent}（{how}）",
                "detail": {"intent": intent, "need_retrieval": need, "kbs": kbs,
                           "ms": round((time.time() - t0) * 1000)},
            }],
        }

    async def _llm_route(self, question: str, state: RAGState) -> dict:
        from app.core.llm import complete_json

        data = await complete_json(
            prompts.ROUTER_USER.format(
                kb_list=self._kb_list_text(), history=self._history(state), question=question
            ),
            system=prompts.ROUTER_SYSTEM,
            fallback={},
        )
        return data if isinstance(data, dict) else {}

    async def node_chat(self, state: RAGState) -> dict[str, Any]:
        llm = get_chat_model()
        resp = await llm.ainvoke(
            [("system", with_no_think("你是一个友好的技术助手，简短回答。")),
             ("human", state["question"])]
        )
        return {
            "answer": resp.content if isinstance(resp.content, str) else str(resp.content),
            "verdict": "answered",
            "citations": [],
            "steps": [{"node": "chat", "title": "闲聊直答（未检索）", "detail": {}}],
        }

    async def node_rewrite(self, state: RAGState) -> dict[str, Any]:
        from app.core.llm import complete_json

        t0 = time.time()
        attempt = state.get("attempts", 0)
        feedback = ""
        if attempt:
            feedback = (
                "\n注意：上一轮检索结果相关性不足，请换用不同的关键词/英文术语重新生成查询。"
            )
        kb_desc = ", ".join(
            f"{m['name']}（{m['title']}）" for m in self.manager.list_meta()
            if not state.get("kbs") or m["name"] in state["kbs"]
        )
        data = await complete_json(
            prompts.REWRITE_USER.format(
                kb_desc=kb_desc or "（无）",
                history=self._history(state),
                question=state["question"],
                feedback=feedback,
            ),
            system=prompts.REWRITE_SYSTEM,
            fallback={},
        )
        queries = []
        if isinstance(data, dict):
            queries = [q.strip() for q in (data.get("queries") or []) if isinstance(q, str) and q.strip()]
        if not queries:
            queries = [state["question"]]
        queries = list(dict.fromkeys(queries))[:3]
        return {
            "queries": queries,
            "steps": [{
                "node": "rewrite",
                "title": f"查询改写 → {len(queries)} 条",
                "detail": {"queries": queries, "retry": attempt > 0,
                           "ms": round((time.time() - t0) * 1000)},
            }],
        }

    async def node_retrieve(self, state: RAGState) -> dict[str, Any]:
        t0 = time.time()
        queries = state.get("queries") or [state["question"]]
        kbs = state.get("kbs") or None
        prefixes = state.get("sources") or None
        best: dict[str, tuple[Any, str]] = {}

        for q in queries:
            hits = await self.retriever.search(
                q, kbs=kbs, k=self.settings.candidate_k, prefixes=prefixes
            )
            for h in hits:
                cid = h.chunk.chunk_id
                if cid not in best or h.score > best[cid][0].score:
                    best[cid] = (h, q)

        ranked = sorted(best.values(), key=lambda x: x[0].score, reverse=True)[: self.settings.candidate_k]
        candidates = []
        for h, q in ranked:
            item = h.to_public()
            item["matched_query"] = q
            candidates.append(item)

        return {
            "candidates": candidates,
            "steps": [{
                "node": "retrieve",
                "title": f"混合检索 → {len(candidates)} 个候选",
                "detail": {
                    "queries": queries,
                    "kbs": kbs or self.manager.names(),
                    "sources": state.get("sources") or [],
                    "candidates": [
                        {"chunk_id": c["chunk_id"], "title": c["heading_path"] or c["title"],
                         "path": c["path"], "score": c["score"], "sources": c["sources"]}
                        for c in candidates[:10]
                    ],
                    "ms": round((time.time() - t0) * 1000),
                },
            }],
        }

    async def node_grade(self, state: RAGState) -> dict[str, Any]:
        from app.core.llm import complete_json

        t0 = time.time()
        cands = state.get("candidates") or []
        attempts = state.get("attempts", 0) + 1
        if not cands:
            return {
                "relevant": [], "attempts": attempts,
                "steps": [{"node": "grade", "title": "无候选片段", "detail": {"attempt": attempts}}],
            }

        pool = cands[:12]
        lines = []
        for i, c in enumerate(pool, 1):
            lines.append(
                f"[c{i}] {c['heading_path'] or c['title']} | {c['path']}\n{truncate(c['text'], 700)}"
            )
        data = await complete_json(
            prompts.GRADE_USER.format(question=state["question"], candidates="\n\n".join(lines)),
            system=prompts.GRADE_SYSTEM,
            fallback=None,
        )

        scores: dict[str, int] = {}
        if isinstance(data, dict):
            for g in data.get("grades") or []:
                try:
                    idx = int(str(g.get("id", "")).lstrip("c")) - 1
                    if 0 <= idx < len(pool):
                        scores[pool[idx]["chunk_id"]] = int(g.get("score", 0))
                except (ValueError, TypeError):
                    continue

        if scores:
            relevant = [c for c in pool if scores.get(c["chunk_id"], 0) >= 1]
            graded_by = "llm"
        else:
            # LLM 不可用 / 输出坏了：退化为按融合分截断，保证服务可用
            relevant = pool[:4]
            graded_by = "fallback"

        return {
            "relevant": relevant,
            "attempts": attempts,
            "steps": [{
                "node": "grade",
                "title": f"相关性打分 → 保留 {len(relevant)}/{len(pool)}",
                "detail": {
                    "approach": graded_by,
                    "attempt": attempts,
                    "grades": [
                        {"chunk_id": c["chunk_id"], "score": scores.get(c["chunk_id"], -1),
                         "title": c["heading_path"] or c["title"]}
                        for c in pool
                    ],
                    "ms": round((time.time() - t0) * 1000),
                },
            }],
        }

    def _build_context(self, relevant: list[dict]) -> tuple[str, list[dict]]:
        parts: list[str] = []
        used: list[dict] = []
        total = 0
        for i, c in enumerate(relevant, 1):
            block = (
                f"[{i}] {c['kb']} · {c['heading_path'] or c['title']} · {c['path']}\n"
                f"{c['text']}"
            )
            if total + len(block) > self.settings.max_context_chars and used:
                break
            parts.append(block)
            used.append(c)
            total += len(block)
        return "\n\n---\n\n".join(parts), used

    async def node_generate(self, state: RAGState) -> dict[str, Any]:
        t0 = time.time()
        relevant = state.get("relevant") or []
        context, used = self._build_context(relevant)
        gen_attempts = state.get("gen_attempts", 0)

        user = prompts.GENERATE_USER.format(
            context=context or "（无）",
            history=self._history(state),
            question=state["question"],
        )
        if gen_attempts > 0:
            user += (
                "\n\n【重要】上一次回答没有标注引用编号。本次回答的每一句事实都必须带上 "
                "[1]、[2] 这样的编号，否则视为无效答案。"
            )

        llm = get_chat_model()
        resp = await llm.ainvoke(
            [("system", with_no_think(prompts.GENERATE_SYSTEM)), ("human", user)]
        )
        answer = resp.content if isinstance(resp.content, str) else str(resp.content)
        return {
            "answer": answer,
            "context": context,
            "relevant": used,
            "gen_attempts": gen_attempts + 1,
            "steps": [{
                "node": "generate",
                "title": f"生成回答（{len(used)} 个片段进上下文）",
                "detail": {"context_chars": len(context), "retry": gen_attempts > 0,
                           "attempt": gen_attempts + 1, "ms": round((time.time() - t0) * 1000)},
            }],
        }

    async def node_verify(self, state: RAGState) -> dict[str, Any]:
        answer = state.get("answer") or ""
        n = len(state.get("relevant") or [])
        cited = sorted({int(x) for x in _CITE_RE.findall(answer)})
        valid = [i for i in cited if 1 <= i <= n]
        # 「无相关」类回答不需要引用
        refused = any(k in answer for k in ("没有找到", "未找到", "无法回答", "不足以回答"))
        if refused:
            verdict, reason = "no_answer", "模型判定资料不足"
        elif valid:
            verdict, reason = "answered", "引用编号有效"
        elif n == 0:
            verdict, reason = "no_answer", "无参考资料"
        else:
            verdict, reason = "ungrounded", "回答中没有任何有效引用"
        return {
            "verdict": verdict,
            "steps": [{
                "node": "verify",
                "title": f"引用校验：{verdict}（{reason}）",
                "detail": {"cited": cited, "valid": valid, "context_chunks": n},
            }],
        }

    async def node_finalize(self, state: RAGState) -> dict[str, Any]:
        answer = state.get("answer") or ""
        relevant = state.get("relevant") or []
        citations: list[dict] = []
        for idx in sorted({int(x) for x in _CITE_RE.findall(answer)}):
            if 1 <= idx <= len(relevant):
                c = relevant[idx - 1]
                citations.append({
                    "index": idx,
                    "chunk_id": c["chunk_id"],
                    "kb": c["kb"],
                    "title": c["heading_path"] or c["title"],
                    "path": c["path"],
                    "source_url": c.get("source_url", ""),
                    "snippet": truncate(c["text"], 240),
                })
        msgs = [HumanMessage(content=state["question"]), AIMessage(content=answer)]
        return {
            "answer": answer,
            "citations": citations,
            "messages": msgs,
            "verdict": "answered" if citations else state.get("verdict", "answered"),
            "steps": [{"node": "finalize", "title": f"输出 {len(citations)} 条引用", "detail": {}}],
        }

    async def node_no_answer(self, state: RAGState) -> dict[str, Any]:
        return {
            "answer": prompts.NO_ANSWER,
            "citations": [],
            "verdict": "no_answer",
            "messages": [HumanMessage(content=state["question"]),
                         AIMessage(content=prompts.NO_ANSWER)],
            "steps": [{"node": "no_answer", "title": "证据不足，拒答", "detail": {}}],
        }

    # --------------------------------------------------------------- edges
    def route_after_router(self, state: RAGState) -> str:
        if state.get("intent") == "chitchat" or not state.get("need_retrieval", True):
            return "chat"
        return "rewrite"

    def route_after_grade(self, state: RAGState) -> str:
        if state.get("relevant"):
            return "generate"
        if state.get("attempts", 0) < self.settings.max_retrieval_attempts:
            return "rewrite"
        return "no_answer"

    def route_after_verify(self, state: RAGState) -> str:
        if state.get("verdict") == "ungrounded" and state.get("gen_attempts", 1) <= 1:
            return "generate"
        return "finalize"

    # --------------------------------------------------------------- 流式
    async def astream(
        self,
        question: str,
        kbs: list[str] | None = None,
        session_id: str | None = None,
        sources: list[str] | None = None,
    ):
        """把图执行过程变成事件流，供 FastAPI SSE 直接转发。

        事件类型：step（节点进展）/ token（逐字输出）/ final（最终结果 + 引用）。
        """
        session_id = session_id or uuid.uuid4().hex
        inputs = {
            "question": question,
            "kbs": kbs or [],
            "sources": sources or [],
            "session_id": session_id,
            "started_at": time.time(),
            "messages": [],
        }
        config = {"configurable": {"thread_id": session_id}, "recursion_limit": 30}
        steps: list[dict[str, Any]] = []
        t0 = time.time()

        async for mode, chunk in self.graph.astream(
            inputs, config, stream_mode=["updates", "messages"]
        ):
            if mode == "messages":
                msg, meta = chunk
                node = (meta or {}).get("langgraph_node")
                if node in ("generate", "chat") and isinstance(msg.content, str) and msg.content:
                    yield {"type": "token", "text": msg.content}
                continue

            for node, update in (chunk or {}).items():
                if not isinstance(update, dict):
                    continue
                for step in update.get("steps", []) or []:
                    steps.append(step)
                    yield {"type": "step", **step}

        snapshot = await self.graph.aget_state(config)
        values = snapshot.values
        yield {
            "type": "final",
            "answer": values.get("answer", ""),
            "citations": values.get("citations", []),
            "session_id": session_id,
            "message_id": uuid.uuid4().hex[:12],
            "verdict": values.get("verdict", ""),
            "kbs": values.get("kbs", []),
            "steps": steps,
            "elapsed": round(time.time() - t0, 1),
            "mode": "graph",
        }
