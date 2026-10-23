"""第二种 Agent 形态：ReAct（模型自己决定调哪个工具、调几次）。

和主图的关系：
- 主图 = 固定控制流（成本可预测、可控、易评估），适合线上问答；
- ReAct = 自主控制流（灵活，能自己换关键词多轮搜索），适合探索型问题。
面试里能讲清「什么时候用编排图、什么时候用自主 Agent」，比只会调 create_react_agent 值钱。
"""

from __future__ import annotations

import re
import time
import uuid
from typing import Any, AsyncIterator

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langgraph.checkpoint.memory import MemorySaver
from langgraph.prebuilt import create_react_agent

from app.agent import prompts
from app.agent.tools import build_tools
from app.core.llm import get_chat_model
from app.kb import KBManager
from app.retrieval.service import Retriever
from app.settings import Settings

# 工具返回的格式： [1] kb=langgraph | Checkpointer vs. store | path=... | doc_id=...
_HIT_RE = re.compile(r"^\[(\d+)\] kb=(\S+) \| (.+?) \| path=(\S+) \| doc_id=(\w+)", re.MULTILINE)


def _parse_citations(messages: list) -> list[dict]:
    """从工具返回文本里还原引用来源，让 ReAct 模式也能点开原文。"""
    seen: dict[str, dict] = {}
    for m in messages:
        if isinstance(m, ToolMessage) and m.name == "search_knowledge_base":
            content = str(m.content)
            for match in _HIT_RE.finditer(content):
                _, kb, title, path, doc_id = match.groups()
                key = f"{kb}:{path}:{title}"
                if key in seen:
                    continue
                start = match.end()
                snippet = content[start : start + 300].strip()
                seen[key] = {
                    "index": len(seen) + 1,
                    "chunk_id": "",
                    "kb": kb,
                    "title": title.strip(),
                    "path": path,
                    "source_url": "",
                    "snippet": snippet,
                }
    return list(seen.values())


class ReActDocAgent:
    def __init__(self, retriever: Retriever, manager: KBManager, settings: Settings) -> None:
        self.settings = settings
        self.tools = build_tools(retriever, manager)
        self.graph = create_react_agent(
            get_chat_model(),
            self.tools,
            prompt=prompts.REACT_SYSTEM,
            checkpointer=MemorySaver(),
        )

    async def astream(
        self, question: str, kbs: list[str] | None = None, session_id: str | None = None
    ) -> AsyncIterator[dict[str, Any]]:
        session_id = session_id or uuid.uuid4().hex
        hint = ""
        if kbs:
            hint = f"\n\n（提示：本次只应检索这些知识库：{', '.join(kbs)}，调用工具时请带上 kb 参数。）"
        config = {"configurable": {"thread_id": session_id}, "recursion_limit": 30}
        inputs = {"messages": [HumanMessage(content=question + hint)]}

        steps: list[dict] = []
        tool_calls = 0
        t0 = time.time()

        async for mode, chunk in self.graph.astream(
            inputs, config, stream_mode=["updates", "messages"]
        ):
            if mode == "messages":
                msg, meta = chunk
                if meta.get("langgraph_node") == "agent" and isinstance(msg.content, str) and msg.content:
                    yield {"type": "token", "text": msg.content}
                continue

            # updates: {node_name: {...}}
            for node, update in (chunk or {}).items():
                if not isinstance(update, dict):
                    continue
                for m in update.get("messages", []) or []:
                    if isinstance(m, AIMessage) and m.tool_calls:
                        for tc in m.tool_calls:
                            tool_calls += 1
                            step = {
                                "node": "tool_call",
                                "title": f"调用工具 {tc['name']}",
                                "detail": {"args": tc.get("args", {})},
                            }
                            steps.append(step)
                            yield {"type": "step", **step}
                    elif isinstance(m, ToolMessage):
                        step = {
                            "node": "tool_result",
                            "title": f"工具返回 {len(str(m.content))} 字符",
                            "detail": {"name": m.name, "preview": str(m.content)[:400]},
                        }
                        steps.append(step)
                        yield {"type": "step", **step}

        # 取最终状态
        snapshot = await self.graph.aget_state(config)
        messages = snapshot.values.get("messages", [])
        answer = ""
        for m in reversed(messages):
            if isinstance(m, AIMessage) and isinstance(m.content, str) and m.content.strip():
                answer = m.content
                break

        cites = _parse_citations(messages)
        yield {
            "type": "final",
            "answer": answer,
            "citations": cites,
            "session_id": session_id,
            "message_id": uuid.uuid4().hex[:12],
            "verdict": "answered" if answer else "no_answer",
            "tool_calls": tool_calls,
            "steps": steps,
            "elapsed": round(time.time() - t0, 1),
            "mode": "react",
        }
