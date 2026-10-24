"""LangGraph 状态定义与提示词。

状态设计原则（面试会问）：
1. 只用可序列化结构（dict / 基础类型）—— 检查点要能存进 SQLite/Postgres；
2. 用 Annotated + reducer 表达「累加」语义（steps 只增不减），
   否则每个节点 return 会覆盖上一个节点的值；
3. 把「控制流用到的字段」（need_retrieval / attempts / verdict）显式放进 state，
   条件边就是纯函数 state -> 下一节点，可测试、可回放。
"""

from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict

from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages


class Step(TypedDict):
    node: str
    title: str
    detail: dict[str, Any]


class RAGState(TypedDict, total=False):
    # ---- 会话 ----
    session_id: str
    messages: Annotated[list[AnyMessage], add_messages]
    question: str
    history: str

    # ---- 路由 ----
    kbs: list[str]
    sources: list[str]              # KB 内的来源子集（如 ids 下的 suricata / zeek / rfc / papers）
    need_retrieval: bool
    intent: str

    # ---- 检索 ----
    queries: list[str]
    candidates: list[dict[str, Any]]   # 序列化后的候选片段
    relevant: list[dict[str, Any]]

    # ---- 生成 ----
    context: str
    answer: str
    citations: list[dict[str, Any]]

    # ---- 控制 ----
    attempts: int
    verdict: str                       # answered | no_answer | ungrounded
    steps: Annotated[list[Step], operator.add]
    started_at: float
