"""依赖注入：所有组件单例，随进程存活。"""

from __future__ import annotations

from functools import lru_cache

from app.agent.graph import RAGAgent
from app.agent.react import ReActDocAgent
from app.kb import get_kb_manager
from app.retrieval.service import Retriever
from app.settings import get_settings


@lru_cache
def get_retriever() -> Retriever:
    return Retriever(get_kb_manager(), get_settings())


@lru_cache
def get_rag_agent() -> RAGAgent:
    return RAGAgent(get_retriever(), get_kb_manager(), get_settings())


@lru_cache
def get_react_agent() -> ReActDocAgent:
    return ReActDocAgent(get_retriever(), get_kb_manager(), get_settings())
