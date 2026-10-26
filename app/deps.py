"""依赖注入：所有组件单例，随进程存活。"""

from __future__ import annotations

from functools import lru_cache

from app.agent.graph import RAGAgent
from app.agent.fusion_graph import FusionAgent
from app.agent.traffic_graph import TrafficAgent
from app.agent.react import ReActDocAgent
from app.kb import get_kb_manager
from app.retrieval.service import Retriever
from app.settings import get_settings
from app.siem.store import AlertStore
from app.siem.tailer import EveTailer
from app.traffic.tools import TrafficService


@lru_cache
def get_retriever() -> Retriever:
    return Retriever(get_kb_manager(), get_settings())


@lru_cache
def get_rag_agent() -> RAGAgent:
    return RAGAgent(get_retriever(), get_kb_manager(), get_settings())


@lru_cache
def get_react_agent() -> ReActDocAgent:
    return ReActDocAgent(get_retriever(), get_kb_manager(), get_settings())


@lru_cache
def get_traffic_service() -> TrafficService:
    return TrafficService(get_settings().pcaps_dir)


@lru_cache
def get_traffic_agent() -> TrafficAgent:
    return TrafficAgent(get_traffic_service(), get_retriever(), get_settings())


@lru_cache
def get_fusion_agent() -> FusionAgent:
    return FusionAgent(get_traffic_service(), get_retriever(), get_settings())


@lru_cache
def get_siem_store() -> AlertStore:
    return AlertStore(get_settings().siem_db)


@lru_cache
def get_eve_tailer() -> EveTailer:
    return EveTailer(get_siem_store())
