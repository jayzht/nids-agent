"""LLM / Embedding 客户端封装。

设计要点：
1. 统一走 OpenAI 兼容协议 —— 换 Ollama / DeepSeek / 通义 / vLLM 只改环境变量。
2. 生成用 langchain 的 ChatOpenAI（能直接被 LangGraph 消费，支持 tool calling / 流式）。
3. 向量化自己写 httpx 客户端：批量、限流、重试、L2 归一化、按内容哈希做缓存。
   归一化之后余弦相似度 == 点积，检索端可以纯矩阵乘法。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from functools import lru_cache
from typing import Any, Sequence

import httpx
import numpy as np
from langchain_openai import ChatOpenAI

from app.settings import Settings, get_settings

logger = logging.getLogger(__name__)

# Qwen3 系列默认会输出  thinking 块，加这个软开关能显著降低延迟
_NO_THINK = "/no_think"


@lru_cache
def get_chat_model(
    model: str | None = None,
    temperature: float | None = None,
    streaming: bool = True,
    json_mode: bool = False,
) -> ChatOpenAI:
    s = get_settings()
    kwargs: dict[str, Any] = {}
    if json_mode:
        # Ollama 支持 response_format={"type":"json_object"}
        kwargs["model_kwargs"] = {"response_format": {"type": "json_object"}}
    return ChatOpenAI(
        model=model or s.llm_model,
        base_url=s.llm_base_url,
        api_key=s.llm_api_key,
        temperature=s.llm_temperature if temperature is None else temperature,
        timeout=s.llm_timeout,
        streaming=streaming,
        max_retries=2,
        **kwargs,
    )


@lru_cache
def get_fast_chat_model(json_mode: bool = False) -> ChatOpenAI:
    s = get_settings()
    return get_chat_model(model=s.llm_fast_model or s.llm_model, temperature=0.0, json_mode=json_mode)


def with_no_think(system_prompt: str) -> str:
    return f"{system_prompt}\n{_NO_THINK}"


class EmbeddingClient:
    """OpenAI 兼容 /v1/embeddings 的批量客户端。"""

    def __init__(self, settings: Settings | None = None) -> None:
        s = settings or get_settings()
        self.base_url = s.embedding_base_url.rstrip("/")
        self.api_key = s.embedding_api_key
        self.model = s.embedding_model
        self.batch_size = max(1, s.embedding_batch_size)
        self.timeout = s.llm_timeout
        self._dim = s.embedding_dim or 0
        self._cache: dict[str, np.ndarray] = {}

    @property
    def dim(self) -> int:
        return self._dim

    async def _post(self, client: httpx.AsyncClient, batch: list[str]) -> list[list[float]]:
        last_err: Exception | None = None
        for attempt in range(3):
            try:
                resp = await client.post(
                    f"{self.base_url}/embeddings",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    json={"model": self.model, "input": batch},
                )
                resp.raise_for_status()
                data = resp.json()["data"]
                data = sorted(data, key=lambda d: d.get("index", 0))
                return [d["embedding"] for d in data]
            except Exception as exc:  # noqa: BLE001
                last_err = exc
                await asyncio.sleep(0.8 * (attempt + 1))
        raise RuntimeError(f"embedding failed after retries: {last_err}")

    async def embed(self, texts: Sequence[str], progress: Any = None) -> np.ndarray:
        """返回 (n, dim) 的 float32 归一化矩阵。"""
        if not texts:
            return np.zeros((0, self._dim or 1), dtype=np.float32)

        keys = [hashlib.sha1(t.encode("utf-8")).hexdigest() for t in texts]
        todo = [(k, t) for k, t in zip(keys, texts) if k not in self._cache]
        if todo:
            sem = asyncio.Semaphore(4)
            lock = asyncio.Lock()
            state = {"done": 0}

            async with httpx.AsyncClient(timeout=self.timeout) as client:

                async def run(chunk: list[tuple[str, str]]) -> None:
                    async with sem:
                        vecs = await self._post(client, [t for _, t in chunk])
                        for (k, _), v in zip(chunk, vecs):
                            arr = np.asarray(v, dtype=np.float32)
                            if self._dim and len(arr) != self._dim:
                                raise ValueError(
                                    f"embedding dim mismatch: expect {self._dim}, got {len(arr)}"
                                )
                            self._cache[k] = _l2_normalize(arr)
                        async with lock:
                            state["done"] += len(chunk)
                            if progress is not None:
                                progress(state["done"], len(todo))

                chunks = [todo[i : i + self.batch_size] for i in range(0, len(todo), self.batch_size)]
                await asyncio.gather(*(run(c) for c in chunks))

        if self._dim == 0:
            self._dim = len(next(iter(self._cache.values())))
        return np.vstack([self._cache[k] for k in keys])

    async def embed_query(self, text: str) -> np.ndarray:
        return (await self.embed([text]))[0]


def _l2_normalize(v: np.ndarray) -> np.ndarray:
    n = float(np.linalg.norm(v))
    return v / n if n > 1e-12 else v


@lru_cache
def get_embedder() -> EmbeddingClient:
    return EmbeddingClient()


async def complete_json(
    prompt: str, system: str = "", model: str | None = None, fallback: Any = None
) -> Any:
    """调用 LLM 并尽量解析出 JSON；失败返回 fallback，保证流水线不中断。"""
    llm = get_chat_model(model=model, temperature=0.0, streaming=False, json_mode=True)
    msgs = []
    if system:
        msgs.append(("system", with_no_think(system)))
    msgs.append(("human", prompt))
    try:
        resp = await llm.ainvoke(msgs)
        return parse_json(resp.content if isinstance(resp.content, str) else str(resp.content))
    except Exception as exc:  # noqa: BLE001
        logger.warning("complete_json failed: %s", exc)
        return fallback


def parse_json(text: str) -> Any:
    """容忍 ```json 包裹、前后废话的 JSON 解析。"""
    text = text.strip()
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.lower().startswith("json"):
            text = text[4:]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                pass
    return None


async def ainvoke_text(messages, model: str | None = None) -> str:
    """调用 LLM 并返回文本。

    有些 OpenAI 兼容网关会忽略 `stream: true` 直接返回完整 JSON
    （例如轻量代理/自研网关），LangChain 的流式解析器会抛
    `ValueError: No generations found in stream`。
    这种情况自动回退到非流式，保证接口可用——只是前端拿不到逐字输出。
    """
    llm = get_chat_model(model=model, streaming=True)
    try:
        resp = await llm.ainvoke(messages)
    except ValueError as exc:
        if "No generations found in stream" not in str(exc):
            raise
        logger.warning("后端返回了非流式响应，回退到非流式调用")
        resp = await get_chat_model(model=model, streaming=False).ainvoke(messages)
    return resp.content if isinstance(resp.content, str) else str(resp.content)
