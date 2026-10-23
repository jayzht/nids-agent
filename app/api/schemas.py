"""请求 / 响应模型。Pydantic v2 —— 本身就是知识库里的内容，顺便自证。"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=2000, description="用户问题")
    kb: str | None = Field(None, description="只检索单个知识库")
    kbs: list[str] | None = Field(None, description="检索多个知识库")
    session_id: str | None = Field(None, description="会话 id，用于多轮记忆")
    stream: bool = True
    mode: Literal["graph", "react"] = Field("graph", description="graph=可控 CRAG 流程，react=自主工具调用")


class Citation(BaseModel):
    index: int
    chunk_id: str
    kb: str
    title: str
    path: str
    source_url: str = ""
    snippet: str = ""


class ChatResponse(BaseModel):
    answer: str
    citations: list[Citation] = []
    session_id: str
    message_id: str
    verdict: str = "answered"
    kbs: list[str] = []
    steps: list[dict[str, Any]] = []
    elapsed: float = 0.0


class KBInfo(BaseModel):
    name: str
    title: str
    description: str = ""
    num_docs: int = 0
    num_chunks: int = 0
    embedding_model: str = ""
    updated_at: str = ""
    loaded: bool = False


class KBCreateRequest(BaseModel):
    name: str = Field(..., pattern=r"^[a-z0-9][a-z0-9_-]{1,30}$")
    title: str = ""
    description: str = ""
    # 方式一：data/raw/<name> 已经有语料
    # 方式二：给一个 git 仓库 + 文档子目录，后台自动拉取
    repo: str | None = None
    subdir: str | None = None
    url_template: str = ""


class FeedbackRequest(BaseModel):
    session_id: str
    message_id: str = ""
    rating: Literal["up", "down"]
    comment: str = ""
    question: str = ""
    answer: str = ""


class EvalRequest(BaseModel):
    kb: str | None = None
    mode: Literal["retrieval", "end2end"] = "retrieval"
    top_k: int = 6
