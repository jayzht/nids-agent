"""全局配置：全部通过环境变量 / .env 覆盖，不写死任何密钥。"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ---------- 目录 ----------
    data_dir: Path = BASE_DIR / "data"
    raw_dir: Path = BASE_DIR / "data" / "raw"
    index_dir: Path = BASE_DIR / "data" / "index"
    pcaps_dir: Path = BASE_DIR / "data" / "pcaps"
    siem_db: Path = BASE_DIR / "data" / "siem.db"

    # ---------- LLM（OpenAI 兼容协议：Ollama / DeepSeek / 通义 / vLLM 都能接） ----------
    llm_base_url: str = "http://127.0.0.1:11434/v1"
    llm_api_key: str = "ollama"
    llm_model: str = "qwen3:8b"
    llm_temperature: float = 0.1
    llm_timeout: float = 180.0
    # 便宜的小模型可以单独指定，用于打分/改写等高频调用
    llm_fast_model: str = ""

    # ---------- Embedding ----------
    embedding_base_url: str = "http://127.0.0.1:11434/v1"
    embedding_api_key: str = "ollama"
    embedding_model: str = "bge-m3"  # 多语言，中文问英文文档也能召回
    embedding_batch_size: int = 32
    embedding_dim: int = 0  # 0 = 首次调用时自动探测

    # ---------- 检索 ----------
    top_k: int = 6                 # 最终喂给 LLM 的片段数
    candidate_k: int = 40          # 混合检索的候选池大小
    bm25_weight: float = 0.2       # 稠密/稀疏融合权重（用 scripts/sweep.py 定出来的）
    fusion: str = "normalized"     # rrf | normalized
    rrf_k: int = 60                # RRF 平滑常数
    rerank_mode: str = "none"      # none | lexical | llm
    rerank_top_n: int = 12

    # ---------- 分块 ----------
    chunk_tokens: int = 420
    chunk_overlap_tokens: int = 60

    # ---------- Agent ----------
    max_retrieval_attempts: int = 2   # 检索不到时改写查询重试次数
    max_context_chars: int = 12000
    history_turns: int = 4

    # ---------- 服务 ----------
    host: str = "0.0.0.0"
    port: int = 8000
    cors_origins: list[str] = Field(default_factory=lambda: ["*"])
    log_level: str = "INFO"

    # ---------- 可选：Qdrant ----------
    vector_backend: str = "numpy"          # numpy | qdrant
    qdrant_url: str = "http://127.0.0.1:6333"
    qdrant_api_key: str = ""

    @property
    def kb_root(self) -> Path:
        return self.index_dir

    def ensure_dirs(self) -> None:
        for p in (self.raw_dir, self.index_dir, self.pcaps_dir):
            p.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    s.ensure_dirs()
    return s
