"""LangGraph 检查点：默认持久化到 SQLite。

为什么需要：`MemorySaver` 把多轮状态放在进程内存里，服务一重启，同一个
`session_id` 的追问就「失忆」；而且没有 TTL，长期运行的进程内存只涨不落。

设计上区分两种场景：
- **服务**：`app.main.lifespan` 在启动时 `await setup()`，四个图共享同一个
  `AsyncSqliteSaver`，状态落到 `data/checkpoints.sqlite`，重启后能接着聊。
- **脚本 / 测试**：没初始化就退回 `MemorySaver`，不产生文件、不依赖事件循环，
  所以 `scripts/` 和单测行为的改动面为零。

注意必须用 `AsyncSqliteSaver`：四个图都是 `astream` / `aget_state` 调用的，
同步的 `SqliteSaver` 在异步图里不可用。
"""

from __future__ import annotations

import logging
from typing import Any

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.memory import MemorySaver

from app.settings import Settings, get_settings

logger = logging.getLogger("devrag.checkpoint")

_saver: BaseCheckpointSaver | None = None
_conn_ctx: Any = None


async def setup(settings: Settings | None = None) -> BaseCheckpointSaver:
    """初始化持久化检查点；失败时退回内存，不阻塞启动。"""
    global _saver, _conn_ctx

    s = settings or get_settings()
    if _saver is not None:
        return _saver

    if s.checkpoint_backend != "sqlite":
        logger.info("检查点后端=%s（进程重启后多轮记忆不保留）", s.checkpoint_backend)
        return MemorySaver()

    try:
        from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

        path = s.checkpoint_db
        path.parent.mkdir(parents=True, exist_ok=True)
        _conn_ctx = AsyncSqliteSaver.from_conn_string(str(path))
        saver = await _conn_ctx.__aenter__()
        await saver.setup()
        _saver = saver
        logger.info("检查点：%s", path)
        return saver
    except Exception as exc:  # noqa: BLE001
        logger.warning("检查点初始化失败，退回内存：%s", exc)
        await close()
        return MemorySaver()


async def close() -> None:
    global _saver, _conn_ctx
    ctx, _conn_ctx = _conn_ctx, None
    _saver = None
    if ctx is not None:
        try:
            await ctx.__aexit__(None, None, None)
        except Exception as exc:  # noqa: BLE001
            logger.debug("关闭检查点连接失败：%s", exc)


def get_checkpointer() -> BaseCheckpointSaver:
    """图编译时取检查点；服务未初始化时退回内存。"""
    return _saver if _saver is not None else MemorySaver()
