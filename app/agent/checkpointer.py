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
        await prune(s.checkpoint_retention_days)
        return saver
    except Exception as exc:  # noqa: BLE001
        logger.warning("检查点初始化失败，退回内存：%s", exc)
        await close()
        return MemorySaver()


# ---- 保留期：会话多了检查点只涨不落，按 thread 的最后活跃时间清理 ----
# LangGraph 的 checkpoint_id 是 UUIDv6（时间有序），前 60 bit 就是时间戳，
# 所以可以直接在 SQL 里比较字符串，不用额外加时间列。
_EPOCH_OFFSET = 12219292800.0  # UUIDv6 起算点(1582-10-15) 到 Unix epoch 的秒数


def uuid6_time(checkpoint_id: str) -> float:
    """UUIDv6 -> Unix 时间戳（秒）。"""
    h = checkpoint_id.replace("-", "")
    ticks = (int(h[0:8], 16) << 28) | (int(h[8:12], 16) << 12) | int(h[13:16], 16)
    return ticks / 1e7 - _EPOCH_OFFSET


def uuid6_id(unix_ts: float) -> str:
    """Unix 时间戳 -> UUIDv6 字符串（用于生成清理阈值）。"""
    ticks = int((unix_ts + _EPOCH_OFFSET) * 1e7)
    high = (ticks >> 28) & 0xFFFFFFFF
    mid = (ticks >> 12) & 0xFFFF
    low = ticks & 0xFFF
    return f"{high:08x}-{mid:04x}-6{low:03x}-8000-000000000000"


async def prune(retention_days: float, now: float | None = None) -> int:
    """删掉最后活跃时间早于保留期的会话，返回删除的 thread 数。"""
    if retention_days <= 0 or _saver is None:
        return 0
    import time as _time

    cutoff = uuid6_id((now or _time.time()) - retention_days * 86400)
    conn = getattr(_saver, "conn", None)
    if conn is None:
        return 0
    stale = [
        row[0]
        for row in await (await conn.execute(
            "SELECT thread_id FROM checkpoints GROUP BY thread_id HAVING MAX(checkpoint_id) < ?",
            (cutoff,),
        )).fetchall()
    ]
    for thread_id in stale:
        for table in ("writes", "checkpoints"):
            try:
                await conn.execute(f"DELETE FROM {table} WHERE thread_id = ?", (thread_id,))
            except Exception as exc:  # noqa: BLE001
                logger.debug("清理 %s.%s 失败：%s", table, thread_id, exc)
    await conn.commit()
    if stale:
        logger.info("清理过期检查点：%d 个会话（保留 %.0f 天）", len(stale), retention_days)
    return len(stale)


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
