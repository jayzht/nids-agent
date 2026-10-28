"""检查点持久化：服务重启后多轮记忆不丢。

之前四个图都用 `MemorySaver`，状态只在进程内存里：重启服务，同一个
`session_id` 的追问就失忆，且没有 TTL。这里验证换成 SQLite 之后，
「新进程（新 saver 实例）读旧文件」依然能拿到历史。
"""

from __future__ import annotations

from langgraph.checkpoint.memory import MemorySaver

from app.agent import checkpointer


async def test_falls_back_to_memory_when_not_setup():
    await checkpointer.close()
    assert isinstance(checkpointer.get_checkpointer(), MemorySaver)


async def test_state_survives_new_saver_instance(tmp_path, monkeypatch):
    """写入 -> 关闭 -> 用同一文件重新打开，历史仍在（模拟服务重启）。"""
    from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
    from langgraph.graph import END, START, StateGraph

    db = tmp_path / "cp.sqlite"

    class S(dict):
        pass

    def build(saver):
        g = StateGraph(dict)
        g.add_node("bump", lambda st: {"n": st.get("n", 0) + 1})
        g.add_edge(START, "bump")
        g.add_edge("bump", END)
        return g.compile(checkpointer=saver)

    cfg = {"configurable": {"thread_id": "t-1"}}

    # ---- 第一次「运行」：写两条检查点
    async with AsyncSqliteSaver.from_conn_string(str(db)) as saver1:
        await saver1.setup()
        g1 = build(saver1)
        await g1.ainvoke({"n": 0}, cfg)
        await g1.ainvoke({"n": 10}, cfg)
        snap1 = await g1.aget_state(cfg)
        assert snap1.values["n"] == 11

    # ---- 重启：换一个新 saver 实例，只靠文件恢复
    async with AsyncSqliteSaver.from_conn_string(str(db)) as saver2:
        await saver2.setup()
        g2 = build(saver2)
        snap2 = await g2.aget_state(cfg)
        assert snap2.values["n"] == 11, "重启后应能读到上一次的状态"
        # 接着跑，是从 11 继续，而不是从 0
        await g2.ainvoke({"n": snap2.values["n"]}, cfg)
        snap3 = await g2.aget_state(cfg)
        assert snap3.values["n"] == 12


async def test_setup_uses_settings_path(tmp_path):
    from app.settings import Settings

    s = Settings(checkpoint_db=tmp_path / "sub" / "cp.sqlite")
    await checkpointer.close()
    saver = await checkpointer.setup(s)
    assert not isinstance(saver, MemorySaver)
    assert (tmp_path / "sub" / "cp.sqlite").exists()
    assert checkpointer.get_checkpointer() is saver
    await checkpointer.close()
    assert isinstance(checkpointer.get_checkpointer(), MemorySaver)


async def test_memory_backend_keeps_old_behaviour(tmp_path):
    from app.settings import Settings

    await checkpointer.close()
    s = Settings(checkpoint_backend="memory", checkpoint_db=tmp_path / "x.sqlite")
    saver = await checkpointer.setup(s)
    assert isinstance(saver, MemorySaver)
    assert not (tmp_path / "x.sqlite").exists()


async def test_uuid6_helpers_are_time_sorted():
    import time

    import pytest

    from app.agent.checkpointer import uuid6_id, uuid6_time

    now = time.time()
    a, b = uuid6_id(now - 60), uuid6_id(now)
    assert a < b, "UUIDv6 字典序必须等于时间序（清理用的就是字符串比较）"
    assert uuid6_time(b) == pytest.approx(now, abs=1e-3)


async def test_prune_drops_idle_threads(tmp_path):
    """保留期到了就删；界限之内的会话不能误删。"""
    import asyncio

    from app.agent import checkpointer as cp
    from app.settings import Settings

    await cp.close()
    s = Settings(checkpoint_db=tmp_path / "cp.sqlite", checkpoint_retention_days=0)
    await cp.setup(s)  # retention=0 表示启动时不清理

    from langgraph.graph import END, START, StateGraph

    g = StateGraph(dict)
    g.add_node("n", lambda st: {"n": 1})
    g.add_edge(START, "n")
    g.add_edge("n", END)
    graph = g.compile(checkpointer=cp.get_checkpointer())
    await graph.ainvoke({}, {"configurable": {"thread_id": "idle"}})

    assert await cp.prune(0) == 0, "retention<=0 不应清理"
    await asyncio.sleep(1.1)
    assert await cp.prune(1 / 86400) == 1, "1 秒保留期应清掉刚写的会话"
    rows = (await (await cp.get_checkpointer().conn.execute(
        "SELECT COUNT(*) FROM checkpoints")).fetchone())[0]
    assert rows == 0
    await cp.close()
