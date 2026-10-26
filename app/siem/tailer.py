"""eve.json 增量消费：文件偏移量游标 + 轮询。

为什么不能直接 `tail -f | 解析`：
- 进程重启后必须知道「读到哪了」，否则要么漏告警、要么重复灌；
- eve.json 是按行追加的，可能读到半行（写了但没写完），必须等换行再消费；
- 日志会轮转（rename / 截断），偏移量大于文件大小时要能自动重置。

游标存在 SQLite 的 cursors 表里（path / inode / offset / lines），
所以「重启继续读」和「检测轮转」都只是查表比较。
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path

from app.siem.store import AlertStore

logger = logging.getLogger(__name__)


class EveTailer:
    def __init__(self, store: AlertStore) -> None:
        self.store = store

    # ------------------------------------------------------------ 游标
    def cursor(self, path: Path) -> dict | None:
        with self.store._conn() as conn:  # noqa: SLF001 - 同模块族，共用连接配置
            row = conn.execute("SELECT * FROM cursors WHERE path = ?", (str(path),)).fetchone()
        return dict(row) if row else None

    def _save_cursor(self, path: Path, inode: int, offset: int, lines: int) -> None:
        with self.store._conn() as conn:  # noqa: SLF001
            conn.execute(
                """INSERT INTO cursors (path, inode, offset, lines, updated_at)
                   VALUES (?,?,?,?,?)
                   ON CONFLICT(path) DO UPDATE SET
                     inode=excluded.inode, offset=excluded.offset,
                     lines=excluded.lines, updated_at=excluded.updated_at""",
                (str(path), inode, offset, lines, time.time()),
            )

    def reset(self, path: Path) -> None:
        with self.store._conn() as conn:  # noqa: SLF001
            conn.execute("DELETE FROM cursors WHERE path = ?", (str(path),))

    def cursors(self) -> list[dict]:
        with self.store._conn() as conn:  # noqa: SLF001
            rows = conn.execute("SELECT * FROM cursors ORDER BY updated_at DESC").fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------ 消费
    def poll(self, path: Path, dedupe_window: float = 300.0) -> dict:
        path = path.resolve()
        if not path.exists():
            return {"error": f"文件不存在：{path}", "new_alerts": 0}

        stat = path.stat()
        cur = self.cursor(path)
        offset, lines, reset = 0, 0, False
        if cur:
            # inode 变了 = 轮转；文件变小 = 截断
            if cur["inode"] != stat.st_ino or stat.st_size < cur["offset"]:
                reset = True
            else:
                offset, lines = cur["offset"], cur["lines"]

        with path.open("rb") as fh:
            fh.seek(offset)
            chunk = fh.read()

        # 只消费完整行；最后一行没有换行说明还没写完，留到下次
        complete = chunk.rfind(b"\n")
        if complete == -1:
            consumed, payload = 0, b""
        else:
            consumed, payload = complete + 1, chunk[: complete + 1]

        texts = [ln for ln in payload.decode("utf-8", "replace").splitlines() if ln.strip()]
        from app.siem.parsers import parse_batch

        alerts = []
        for line in texts:
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        parsed = parse_batch(alerts) if alerts else []
        result = self.store.ingest(parsed, dedupe_window=dedupe_window) if parsed else {
            "received": 0, "accepted": 0, "duplicates": 0, "total": self.store.total_alerts()}

        new_offset = offset + consumed
        self._save_cursor(path, stat.st_ino, new_offset, lines + len(texts))
        return {
            "path": str(path),
            "reset": reset,
            "lines_read": len(texts),
            "new_alerts": result["accepted"],
            "duplicates": result["duplicates"],
            "offset": new_offset,
            "size": stat.st_size,
        }


async def watch(paths: list[str], store: AlertStore, interval: float = 5.0) -> None:
    """后台轮询：配置了 SIEM_TAIL_PATHS 时随服务启动。"""
    tailer = EveTailer(store)
    resolved = [Path(p).expanduser() for p in paths]
    logger.info("eve.json 增量消费启动：%s（每 %.0fs）", [str(p) for p in resolved], interval)
    while True:
        for p in resolved:
            try:
                res = tailer.poll(p)
                if res.get("new_alerts"):
                    logger.info("tail %s -> +%d 条告警", p, res["new_alerts"])
            except Exception as exc:  # noqa: BLE001
                logger.warning("tail %s 失败：%s", p, exc)
        await asyncio.sleep(interval)
