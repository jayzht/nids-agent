"""eve.json 增量消费测试：游标、半行、轮转、幂等。"""

from __future__ import annotations

import os

import pytest

from app.siem.store import AlertStore
from app.siem.tailer import EveTailer

ALERT = '{{"event_type":"alert","src_ip":"{}","alert":{{"signature":"r{}","severity":1}}}}\n'


@pytest.fixture()
def env(tmp_path):
    store = AlertStore(tmp_path / "t.db")
    return store, EveTailer(store), tmp_path / "eve.jsonl"


def write(path, *ips):
    path.write_text("".join(ALERT.format(ip, ip) for ip in ips), encoding="utf-8")


def append(path, ip):
    with path.open("a", encoding="utf-8") as f:
        f.write(ALERT.format(ip, ip))


def test_first_poll_reads_all(env):
    store, tailer, path = env
    write(path, "1.1.1.1", "2.2.2.2")
    r = tailer.poll(path)
    assert r["new_alerts"] == 2 and r["lines_read"] == 2
    assert store.total_alerts() == 2


def test_second_poll_is_idempotent(env):
    store, tailer, path = env
    write(path, "1.1.1.1")
    tailer.poll(path)
    r = tailer.poll(path)
    assert r["new_alerts"] == 0 and r["offset"] == path.stat().st_size
    assert store.total_alerts() == 1


def test_append_then_poll(env):
    store, tailer, path = env
    write(path, "1.1.1.1")
    tailer.poll(path)
    append(path, "3.3.3.3")
    r = tailer.poll(path)
    assert r["new_alerts"] == 1
    assert store.total_alerts() == 2


def test_partial_line_is_not_consumed(env):
    store, tailer, path = env
    line = ALERT.format("9.9.9.9", "9")
    path.write_text(line[:20], encoding="utf-8")     # 写了半行
    assert tailer.poll(path)["new_alerts"] == 0
    with path.open("a", encoding="utf-8") as f:      # 补完
        f.write(line[20:])
    assert tailer.poll(path)["new_alerts"] == 1


def test_truncation_resets_offset(env):
    store, tailer, path = env
    write(path, "1.1.1.1", "2.2.2.2", "3.3.3.3")
    tailer.poll(path)
    write(path, "4.4.4.4")                           # 文件被截断重写
    r = tailer.poll(path)
    assert r["reset"] is True and r["new_alerts"] == 1


def test_cursor_persists_across_instances(tmp_path):
    db = tmp_path / "c.db"
    path = tmp_path / "e.jsonl"
    write(path, "1.1.1.1")
    EveTailer(AlertStore(db)).poll(path)
    store2 = AlertStore(db)
    r = EveTailer(store2).poll(path)
    assert r["new_alerts"] == 0


def test_bad_json_lines_are_skipped(env):
    store, tailer, path = env
    path.write_text('not json\n{"event_type":"alert","src_ip":"1.1.1.1",'
                    '"alert":{"signature":"a","severity":1}}\n', encoding="utf-8")
    r = tailer.poll(path)
    assert r["lines_read"] == 2 and r["new_alerts"] == 1


def test_missing_file_returns_error(env):
    _, tailer, path = env
    assert "error" in tailer.poll(path)


def test_reset_rereads(env):
    store, tailer, path = env
    write(path, "1.1.1.1")
    tailer.poll(path)
    tailer.reset(path)
    assert tailer.poll(path)["new_alerts"] == 0      # 去重仍然拦住
    assert tailer.cursors()[0]["offset"] == path.stat().st_size


def test_cursor_inode_tracking(env):
    store, tailer, path = env
    write(path, "1.1.1.1")
    tailer.poll(path)
    c = tailer.cursors()[0]
    assert c["inode"] == os.stat(path).st_ino and c["lines"] == 1
