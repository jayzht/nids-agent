"""pcap 读取层：一切事实来自 tshark 的结构化输出，Python 只做聚合。

为什么不自己解析 pcap：
- 协议解析（尤其 TLS/JA3、DNS 压缩指针）极容易出错，tshark 是 20 年的累积；
- `-T fields` 输出稳定、可测试，比 pyshark 的对象树更适合做批处理；
- 保留 tshark 让"确定性证据"这条线永远可用，模型挂了也能出报告。

没有 tshark 时优雅降级：只做 pcap 文件头解析（包数/时间范围），分析能力降级但不崩。
"""

from __future__ import annotations

import json
import shutil
import struct
import subprocess
from pathlib import Path

from app.traffic.models import Packet

TSHARK = shutil.which("tshark")

# 一次抓全需要的字段，避免多次遍历文件
MAIN_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "ip.src",
    "ip.dst",
    "ip.proto",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags",
    "udp.srcport",
    "udp.dstport",
    "_ws.col.Protocol",
    "_ws.col.Info",
]

DNS_FIELDS = ["frame.number", "dns.qry.name", "dns.flags.response", "dns.flags.rcode",
              "ip.src", "ip.dst"]
HTTP_FIELDS = [
    "frame.number",
    "http.request.method",
    "http.host",
    "http.request.uri",
    "http.user_agent",
]
TLS_FIELDS = ["frame.number", "tls.handshake.extensions_server_name"]


class TsharkUnavailable(RuntimeError):
    pass


def tshark_available() -> bool:
    return TSHARK is not None


def _run(cmd: list[str], timeout: float = 120.0) -> str:
    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=timeout,
            # 真实流量里常有不规范字节，不能让解码失败把整份分析炸掉
            encoding="utf-8", errors="replace",
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"tshark 超时（{timeout}s）：{' '.join(cmd[:4])}") from exc
    if proc.returncode != 0:
        raise RuntimeError(f"tshark 失败：{proc.stderr.strip()[:300]}")
    return proc.stdout


def read_fields(
    path: Path, fields: list[str], display_filter: str | None = None, limit: int | None = None
) -> list[list[str]]:
    if not TSHARK:
        raise TsharkUnavailable("未安装 tshark（apt install tshark）")
    cmd = [
        TSHARK, "-r", str(path), "-T", "fields",
        "-E", "separator=\t", "-E", "occurrence=f", "-E", "quote=n",
    ]
    for f in fields:
        cmd += ["-e", f]
    if display_filter:
        cmd += ["-Y", display_filter]
    if limit:
        cmd += ["-c", str(limit)]
    out = _run(cmd)
    rows: list[list[str]] = []
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < len(fields):          # tshark 会省略尾部空字段
            parts += [""] * (len(fields) - len(parts))
        rows.append([p.strip() for p in parts[: len(fields)]])
    return rows


def _flag_name(hex_flags: str) -> str:
    """把 tshark 的 0x0012 转成 SYN/ACK 之类的可读标记。"""
    try:
        v = int(hex_flags, 16)
    except (TypeError, ValueError):
        return ""
    names = []
    for bit, name in ((0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
                      (0x10, "ACK"), (0x20, "URG")):
        if v & bit:
            names.append(name)
    return ",".join(names)


def read_packets(path: Path) -> list[Packet]:
    rows = read_fields(path, MAIN_FIELDS)
    pkts: list[Packet] = []
    for r in rows:
        no, ts, length, src, dst, _ipproto, tsrc, tdst, flags, usrc, udst, proto, info = r
        try:
            no_i = int(no)
        except ValueError:
            continue
        pkts.append(
            Packet(
                no=no_i,
                ts=float(ts or 0.0),
                length=int(length or 0),
                src=src,
                dst=dst,
                sport=int(tsrc or usrc or 0),
                dport=int(tdst or udst or 0),
                proto=proto or "?",
                flags=_flag_name(flags),
                info=(info or "").replace("\t", " ")[:200],
            )
        )
    return pkts


def read_dns(path: Path) -> list[dict]:
    rows = read_fields(path, DNS_FIELDS, display_filter="dns")
    out = []
    for no, name, is_resp, rcode, src, dst in rows:
        if not name:
            continue
        out.append(
            {
                "no": int(no),
                "name": name,
                "response": (is_resp or "").strip() in {"1", "True", "true"},
                "rcode": rcode or "0",
                "src": src,
                "dst": dst,
            }
        )
    return out


def read_http_bodies(path: Path, limit: int = 60, max_bytes: int = 4096) -> dict[int, str]:
    """按帧号取 HTTP 请求体（只读前 max_bytes，最多 limit 条）。

    为什么单独走 `-T json`：`-T fields` 是按行解析的，而请求体里常有换行
    （SOAP/XML 一换行，后面的字段就全部错位）。JSON 输出不受影响。
    取不到就返回空 dict —— 载荷检测是加分项，不能让它拖垮整条链路。
    """
    cmd = [TSHARK, "-r", str(path), "-T", "json", "-Y", "http.request"]
    if limit:
        cmd += ["-c", str(limit)]
    try:
        rows = json.loads(_run(cmd) or "[]")
    except Exception:  # noqa: BLE001
        return {}
    out: dict[int, str] = {}
    for row in rows:
        layers = (((row or {}).get("_source") or {}).get("layers") or {})
        frame = layers.get("frame") or {}
        body = (layers.get("http") or {}).get("http.file_data")
        if isinstance(body, dict):          # 多段 body 时 tshark 给的是对象
            body = " ".join(str(v) for v in body.values())
        if not body:
            continue
        try:
            no = int(frame.get("frame.number", 0))
        except (TypeError, ValueError):
            continue
        text = str(body)
        out[no] = text[:max_bytes]
    return out


def read_http(path: Path) -> list[dict]:
    rows = read_fields(path, HTTP_FIELDS, display_filter="http.request")
    out = []
    for no, method, host, uri, ua in rows:
        out.append(
            {
                "no": int(no),
                "method": method,
                "host": host,
                "uri": uri,
                "ua": ua,
            }
        )
    return out


def read_tls_sni(path: Path) -> list[dict]:
    try:
        rows = read_fields(path, TLS_FIELDS, display_filter="tls.handshake.type==1")
    except RuntimeError:
        return []
    return [{"no": int(no), "sni": sni} for no, sni in rows if sni]


def read_cleartext_http(path: Path) -> list[dict]:
    """抓非标准端口上的明文 HTTP（tshark 不会把它当 HTTP 解析，只能看 payload）。"""
    import re

    try:
        rows = read_fields(
            path, ["frame.number", "tcp.dstport", "tcp.payload"],
            display_filter='tcp contains "User-Agent"'
        )
    except RuntimeError:
        return []
    out = []
    for no, dport, hex_payload in rows:
        raw_hex = (hex_payload or "").replace(":", "").replace(" ", "")
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError:
            continue
        text = raw.decode("latin-1", "ignore")
        ua = re.search(r"User-Agent:\s*([^\r\n]+)", text)
        host = re.search(r"Host:\s*([^\r\n]+)", text)
        req = re.match(r"([A-Z]+)\s+(\S+)\s+HTTP/", text)
        out.append(
            {
                "no": int(no),
                "dport": int(dport or 0),
                "ua": ua.group(1).strip() if ua else "",
                "host": host.group(1).strip() if host else "",
                "method": req.group(1) if req else "",
                "uri": req.group(2) if req else "",
            }
        )
    return out


def find_pcaps(root: Path) -> list[dict]:
    """列出可用流量文件（含 samples 目录）。"""
    items = []
    for p in sorted(root.rglob("*")):
        if p.suffix.lower() not in {".pcap", ".pcapng", ".cap"}:
            continue
        items.append(
            {
                "name": p.name,
                "rel": str(p.relative_to(root)).replace("\\", "/"),
                "size": p.stat().st_size,
            }
        )
    return items


def _pcap_header_stats(path: Path) -> tuple[int, float, float]:
    """没有 tshark 时的兜底：只读 pcap 全局头 + 第一条记录的秒级时间。"""
    try:
        with path.open("rb") as fh:
            head = fh.read(24)
            if len(head) < 24:
                return 0, 0.0, 0.0
            magic = struct.unpack("<I", head[:4])[0]
            big = magic in (0xA1B2C3D4, 0xA1B23C4D)
            endian = ">" if big else "<"
            rec = fh.read(16)
            ts = 0.0
            if len(rec) == 16:
                sec = struct.unpack(endian + "I", rec[:4])[0]
                ts = float(sec)
            return 0, ts, ts
    except OSError:
        return 0, 0.0, 0.0
