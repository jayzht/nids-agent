#!/usr/bin/env python3
"""生成一份「自建 TLS C2」标注抓包，用来验证 JA3 / 无 SNI / 周期性检测。

为什么自建：手头所有带标注数据集里都没有 TLS C2——Hancitor 那个样本
一个 ClientHello 都没有（经代理采集），IoT-23 三个场景也全是裸 TCP/UDP。
不造一份可控的样本，TLS 检测只能靠猜。

它长什么样（一条连一条地模拟真实 C2 的心跳）：
- C2 客户端（源地址 127.0.0.2）：每隔 5s±1.2s 连一次 TLS 服务端，
  **不带 SNI**，发 48 字节心跳、收 32 字节、关连接（典型 sleep/jitter 心跳）；
- 正常客户端（源地址 127.0.0.3）：带 SNI 的短连接 + 一个非标准端口(9443)的长连接，
  用来验证「不能把所有 TLS 都当 C2」。

抓包方式：本机没有 CAP_NET_RAW，所以起一个容器共享 host 网络命名空间跑 tcpdump
（`--net=host --cap-add=NET_RAW`），只抓这两个端口的流量。

产物：
- `<out>.pcap`            抓包
- `<out>.flows.csv`       逐流标注（src,sport,dst,dport,ts,label），喂给 eval_labeled.py

用法：
    python scripts/make_tls_c2_pcap.py --beacons 12
    python scripts/eval_labeled.py --dir data/labeled/tls-c2 --scenario c2-lab
"""

from __future__ import annotations

import argparse
import random
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / "data" / ".cache" / "tls-lab"
C2_PORT = 8443
BENIGN_PORT = 8443
BENIGN_ALT_PORT = 9443
SNI = "update-check.example.local"


def log(msg: str) -> None:
    print(msg, flush=True)


def ensure_cert() -> tuple[Path, Path]:
    CACHE.mkdir(parents=True, exist_ok=True)
    cert, key = CACHE / "cert.pem", CACHE / "key.pem"
    if not (cert.exists() and key.exists()):
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(key), "-out", str(cert), "-days", "2",
             "-subj", f"/CN={SNI}"],
            check=True, capture_output=True,
        )
        log(f"生成自签证书：{cert.name}")
    return cert, key


class TLSServer(threading.Thread):
    """收一条连接、读一点数据、回一点数据就关——模拟 C2 服务端的应答。"""

    def __init__(self, port: int, cert: Path, key: Path) -> None:
        super().__init__(daemon=True)
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert, key)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(64)
        self.port = port
        self.stop = False

    def run(self) -> None:
        while not self.stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        try:
            with self.ctx.wrap_socket(conn, server_side=True) as tls:
                tls.settimeout(3)
                tls.recv(512)
                tls.sendall(b"ACK" + b"\x00" * 29)
        except Exception:  # noqa: BLE001
            pass

    def close(self) -> None:
        self.stop = True
        try:
            self.sock.close()
        except OSError:
            pass


def beacon(src_ip: str, port: int, with_sni: bool, payload: int, label: str,
           rows: list[dict]) -> None:
    """发一次 TLS 连接并记录五元组，供后面写标注。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((src_ip, 0))
    sport = sock.getsockname()[1]
    ts = time.time()
    try:
        sock.settimeout(5)
        sock.connect(("127.0.0.1", port))
        with ctx.wrap_socket(sock, server_hostname=SNI if with_sni else None) as tls:
            tls.sendall(b"\x00" * payload)
            try:
                tls.recv(256)
            except (TimeoutError, ssl.SSLError):
                pass
    except Exception as exc:  # noqa: BLE001
        log(f"  连接失败（{src_ip}→{port}）：{exc}")
    finally:
        try:
            sock.close()
        except OSError:
            pass
    rows.append({"src": src_ip, "sport": sport, "dst": "127.0.0.1", "dport": port,
                 "ts": f"{ts:.6f}", "label": label})


def start_capture(out: Path) -> subprocess.Popen:
    out.parent.mkdir(parents=True, exist_ok=True)
    rel = out.resolve().relative_to(ROOT)
    data_dir = ROOT / "data"
    inside = "/data/" + rel.relative_to("data").as_posix()
    cmd = [
        "docker", "run", "--rm", "--net=host", "--cap-add=NET_RAW",
        "-v", f"{data_dir}:/data", "alpine:latest", "sh", "-c",
        "apk add --no-cache tcpdump >/dev/null 2>&1; "
        f"exec tcpdump -i lo -s 0 -U -w {inside} 'tcp port {C2_PORT} or tcp port {BENIGN_ALT_PORT}'",
    ]
    log("启动抓包容器（host 网络 + NET_RAW）…")
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/labeled/tls-c2/c2-lab.pcap")
    ap.add_argument("--beacons", type=int, default=12)
    ap.add_argument("--interval", type=float, default=5.0)
    ap.add_argument("--jitter", type=float, default=1.2)
    args = ap.parse_args()

    out = (ROOT / args.out).resolve()
    cert, key = ensure_cert()

    servers = [TLSServer(C2_PORT, cert, key)]
    servers.append(TLSServer(BENIGN_ALT_PORT, cert, key))
    for s in servers:
        s.start()

    cap = start_capture(out)
    time.sleep(6)          # 等容器里 apk 装完 tcpdump 并开始抓包

    rows: list[dict] = []
    log(f"C2 心跳：{args.beacons} 次，间隔 {args.interval}s ± {args.jitter}s，无 SNI")
    for i in range(args.beacons):
        beacon("127.0.0.2", C2_PORT, with_sni=False, payload=48, label="malicious-c2", rows=rows)
        if i < args.beacons - 1:
            time.sleep(max(0.5, args.interval + random.uniform(-args.jitter, args.jitter)))

    log("正常 TLS：带 SNI 的短连接 + 非标准端口连接")
    for _ in range(4):
        beacon("127.0.0.3", BENIGN_PORT, with_sni=True, payload=1024, label="benign-tls", rows=rows)
        time.sleep(1.5)
    for _ in range(3):
        beacon("127.0.0.3", BENIGN_ALT_PORT, with_sni=True, payload=2048, label="benign-tls", rows=rows)
        time.sleep(1.2)

    time.sleep(2)
    log("停止抓包…")
    subprocess.run(["docker", "kill", str(cap.pid)], capture_output=True)
    try:
        cap.wait(timeout=15)
    except subprocess.TimeoutExpired:
        cap.kill()
    time.sleep(1)

    for s in servers:
        s.close()

    if not out.exists() or out.stat().st_size == 0:
        raise SystemExit(f"抓包没生成：{out}")

    csv_path = out.with_suffix(".flows.csv")
    lines = ["src,sport,dst,dport,ts,label"]
    lines += [f"{r['src']},{r['sport']},{r['dst']},{r['dport']},{r['ts']},{r['label']}"
              for r in rows]
    csv_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    mal = sum(1 for r in rows if r["label"].startswith("malicious"))
    log(f"完成：{out.relative_to(ROOT)}（{out.stat().st_size / 1024:.0f}KB）")
    log(f"标注：{csv_path.relative_to(ROOT)} · 恶意 {mal} 条 / 正常 {len(rows) - mal} 条")


if __name__ == "__main__":
    sys.exit(main())
