#!/usr/bin/env python3
"""补充 PDF / HTML 类权威文档：NIST 事件响应、MS-SMB2 协议规范、Snort 3 官方文档。

这三类之前补不进来，因为项目只吃 Markdown：
    NIST SP 800-61  -> PDF
    MS-SMB2         -> PDF（微软 Open Specifications）
    Snort 3 文档    -> HTML（docs.snort.org 的整本 print.html）

用法：
    python scripts/fetch_pdf_docs.py              # 全部
    python scripts/fetch_pdf_docs.py --only nist
    python scripts/fetch_pdf_docs.py --proxy http://127.0.0.1:7890
"""

from __future__ import annotations

import argparse
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from _net import log, proxy_candidates  # noqa: E402
from app.ingest.converters import html_to_markdown  # noqa: E402
from app.ingest.pdf import pdf_to_markdown  # noqa: E402

RAW = ROOT / "data" / "raw" / "ids"
CACHE = ROOT / "data" / ".cache" / "docs"
KB = "ids"


@dataclass
class DocSource:
    key: str
    kind: str                 # pdf | html
    url: str
    prefix: str
    title: str
    name: str                 # 输出文件名（不含扩展名）
    max_pages: int | None = None
    drop_patterns: tuple[str, ...] = field(default_factory=tuple)


SOURCES: list[DocSource] = [
    DocSource(
        key="nist800-61r3", kind="pdf",
        url="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf",
        prefix="nist", title="NIST SP 800-61r3 事件响应指南",
        name="NIST.SP.800-61r3",
        drop_patterns=(r"^NIST SP 800-61", r"^Incident Response Recommendations"),
    ),
    DocSource(
        key="nist800-61r2", kind="pdf",
        url="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf",
        prefix="nist", title="NIST SP 800-61r2 事件响应指南",
        name="NIST.SP.800-61r2",
        drop_patterns=(r"^NIST SP 800-61",),
    ),
    DocSource(
        key="ms-smb2", kind="pdf",
        url="https://winprotocoldocs-bhdugrdyduf5h2e4.b02.azurefd.net/MS-SMB2/%5bMS-SMB2%5d.pdf",
        prefix="ms-smb2", title="MS-SMB2：SMB 协议 2/3 规范（微软 Open Specifications）",
        name="MS-SMB2",
        drop_patterns=(r"^\[MS-SMB2\]", r"^Copyright ©", r"^Release:", r"^Server Message Block \(SMB\)"),
    ),
    DocSource(
        key="snort3", kind="html",
        url="https://docs.snort.org/print.html",
        prefix="snort", title="Snort 3 官方文档（规则、配置、插件）",
        name="snort3",
    ),
]


def download(src: DocSource, proxies: list[str | None]) -> Path:
    CACHE.mkdir(parents=True, exist_ok=True)
    suffix = ".pdf" if src.kind == "pdf" else ".html"
    dest = CACHE / f"{src.key}{suffix}"
    if dest.exists() and dest.stat().st_size > 1024:
        log(f"  [cache] {dest.name}")
        return dest
    last: Exception | None = None
    for _ in range(2):
        for proxy in proxies:
            try:
                with httpx.Client(proxy=proxy, timeout=180, follow_redirects=True,
                                  headers={"User-Agent": "devrag-corpus-bot/1.0"}) as c:
                    resp = c.get(src.url)
                    resp.raise_for_status()
                    dest.write_bytes(resp.content)
                    log(f"  {src.key:14s} {len(resp.content)/1024:9.1f} KB")
                    return dest
            except Exception as exc:  # noqa: BLE001
                last = exc
                time.sleep(1)
    raise RuntimeError(f"下载失败 {src.url}: {last}")


def convert(src: DocSource, path: Path) -> str:
    if src.kind == "pdf":
        return pdf_to_markdown(path, title=src.title, max_pages=src.max_pages,
                               drop_patterns=src.drop_patterns)
    return html_to_markdown(path.read_text(encoding="utf-8", errors="ignore"), title=src.title)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--proxy", default=None)
    args = ap.parse_args()

    wanted = {x.strip() for x in args.only.split(",") if x.strip()}
    proxies = proxy_candidates(args.proxy)

    for src in SOURCES:
        if wanted and src.key not in wanted:
            continue
        log(f"[{src.key}] {src.title}")
        try:
            path = download(src, proxies)
            md = convert(src, path)
        except Exception as exc:  # noqa: BLE001
            log(f"  !! 失败：{str(exc)[:180]}")
            continue
        target = RAW / src.prefix / f"{src.name}.md"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(md, encoding="utf-8")
        log(f"  -> {target.relative_to(RAW)}（{len(md)} 字符）")

    # 复用领域语料的 manifest 生成逻辑
    from fetch_domain_corpus import scan_urls, write_manifest  # noqa: E402

    urls = scan_urls(RAW)
    write_manifest(RAW, urls)
    log(f"\nmanifest 已更新：{len(urls)} 篇文档")
    log("下一步: python scripts/build_index.py --kb ids")


if __name__ == "__main__":
    main()
