#!/usr/bin/env python3
"""领域语料一键构建：网络流量检测 / 入侵检测（NIDS）。

为什么要自己写采集器而不是「找一份现成的语料」：
NIDS 这个方向**没有**一份覆盖「工具怎么用 + 协议怎么规定 + 方法怎么研究」的单一文档，
真实的知识散在三类源里，而且三种格式：

    工具文档  Suricata / Zeek / nDPI   -> reStructuredText（Sphinx）
    协议规范  IETF RFC                -> 定宽纯文本（分页符、页眉页脚）
    研究论文  arXiv                   -> HTML（LaTeXML）

本脚本负责采集 + 统一转成 Markdown，剩下的分块/索引/检索复用项目原有管线。

用法：
    python scripts/fetch_domain_corpus.py                       # 全量
    python scripts/fetch_domain_corpus.py --proxy http://127.0.0.1:7890
    python scripts/fetch_domain_corpus.py --only suricata,zeek
    python scripts/fetch_domain_corpus.py --papers 12           # 少抓点论文，快
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import time
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from _net import clone_sparse, http_get, log, proxy_candidates  # noqa: E402

from app.ingest.converters import html_to_markdown, rfc_to_markdown, rst_to_markdown  # noqa: E402

RAW = ROOT / "data" / "raw"
CACHE = ROOT / "data" / ".cache"
KB = "ids"

TITLE = "网络流量检测 / 入侵检测（NIDS）"
DESCRIPTION = (
    "Suricata、Zeek、nDPI 官方文档 + IETF RFC 协议规范 + arXiv 最新论文，"
    "覆盖规则编写、协议解析与字段含义、流量特征工程、异常检测与入侵检测方法。"
)


@dataclass
class GitSource:
    name: str
    repo: str
    prefix: str
    sparse: bool = True
    subdirs: list[str] = field(default_factory=list)   # 空 = 整个仓库
    suffixes: tuple[str, ...] = (".rst",)
    # 输出路径是否去掉源仓库里的文档根目录（suricata 的 doc/userguide 去掉更干净）
    strip_subdir: bool = True
    url_for: Callable[[str, str], str] = lambda rel_repo, rel_sub: ""


# 只要这些子目录（Zeek 仓库里有大量自动生成的空壳页，用内容长度过滤）
ZEEK_ROOTS: tuple[str, ...] = ("logs", "frameworks", "scripting", "script-reference",
                               "scripts/policy", "scripts/base/protocols")

# --------------------------------------------------------------------------- #
# 1. 工具文档（RST）
# --------------------------------------------------------------------------- #

GIT_SOURCES: list[GitSource] = [
    GitSource(
        name="suricata",
        repo="https://github.com/OISF/suricata.git",
        prefix="suricata",
        subdirs=["doc/userguide"],
        url_for=lambda rel_repo, rel_sub: f"https://docs.suricata.io/en/latest/{rel_sub}.html",
    ),
    GitSource(
        name="zeek",
        repo="https://github.com/zeek/zeek-docs.git",
        prefix="zeek",
        subdirs=list(ZEEK_ROOTS),   # 整个仓库是文档，但只挑这些目录
        sparse=False,
        strip_subdir=False,         # 保留 logs/ frameworks/ 等层级
        url_for=lambda rel_repo, rel_sub: f"https://docs.zeek.org/en/master/{rel_repo}.html",
    ),
    GitSource(
        name="sigma",
        repo="https://github.com/SigmaHQ/sigma.git",
        prefix="sigma",
        subdirs=["documentation"],
        suffixes=(".md",),
        url_for=lambda rel_repo, rel_sub: f"https://github.com/SigmaHQ/sigma/blob/master/{rel_repo}.md",
    ),
    GitSource(
        name="sigma-spec",
        repo="https://github.com/SigmaHQ/sigma-specification.git",
        prefix="sigma-spec",
        subdirs=["specification", "sigmahq"],
        suffixes=(".md",),
        url_for=lambda rel_repo, rel_sub: (
            f"https://github.com/SigmaHQ/sigma-specification/blob/main/{rel_repo}.md"
        ),
    ),
    GitSource(
        name="ndpi",
        repo="https://github.com/ntop/nDPI.git",
        prefix="ndpi",
        subdirs=["doc"],
        suffixes=(".rst", ".md"),
        url_for=lambda rel_repo, rel_sub: f"https://www.ntop.org/guides/ndpi/{Path(rel_sub).stem}.html",
    ),
]


def convert_git(src: GitSource, proxies: list[str | None], out_root: Path, urls: dict[str, str]) -> int:
    dest = CACHE / f"ids_{src.name}"
    clone_sparse(src.repo, dest, src.subdirs, proxies, sparse=src.sparse)

    bases = [(dest / s, s) for s in src.subdirs] or [(dest, "")]

    count = 0
    skipped = 0
    collisions = 0
    for base, sub in bases:
        if not base.exists():
            log(f"  !! 目录不存在: {base.relative_to(dest)}")
            continue
        for f in sorted(base.rglob("*")):
            if not f.is_file() or f.suffix.lower() not in src.suffixes:
                continue
            rel_repo = str(Path(f.relative_to(dest)).with_suffix("")).replace("\\", "/")
            rel_sub = str(Path(f.relative_to(base)).with_suffix("")).replace("\\", "/")
            rel_target = Path(rel_sub) if src.strip_subdir or base == dest else Path(sub) / rel_sub
            raw = f.read_text(encoding="utf-8", errors="ignore")
            md = rst_to_markdown(raw) if f.suffix == ".rst" else raw
            if len(md) < 300:          # 自动生成的空壳页（只有 Summary / Detailed Interface）
                skipped += 1
                continue
            target = out_root / src.prefix / rel_target.with_suffix(".md")
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():   # 不同源文件落到同一路径，别静默覆盖
                collisions += 1
                target = target.with_name(f"{target.stem}--{collisions}.md")
            target.write_text(md, encoding="utf-8")
            urls[target.relative_to(out_root).as_posix()] = src.url_for(rel_repo, rel_sub)
            count += 1
    extra = f"，重名改名 {collisions} 篇" if collisions else ""
    log(f"  {src.name}: {count} 篇（跳过 {skipped} 篇空壳页{extra}）")
    return count


# --------------------------------------------------------------------------- #
# 2. IETF RFC（纯文本）
# --------------------------------------------------------------------------- #

RFCS: list[tuple[int, str]] = [
    (791, "Internet Protocol"),
    (792, "Internet Control Message Protocol"),
    (768, "User Datagram Protocol"),
    (793, "Transmission Control Protocol"),
    (9293, "Transmission Control Protocol (TCP) Specification"),
    (1034, "Domain Names - Concepts and Facilities"),
    (1035, "Domain Names - Implementation and Specification"),
    (2131, "Dynamic Host Configuration Protocol"),
    (2865, "Remote Authentication Dial In User Service (RADIUS)"),
    (3954, "Cisco Systems NetFlow Services Export Version 9"),
    (4120, "The Kerberos Network Authentication Service (V5)"),
    (4443, "ICMPv6 for IPv6"),
    (4511, "Lightweight Directory Access Protocol (LDAP): The Protocol"),
    (5246, "The Transport Layer Security (TLS) Protocol Version 1.2"),
    (5424, "The Syslog Protocol"),
    (7011, "IP Flow Information Export (IPFIX) Protocol"),
    (8446, "The Transport Layer Security (TLS) Protocol Version 1.3"),
    (8484, "DNS Queries over HTTPS (DoH)"),
    (9000, "QUIC: A UDP-Based Multiplexed and Secure Transport"),
    (9110, "HTTP Semantics"),
    (9113, "HTTP/2"),
]

RFC_BASE = "https://www.rfc-editor.org/rfc/rfc{n}.txt"


def convert_rfcs(proxies: list[str | None], out_root: Path, urls: dict[str, str]) -> int:
    ok = 0
    for num, title in RFCS:
        try:
            text = http_get(RFC_BASE.format(n=num), proxies)
        except Exception as exc:  # noqa: BLE001
            log(f"  !! RFC {num} 下载失败: {str(exc)[:100]}")
            continue
        md = rfc_to_markdown(text, num, title)
        path = out_root / "rfc" / f"rfc{num}.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(md, encoding="utf-8")
        urls[path.relative_to(out_root).as_posix()] = RFC_BASE.format(n=num)
        ok += 1
        log(f"  RFC {num}: {len(md)} 字符")
        time.sleep(0.5)   # 对 rfc-editor 客气一点
    return ok


# --------------------------------------------------------------------------- #
# 3. arXiv 论文（HTML -> Markdown）
# --------------------------------------------------------------------------- #

ARXIV_QUERIES = [
    'all:"network intrusion detection"',
    'all:"encrypted traffic classification"',
    'all:"network traffic anomaly detection"',
    'all:"CICIDS"',
    # 「心跳/周期通信」是 C2 检测的核心方法，但前四个查询覆盖不到方法论。
    # 注意别用 all:"beaconing"：那个词在 arXiv 上基本被车联网/V2X 占用，全是误召回。
    'all:"command and control" AND all:detection',
    'all:"periodicity" AND all:botnet',
]

ARXIV_API = "https://export.arxiv.org/api/query"
NS = {"a": "http://www.w3.org/2005/Atom"}


def _xml_text(node, tag: str) -> str:
    el = node.find(f"a:{tag}", NS)
    return (el.text or "").strip() if el is not None else ""


def arxiv_search(query: str, max_results: int, proxies: list[str | None]) -> list[dict]:
    params = {
        "search_query": query,
        "start": 0,
        "max_results": max_results,
        "sortBy": "relevance",
        "sortOrder": "descending",
    }
    xml = http_get(f"{ARXIV_API}?{urllib.parse.urlencode(params)}", proxies, timeout=90)
    root = ET.fromstring(xml)
    out = []
    for entry in root.findall("a:entry", NS):
        raw_id = _xml_text(entry, "id")
        m = re.search(r"abs/([^v]+)(v\d+)?$", raw_id)
        if not m:
            continue
        authors = [
            (a.find("a:name", NS).text or "").strip()
            for a in entry.findall("a:author", NS)
        ]
        out.append(
            {
                "id": m.group(1),
                "title": re.sub(r"\s+", " ", _xml_text(entry, "title")),
                "abstract": re.sub(r"\s+", " ", _xml_text(entry, "summary")),
                "published": _xml_text(entry, "published")[:10],
                "authors": authors[:6],
            }
        )
    return out


def convert_papers(
    proxies: list[str | None], out_root: Path, urls: dict[str, str], limit: int
) -> int:
    seen: set[str] = set()
    papers: list[dict] = []
    per_query = max(3, limit // len(ARXIV_QUERIES))
    for q in ARXIV_QUERIES:
        try:
            found = arxiv_search(q, per_query, proxies)
            log(f"  {q} -> {len(found)} 篇")
        except Exception as exc:  # noqa: BLE001
            log(f"  !! 检索失败 {q}: {str(exc)[:100]}")
            continue
        for p in found:
            if p["id"] not in seen:
                seen.add(p["id"])
                papers.append(p)
        time.sleep(3)   # arXiv API 要求 3 秒间隔

    papers = papers[:limit]
    ok = 0
    for p in papers:
        html = None
        for attempt_url in (
            f"https://arxiv.org/html/{p['id']}",
            f"https://ar5iv.labs.arxiv.org/html/{p['id']}",
        ):
            try:
                html = http_get(attempt_url, proxies, retries=1, timeout=90)
                if len(html) > 5000:
                    break
                html = None
            except Exception:  # noqa: BLE001
                html = None
            time.sleep(1)
        if not html:
            log(f"  -- 跳过（无 HTML 全文）: {p['id']}")
            continue

        meta = [
            f"Authors: {', '.join(p['authors']) or 'unknown'}",
            f"Published: {p['published']}",
            f"arXiv: {p['id']}",
            f"URL: https://arxiv.org/abs/{p['id']}",
            f"Abstract: {p['abstract']}",
        ]
        md = html_to_markdown(html, title=p["title"], meta_lines=meta)
        slug = re.sub(r"[^a-z0-9]+", "-", p["title"].lower()).strip("-")[:60]
        target = out_root / "papers" / f"{p['id'].replace('.', '_')}-{slug}.md"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(md, encoding="utf-8")
        urls[target.relative_to(out_root).as_posix()] = f"https://arxiv.org/abs/{p['id']}"
        ok += 1
        log(f"  ✔ {p['id']} {p['title'][:60]} ({len(md)} 字符)")
        time.sleep(2)
    return ok


# --------------------------------------------------------------------------- #
# 4. 从磁盘反推每个文件的原文链接（支持分多次抓取后合并 manifest）
# --------------------------------------------------------------------------- #

def scan_urls(out_root: Path) -> dict[str, str]:
    urls: dict[str, str] = {}
    for f in sorted(out_root.rglob("*.md")):
        rel = f.relative_to(out_root).as_posix()
        top, _, rest = rel.partition("/")
        stem = rest.rsplit("/", 1)[-1][: -len(".md")]
        url = ""
        if top == "suricata":
            url = f"https://docs.suricata.io/en/latest/{stem}.html"
        elif top == "zeek":
            url = f"https://docs.zeek.org/en/master/{stem}.html"
        elif top == "ndpi":
            url = f"https://www.ntop.org/guides/ndpi/{Path(stem).stem}.html"
        elif top == "rfc":
            url = RFC_BASE.format(n=Path(stem).stem.replace("rfc", ""))
        elif top == "sigma-spec":
            url = (
                "https://github.com/SigmaHQ/sigma-specification/blob/main/"
                f"{stem}.md"
            )
        elif top == "sigma":
            url = f"https://github.com/SigmaHQ/sigma/blob/master/documentation/{stem}.md"
        elif top == "mitre":
            m = re.match(r"([TSGM]\d{3}(?:\.\d{3})?)-", stem)
            if m:
                tid = m.group(1)
                kind = {"T": "techniques", "S": "software", "G": "groups",
                        "M": "mitigations"}.get(tid[0], "techniques")
                if rest.startswith("tactics/"):
                    kind = "tactics"
                url = f"https://attack.mitre.org/{kind}/{tid}/"
        elif top == "nist":
            url = f"https://nvlpubs.nist.gov/nistpubs/SpecialPublications/{stem}.pdf"
        elif top == "ms-smb2":
            url = "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/"
        elif top == "snort":
            url = "https://docs.snort.org/"
        elif top == "sigma-rules":
            url = f"https://github.com/SigmaHQ/sigma/blob/master/rules/{stem}.yml"
        elif top == "papers":
            m = re.match(r"(\d{4})_(\d{4,5})-", stem)
            if m:
                url = f"https://arxiv.org/abs/{m.group(1)}.{m.group(2)}"
        urls[rel] = url          # 没有映射也保留条目，保证文件被计入索引
    return urls


def write_manifest(out_root: Path, urls: dict[str, str]) -> None:
    manifest = {
        "name": KB,
        "title": TITLE,
        "description": DESCRIPTION,
        "url_template": "",
        "urls": urls,
        "num_files": len(urls),
        "sources": [
            {"name": s.name, "repo": s.repo, "subdirs": s.subdirs} for s in GIT_SOURCES
        ]
        + [{"name": "ietf-rfc", "repo": "https://www.rfc-editor.org", "subdirs": []},
           {"name": "arxiv", "repo": "https://arxiv.org", "subdirs": []}],
    }
    (out_root / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )


# --------------------------------------------------------------------------- #

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--proxy", default=None)
    ap.add_argument("--only", default="", help="suricata,zeek,ndpi,rfc,papers")
    ap.add_argument("--papers", type=int, default=20, help="抓多少篇 arXiv 论文")
    ap.add_argument("--keep", action="store_true", help="保留已有文件（默认清空重建）")
    ap.add_argument("--manifest-only", action="store_true", help="只根据磁盘内容重建 manifest")
    args = ap.parse_args()

    proxies = proxy_candidates(args.proxy)
    out_root = RAW / KB
    if args.manifest_only:
        urls = scan_urls(out_root)
        write_manifest(out_root, urls)
        log(f"manifest 已重建：{len(urls)} 篇文档")
        return
    if out_root.exists() and not args.keep:
        shutil.rmtree(out_root)
    out_root.mkdir(parents=True, exist_ok=True)
    CACHE.mkdir(parents=True, exist_ok=True)

    wanted = {x.strip() for x in args.only.split(",") if x.strip()}
    urls: dict[str, str] = {}
    total = 0

    if not wanted or "tools" in wanted or wanted & {s.name for s in GIT_SOURCES}:
        log("== 工具文档（RST） ==")
        for src in GIT_SOURCES:
            if wanted and src.name not in wanted and "tools" not in wanted:
                continue
            try:
                total += convert_git(src, proxies, out_root, urls)
            except Exception as exc:  # noqa: BLE001
                log(f"  !! {src.name} 失败: {str(exc)[:200]}")

    if not wanted or "rfc" in wanted:
        log("== IETF RFC（纯文本） ==")
        total += convert_rfcs(proxies, out_root, urls)

    if not wanted or "papers" in wanted:
        log("== arXiv 论文（HTML） ==")
        total += convert_papers(proxies, out_root, urls, args.papers)

    merged = scan_urls(out_root)      # 磁盘为准，分次抓取也不会丢 URL
    write_manifest(out_root, merged)
    log(f"\n完成：本轮写入 {total} 篇，磁盘共 {len(merged)} 篇 -> {out_root}")
    log("下一步: python scripts/build_index.py --kb ids")


if __name__ == "__main__":
    main()
