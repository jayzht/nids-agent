"""文档加载：把一堆 Markdown 变成带元数据的 Document。"""

from __future__ import annotations

import json
import re
from pathlib import Path

from app.core.text import sha1
from app.ingest.types import Document

SUPPORTED_SUFFIXES = {".md", ".mdx", ".markdown", ".txt"}

_FRONTMATTER_RE = re.compile(r"\A---\s*\n.*?\n---\s*\n", re.DOTALL)
_STYLE_RE = re.compile(r"<(style|script)\b[^>]*>.*?</\1>", re.DOTALL | re.IGNORECASE)
_INCLUDE_RE = re.compile(r"\{\*.*?\*\}", re.DOTALL)
_ANCHOR_RE = re.compile(r"\{\s*#\s*[\w-]+\s*\}")
_IMG_RE = re.compile(r"<img\b[^>]*>", re.IGNORECASE)
_TAG_ONLY_LINE_RE = re.compile(r"^\s*</?(?:p|div|br|center|details|summary|table|tr|td|th|thead|tbody|ul|ol|li|h[1-6])\b[^>]*>\s*$", re.IGNORECASE | re.MULTILINE)
_IMPORT_RE = re.compile(r"^(import|export)\s.*$", re.MULTILINE)
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_JSX_ONLY_RE = re.compile(r"^\s*</?[A-Z][A-Za-z0-9]*[^>]*/?>\s*$", re.MULTILINE)
_TITLE_RE = re.compile(r"^#\s+(.+)$", re.MULTILINE)
_H1_OR_TITLE_RE = re.compile(r"^(?:title:\s*|\#\s+)(.+)$", re.MULTILINE)


def clean_markdown(raw: str) -> str:
    """去掉 MDX 里对检索无意义、但会污染切分和 BM25 的语法噪音。"""
    text = _FRONTMATTER_RE.sub("", raw)
    text = _STYLE_RE.sub("", text)
    text = _INCLUDE_RE.sub("", text)
    text = _ANCHOR_RE.sub("", text)
    text = _IMG_RE.sub("", text)
    text = _TAG_ONLY_LINE_RE.sub("", text)
    text = _HTML_COMMENT_RE.sub("", text)
    text = _IMPORT_RE.sub("", text)
    text = _JSX_ONLY_RE.sub("", text)
    # 折叠 3 行以上空行
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def guess_title(text: str, path: str) -> str:
    m = _H1_OR_TITLE_RE.search(text)
    if m:
        return m.group(1).strip().strip('"').strip("'")
    return Path(path).stem.replace("-", " ").replace("_", " ").title()


def build_source_url(url_template: str, path: str) -> str:
    if not url_template:
        return ""
    p = Path(path)
    no_ext = str(p.with_suffix(""))
    slug = no_ext
    if slug.endswith("/index"):
        slug = slug[: -len("/index")]
    if slug == "index":
        slug = ""
    return url_template.replace("{path}", slug).replace("{ext}", p.suffix.lstrip("."))


# 这些文档对「问答」是纯噪音：体量大、几乎全是版本流水账，或者只是落地页
SKIP_PATTERNS: tuple[str, ...] = (
    r"^index\.mdx?$",           # KB 根目录的落地页（营销内容）
    r"^release-notes\.md$",     # FastAPI 发布日志：单文件曾占整个 KB 的 48%
    r"^changelog.*\.mdx?$",     # LangChain 变更日志
    r"/changelog.*\.mdx?$",
)
_SKIP_RES = [re.compile(p) for p in SKIP_PATTERNS]


def should_skip(rel_path: str) -> bool:
    return any(r.search(rel_path) for r in _SKIP_RES)


def iter_doc_files(root: Path) -> list[Path]:
    files = [p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in SUPPORTED_SUFFIXES]
    # 排序保证索引可复现
    return sorted(files, key=lambda p: str(p.relative_to(root)))


def load_document(path: Path, root: Path, kb: str, url_template: str = "") -> Document | None:
    try:
        raw = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    rel = str(path.relative_to(root)).replace("\\", "/")
    if should_skip(rel):
        return None
    text = clean_markdown(raw)
    if len(text) < 40:  # 空文件 / 只有标题的占位文件
        return None
    title = guess_title(text, rel)
    return Document(
        doc_id=sha1(f"{kb}:{rel}")[:16],
        kb=kb,
        path=rel,
        title=title,
        text=text,
        source_url=build_source_url(url_template, rel),
    )


def load_corpus(root: Path, kb: str, url_template: str = "") -> list[Document]:
    docs: list[Document] = []
    for f in iter_doc_files(root):
        doc = load_document(f, root, kb, url_template)
        if doc is not None:
            docs.append(doc)
    return docs


def load_manifest(raw_root: Path, kb: str) -> dict:
    """scripts/fetch_corpus.py 下载语料时写的清单。"""
    mf = raw_root / kb / "manifest.json"
    if mf.exists():
        return json.loads(mf.read_text(encoding="utf-8"))
    return {}
