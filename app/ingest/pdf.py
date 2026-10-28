"""PDF → Markdown 转换。

真实语料里 PDF 很常见（NIST 规范、微软协议文档），但直接抽文本会得到：
- 每页重复的页眉页脚（`[MS-SMB2] - v20260928`、`51 / 499`）
- 句中断行（PDF 按版面换行，不是按语义）
- 没有标题结构

所以这里做三件事：去页眉页脚 → 行重排成段落 → 用 `## Page N` 当章节，
让分块器至少能带「页码」这个定位信息（引用时能指回原文第几页）。
"""

from __future__ import annotations

import re
from pathlib import Path

_PAGE_NO_RE = re.compile(r"^\d+\s*/\s*\d+$")
_SENTENCE_END = tuple("。！？.!?:：;；)]}）】")


def _clean_lines(lines: list[str], drop_patterns: tuple[str, ...]) -> list[str]:
    out: list[str] = []
    for raw in lines:
        s = raw.strip()
        if not s:
            out.append("")
            continue
        if _PAGE_NO_RE.match(s):
            continue
        if any(re.search(p, s) for p in drop_patterns):
            continue
        out.append(s)
    return out


def _reflow(lines: list[str]) -> str:
    """把 PDF 的硬换行拼回段落。

    规则很保守：上一行不是以句末标点结束、且下一行不是以大写字母/编号开头，
    就认为它们是同一句，拼上空格。
    """
    merged: list[str] = []
    for line in lines:
        if not line:
            merged.append("")
            continue
        if merged and merged[-1] and not merged[-1].endswith(_SENTENCE_END):
            prev = merged[-1]
            if not re.match(r"^([A-Z][a-z]+:|[0-9]+[.)]|[-*•]|##|\|)", line) and not prev.endswith("-"):
                merged[-1] = prev + " " + line
                continue
        if merged and merged[-1].endswith("-") and line[:1].islower():
            merged[-1] = merged[-1][:-1] + line   # 连字符断词
            continue
        merged.append(line)
    text = "\n".join(merged)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def pdf_to_markdown(
    path: Path | str,
    title: str = "",
    max_pages: int | None = None,
    drop_patterns: tuple[str, ...] = (),
) -> str:
    from pypdf import PdfReader

    reader = PdfReader(str(path))
    pages = reader.pages[:max_pages] if max_pages else reader.pages
    parts: list[str] = [f"# {title}"] if title else []
    for i, page in enumerate(pages, 1):
        try:
            raw = page.extract_text() or ""
        except Exception:  # noqa: BLE001 - 个别页解析失败不影响整体
            continue
        body = _reflow(_clean_lines(raw.splitlines(), drop_patterns))
        if len(body) < 40:
            continue
        parts.append(f"## Page {i}\n\n{body}")
    return "\n\n".join(parts)
