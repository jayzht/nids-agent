"""结构化分块（本项目最容易拉开差距的一环）。

为什么要按 Markdown 标题切，而不是固定 512 字符滑窗：
- 标题天然是语义边界，切出来的片段自带「我在讲哪个主题」的信息；
- 给每个片段拼上标题面包屑（FastAPI > Tutorial > Query Parameters）后，
  向量检索和 BM25 都能同时命中「关键词」和「位置」；
- 代码块绝不能被切断，否则检索到的示例代码是残的，LLM 会照着编。

所以流程是：标题分段 → 段内按空行切块（代码块视为原子）→ 贪心装箱 + 重叠。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.core.text import count_tokens, normalize, sha1
from app.ingest.types import Chunk, Document

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
_ANCHOR_RE = re.compile(r"\{\s*#\s*[\w-]+\s*\}")
_FENCE_RE = re.compile(r"^\s*(```|~~~)")
_FENCE_OPEN_RE = re.compile(r"^\s*(```|~~~)\s*([\w+#.-]*)")
_FENCE_CLOSE_RE = re.compile(r"^\s*(```|~~~)\s*$")


# 这些标题单独出现时不带任何信息量，检索时等于没标题
_GENERIC_HEADINGS = {
    "描述", "检测建议", "简介", "概述", "背景", "说明", "流程", "总结",
    "summary", "overview", "details", "description", "detection", "introduction",
    "content", "example", "examples", "notes",
}


def short_heading(section: "Section", doc_title: str, keep_levels: int = 2) -> str:
    """embed_text 用的短标题。

    只留最近 keep_levels 层，并且丢掉「和文档标题相同」的一级标题。
    原因：像 index.md 这种落地页，H1 就是产品名（FastAPI），
    每块都带这个前缀会让整篇文档变成「万能命中」的 hub，
    把真正相关的页面挤出 top-k。这是向量检索里典型的 hubness 问题。
    """
    titles = [h for _, h in section.headings if h]
    if titles and titles[0].strip().lower() == (doc_title or "").strip().lower():
        titles = titles[1:]
    kept = titles[-keep_levels:]
    joined = " > ".join(kept)
    # 只剩下「描述 / Summary」这类泛化标题时，退回文档标题（MITRE 技术文档就是这样）
    if not kept or all(t.strip().lower() in _GENERIC_HEADINGS for t in kept):
        return (doc_title or "").strip()
    return joined


@dataclass
class Section:
    headings: list[tuple[int, str]] = field(default_factory=list)
    body: str = ""

    @property
    def heading_path(self) -> str:
        return " > ".join(h for _, h in self.headings)

    @property
    def title(self) -> str:
        return self.headings[-1][1] if self.headings else ""


def split_sections(text: str) -> list[Section]:
    """按标题层级切段，代码块里的 `#` 不会被误判成标题。"""
    sections: list[Section] = []
    stack: list[tuple[int, str]] = []
    buf: list[str] = []
    in_fence = False

    def flush() -> None:
        body = "\n".join(buf).strip()
        if body:
            sections.append(Section(headings=list(stack), body=body))

    for line in text.splitlines():
        if _FENCE_RE.match(line):
            in_fence = not in_fence
            buf.append(line)
            continue
        m = None if in_fence else _HEADING_RE.match(line)
        if m:
            flush()
            buf = []
            level = len(m.group(1))
            title = _ANCHOR_RE.sub("", m.group(2)).strip()
            while stack and stack[-1][0] >= level:
                stack.pop()
            stack.append((level, title))
            continue
        buf.append(line)
    flush()
    return sections


def _split_blocks(body: str) -> list[str]:
    """按空行切原子块，代码块内部不切。"""
    blocks: list[str] = []
    cur: list[str] = []
    in_fence = False
    for line in body.splitlines():
        if _FENCE_RE.match(line):
            in_fence = not in_fence
            cur.append(line)
            continue
        if not in_fence and not line.strip():
            if cur:
                blocks.append("\n".join(cur).strip())
                cur = []
            continue
        cur.append(line)
    if cur:
        blocks.append("\n".join(cur).strip())
    return [b for b in blocks if b]


def _split_lines(lines: list[str], budget: int) -> list[str]:
    """按行装箱；单行超长时再按字符切，保证每片都不超预算。"""
    pieces: list[str] = []
    cur: list[str] = []
    cur_tok = 0
    for line in lines:
        t = count_tokens(line)
        if cur and cur_tok + t > budget:
            pieces.append("".join(cur))
            cur, cur_tok = [], 0
        if t > budget * 3:  # 超长单行（压缩过的 JSON / 一行表格）
            step = max(budget, 1) * 3
            for i in range(0, len(line), step):
                pieces.append(line[i : i + step])
            continue
        cur.append(line)
        cur_tok += t
    if cur:
        pieces.append("".join(cur))
    return [p for p in pieces if p.strip()]


def _hard_split(block: str, max_tokens: int) -> list[str]:
    """单个巨块兜底切分。

    关键细节：如果这个块本身是围栏代码块，切开之后必须给每一片**补上床围栏**，
    否则下游拿到的就是语法残缺的代码，模型会照着残码编。
    """
    if count_tokens(block) <= max_tokens:
        return [block]

    lines = block.splitlines(keepends=True)
    m = _FENCE_OPEN_RE.match(lines[0]) if lines else None
    if not m:
        return _split_lines(lines, max_tokens)

    fence, lang = m.group(1), m.group(2)
    body = lines[1:]
    if body and _FENCE_CLOSE_RE.match(body[-1]):
        body = body[:-1]
    budget = max(40, max_tokens - 10)  # 给围栏留位置
    pieces = _split_lines(body, budget)
    return [f"{fence}{lang}\n" + p.rstrip() + f"\n{fence}\n" for p in pieces]


def pack_blocks(
    blocks: list[str], max_tokens: int, overlap_tokens: int
) -> list[str]:
    """贪心装箱 + 尾部重叠。"""
    chunks: list[str] = []
    cur: list[str] = []
    cur_tok = 0

    def flush() -> None:
        nonlocal cur, cur_tok
        if cur:
            chunks.append("\n\n".join(cur).strip())
        if overlap_tokens > 0 and cur:
            tail: list[str] = []
            tail_tok = 0
            for b in reversed(cur):
                bt = count_tokens(b)
                if tail_tok + bt > overlap_tokens:
                    break
                tail.insert(0, b)
                tail_tok += bt
            cur, cur_tok = tail, tail_tok
        else:
            cur, cur_tok = [], 0

    for block in blocks:
        for piece in _hard_split(block, max_tokens):
            t = count_tokens(piece)
            if cur and cur_tok + t > max_tokens:
                flush()
                # 重叠块本身已经接近上限时，避免死循环
                if cur_tok + t > max_tokens:
                    cur, cur_tok = [], 0
            cur.append(piece)
            cur_tok += t
    if cur:
        chunks.append("\n\n".join(cur).strip())
    return [c for c in chunks if c]


def chunk_document(
    doc: Document, max_tokens: int = 420, overlap_tokens: int = 60
) -> list[Chunk]:
    chunks: list[Chunk] = []
    seq = 0
    for section in split_sections(doc.text):
        blocks = _split_blocks(section.body)
        if not blocks:
            continue
        for body in pack_blocks(blocks, max_tokens, overlap_tokens):
            if count_tokens(body) < 12:  # 导航条 / 一句废话
                continue
            heading = section.heading_path
            short = short_heading(section, doc.title)
            embed_text = f"{short}\n{body}" if short else body
            chunks.append(
                Chunk(
                    chunk_id=sha1(f"{doc.doc_id}:{seq}:{body}")[:16],
                    doc_id=doc.doc_id,
                    kb=doc.kb,
                    path=doc.path,
                    title=doc.title,
                    heading_path=heading,
                    text=body,
                    embed_text=embed_text,
                    tokens=count_tokens(body),
                    source_url=doc.source_url,
                    seq=seq,
                )
            )
            seq += 1
    return chunks


def chunk_documents(
    docs: list[Document], max_tokens: int = 420, overlap_tokens: int = 60
) -> tuple[list[Chunk], int]:
    """跨文档去重（同一段内容在多个版本/语言文件中重复很常见）。

    返回 (chunks, 去重掉的重复片段数)。
    """
    seen: set[str] = set()
    out: list[Chunk] = []
    dup = 0
    for doc in docs:
        for ch in chunk_document(doc, max_tokens, overlap_tokens):
            fingerprint = sha1(normalize(ch.text))
            if fingerprint in seen:
                dup += 1
                continue
            seen.add(fingerprint)
            out.append(ch)
    return out, dup
