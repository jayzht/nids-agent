"""格式归一化：把 RST / RFC 纯文本 / HTML 统一转成 Markdown。

为什么要在「接入层」做转换，而不是让分块器认识每种格式：
- 分块器只需要理解一种结构（Markdown 标题 + 代码块），逻辑不膨胀；
- 转换结果可以人工 review（`data/raw/<kb>/*.md`），坏数据一眼看得出来；
- 换成 PDF / Word 时，只要再写一个转换器，下游全都不用动。

真实语料里三种格式的信息密度差别很大：
    Suricata/Zeek  -> reStructuredText（Sphinx 文档源）
    IETF RFC       -> 定宽纯文本（分页符、页眉页脚、编号小节）
    arXiv 论文     -> HTML（LaTeXML 生成，公式是 MathML）
"""

from __future__ import annotations

import re
from typing import Iterable

# --------------------------------------------------------------------------- #
# reStructuredText -> Markdown
# --------------------------------------------------------------------------- #

_UNDERLINE_RE = re.compile(r"^([=\-~^\"'`#*+:._])\1{2,}\s*$")
_DIRECTIVE_RE = re.compile(r"^(\s*)\.\.\s+([\w-]+)::\s*(.*)$")
_TARGET_RE = re.compile(r"^\s*\.\.\s+_[\w .-]+:\s*$")
_ROLE_RE = re.compile(r":[\w-]+:`([^`]*)`")          # :ref:`x`  |  :example-rule:`y`
_ROLE_BARE_RE = re.compile(r":[\w-]+:(?=\s|$)")
_LITERAL_RE = re.compile(r"``([^`]+)``")

# 这些 directive 的缩进内容值得保留（按正文处理）
_KEEP_BODY = {"container", "topic", "admonition", "example", "hlist", "list-table"}
# 这些是提示框，转成引用块
_ADMONITION = {"note", "warning", "tip", "important", "caution", "attention", "danger", "seealso", "hint"}
# 这些是代码块
_CODE = {"code-block", "code", "sourcecode", "testcode", "doctest", "parsed-literal"}
# 直接丢弃（导航 / 图片 / 包含 / 元信息）
_DROP = {
    "toctree", "include", "literalinclude", "image", "figure", "raw", "meta", "role",
    "contents", "index", "highlight", "default-role", "currentmodule", "module",
    "automodule", "autoclass", "autofunction", "autodata", "csv-table", "graphviz",
    "glossary", "productionlist", "versionadded", "versionchanged", "deprecated",
}


def _inline_rst(text: str) -> str:
    text = _ROLE_RE.sub(lambda m: f"`{m.group(1)}`", text)
    text = _ROLE_BARE_RE.sub("", text)
    text = _LITERAL_RE.sub(lambda m: f"`{m.group(1)}`", text)
    text = text.replace("\\ ", " ")
    return text.rstrip()


def _collect_indented(lines: list[str], start: int) -> tuple[list[str], int]:
    """从 start 开始吃掉所有缩进（或空行）内容，返回 (去缩进的行, 下一个位置)。"""
    body: list[str] = []
    i = start
    while i < len(lines):
        line = lines[i]
        if line.strip() == "":
            body.append("")
            i += 1
            continue
        if not line.startswith((" ", "\t")):
            break
        body.append(line)
        i += 1
    # 去掉公共缩进
    indents = [len(x) - len(x.lstrip()) for x in body if x.strip()]
    cut = min(indents) if indents else 0
    return [x[cut:] if x.strip() else "" for x in body], i


def rst_to_markdown(text: str) -> str:
    # 先做一遍全文预处理：RST 的 role 内容可以跨行（Suricata 的规则示例就是这样）
    text = re.sub(r":[\w-]+:`([^`]*)`", lambda m: f"`{m.group(1).strip()}`", text, flags=re.S)
    text = re.sub(r":[\w-]+:(?=\s|$)", "", text)
    lines = text.splitlines()
    out: list[str] = []
    level_map: dict[str, int] = {}
    i = 0

    def level_for(ch: str) -> int:
        if ch not in level_map:
            level_map[ch] = min(len(level_map) + 1, 6)
        return level_map[ch]

    while i < len(lines):
        raw = lines[i]
        line = raw.rstrip()

        # 1) 超链接目标 / 锚点
        if _TARGET_RE.match(line):
            i += 1
            continue

        # 2) directive
        m = _DIRECTIVE_RE.match(line)
        if m:
            indent, name, arg = m.group(1), m.group(2).lower(), m.group(3).strip()
            body, nxt = _collect_indented(lines, i + 1)
            i = nxt
            if name in _CODE:
                lang = arg.split()[0].strip(":") if arg else ""
                code = "\n".join(body).rstrip()
                if code.strip():
                    out.append(f"```{lang}\n{code}\n```")
                continue
            if name in _ADMONITION:
                label = name.capitalize()
                block = "\n".join(body).strip()
                if block:
                    quoted = "\n".join(f"> {ln}" if ln.strip() else ">" for ln in block.splitlines())
                    out.append(f"> **{label}**\n>\n{quoted}")
                continue
            if name in _DROP:
                continue
            # container 之类：保留内容，丢掉包装
            if name in _KEEP_BODY or name not in _DROP:
                out.extend(body)
                continue

        # 3) 标题：下划线风格
        if i + 1 < len(lines) and _UNDERLINE_RE.match(lines[i + 1]) and line.strip():
            ch = lines[i + 1].strip()[0]
            if len(lines[i + 1].strip()) >= min(3, len(line.strip())):
                out.append(f"{'#' * level_for(ch)} {_inline_rst(line.strip())}")
                i += 2
                continue

        # 4) 标题：上划线风格（====\nTitle\n====）
        if _UNDERLINE_RE.match(line) and i + 2 < len(lines) and _UNDERLINE_RE.match(lines[i + 2]) and lines[i + 1].strip():
            ch = line.strip()[0]
            out.append(f"{'#' * level_for(ch)} {_inline_rst(lines[i + 1].strip())}")
            i += 3
            continue

        # 5) 表格分隔行 / 纯装饰行
        if _UNDERLINE_RE.match(line):
            i += 1
            continue

        # 6) 字段列表（:orphan: 等）
        if re.match(r"^:[\w-]+:", line):
            i += 1
            continue

        # 7) `::` 结尾表示下面是一个字面块
        if line.endswith("::") and not line.strip().startswith(".."):
            intro = line[:-2].rstrip()
            if intro:
                out.append(_inline_rst(intro))
            body, nxt = _collect_indented(lines, i + 1)
            code = "\n".join(body).rstrip()
            if code.strip():
                out.append(f"```\n{code}\n```")
            i = nxt
            continue

        out.append(_inline_rst(line))
        i += 1

    md = "\n".join(out)
    md = re.sub(r"\n{3,}", "\n\n", md)
    return md.strip()


# --------------------------------------------------------------------------- #
# IETF RFC（定宽纯文本）-> Markdown
# --------------------------------------------------------------------------- #

_RFC_HEADER_RE = re.compile(r"^RFC\s+\d+\s{2,}.*$")
_RFC_PAGE_RE = re.compile(r"^\[?Page\s+\d+\]?\s*$")
_RFC_SECTION_RE = re.compile(r"^\s*(\d+(?:\.\d+)*)\.?\s{1,}([A-Z0-9][^\n]*)$")


def rfc_to_markdown(text: str, number: int, title: str = "") -> str:
    lines = [ln.rstrip() for ln in text.replace("\f", "\n").splitlines()]

    # 去掉封面页和目录：从「1. 引言」这类第一个真正的编号小节开始
    start = 0
    toc = next(
        (i for i, ln in enumerate(lines) if re.match(r"^\s*(TABLE OF CONTENTS|CONTENTS)\s*$", ln.strip())),
        None,
    )
    if toc is not None:
        for j in range(toc, len(lines)):
            # 目录行是「1.  INTRODUCTION ....... 1」这种带点线的，必须排除
            if (
                re.match(r"^\s*1\.?\s{1,2}[A-Z]", lines[j])
                and "...." not in lines[j]
                and (j + 1 >= len(lines) or not lines[j + 1].strip())
            ):
                start = j
                break

    out: list[str] = [f"# RFC {number}{': ' + title if title else ''}"]
    i = start
    while i < len(lines):
        line = lines[i]
        if _RFC_PAGE_RE.match(line.strip()) or _RFC_HEADER_RE.match(line):
            i += 1
            continue
        m = _RFC_SECTION_RE.match(line)
        # 只把「下一行是空行」的编号行当标题，避免把正文里的编号列表当成标题
        if (
            m
            and "...." not in line
            and (i + 1 >= len(lines) or not lines[i + 1].strip())
            and len(m.group(2)) < 90
        ):
            depth = min(m.group(1).count(".") + 1, 5)
            out.append(f"{'#' * (depth + 1)} {m.group(1)} {m.group(2).strip()}")
            i += 1
            continue
        out.append(line)
        i += 1
    md = "\n".join(out)
    return re.sub(r"\n{3,}", "\n\n", md).strip()


# --------------------------------------------------------------------------- #
# HTML（arXiv / 网页文档）-> Markdown
# --------------------------------------------------------------------------- #

def html_to_markdown(
    html: str, title: str = "", meta_lines: Iterable[str] = (), max_chars: int = 400_000
) -> str:
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "nav", "header", "footer", "button", "form", "svg"]):
        tag.decompose()

    node = (
        soup.find("article")
        or soup.find("main")
        or soup.find(class_="ltx_page_main")
        or soup.body
        or soup
    )

    # 去掉 MathML 噪音，保留 alttext
    for math in node.find_all("math"):
        alt = math.get("alttext") or ""
        math.replace_with(f" {alt} " if alt else " ")

    try:
        import html2text

        conv = html2text.HTML2Text()
        conv.body_width = 0           # 不要硬换行，交给下游分块
        conv.ignore_images = True
        conv.ignore_emphasis = False
        md = conv.handle(str(node))
    except Exception:  # noqa: BLE001
        md = node.get_text("\n")

    md = re.sub(r"\n{3,}", "\n\n", md).strip()
    header = [f"# {title}"] if title else []
    header += [f"> {ln}" for ln in meta_lines]
    body = "\n\n".join(header + [md]) if header else md
    return body[:max_chars]
