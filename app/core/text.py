"""文本工具：分词、token 估算、归一化、哈希。中英混排场景够用，且零依赖。"""

from __future__ import annotations

import hashlib
import re
import unicodedata

_CJK_RE = re.compile(r"[\u4e00-\u9fff\u3400-\u4dbf]")
_WORD_RE = re.compile(r"[A-Za-z0-9_]+")
_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+|[\u4e00-\u9fff]", re.UNICODE)
_WS_RE = re.compile(r"\s+")


def count_tokens(text: str) -> int:
    """粗略 token 估算（不引入 tiktoken，避免额外下载）。

    经验公式：1 个英文单词 ≈ 1.3 token，1 个中文字 ≈ 1 token，标点按半个算。
    """
    if not text:
        return 0
    cjk = len(_CJK_RE.findall(text))
    words = len(_WORD_RE.findall(text))
    others = len(text) - cjk - words
    return int(cjk + words * 1.3 + others * 0.5) + 1


def normalize(text: str) -> str:
    """用于去重指纹：全半角统一 + 小写 + 压缩空白。"""
    text = unicodedata.normalize("NFKC", text)
    text = text.lower()
    return _WS_RE.sub(" ", text).strip()


def sha1(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


def tokenize(text: str) -> list[str]:
    """BM25 用的分词。

    - 英文/数字：按词切分并小写
    - 中文：单字 + 相邻二字 bigram（无需 jieba，也能抓住「依赖注入」这类词）
    """
    tokens: list[str] = [t for t in _TOKEN_RE.findall(text.lower())]
    # 中文 bigram
    cjk_runs = re.findall(r"[\u4e00-\u9fff\u3400-\u4dbf]+", text)
    for run in cjk_runs:
        for i in range(len(run) - 1):
            tokens.append(run[i : i + 2])
    return tokens


def truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 20].rstrip() + "\n... [已截断]"
