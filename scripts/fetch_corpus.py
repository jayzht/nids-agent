#!/usr/bin/env python3
"""一键拉取公开文档语料（开源框架官方文档）。

为什么选这些语料：
- 全是 Markdown/MDX，带标题层级和代码块 —— 正好体现「结构化分块」的价值；
- 来自 GitHub，可复现、可增量更新（记录 git sha）；
- 内容就是本项目自身的技术栈（FastAPI / LangGraph / Pydantic），
  面试时你既讲得清业务，又讲得清每个检索细节。

用法：
    python scripts/fetch_corpus.py                      # 拉全部（直连，失败自动走代理）
    python scripts/fetch_corpus.py --only fastapi
    python scripts/fetch_corpus.py --proxy http://127.0.0.1:7890
    python scripts/fetch_corpus.py --list

网络说明：GitHub 在国内经常时通时不通，脚本对每个仓库会在「直连 / 代理」之间自动重试。
代理优先级：--proxy > GIT_PROXY > HTTPS_PROXY > https_proxy
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _net import clone_sparse, log, proxy_candidates, run  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw"
CACHE = ROOT / "data" / ".cache"


@dataclass
class Corpus:
    name: str
    repo: str
    title: str
    description: str
    url_template: str
    # subdir -> 复制到 data/raw/<name>/ 下的前缀目录
    subdirs: dict[str, str] = field(default_factory=dict)
    suffixes: tuple[str, ...] = (".md", ".mdx")


CORPORA: dict[str, Corpus] = {
    "fastapi": Corpus(
        name="fastapi",
        repo="https://github.com/tiangolo/fastapi.git",
        title="FastAPI 官方文档（英文）",
        description="FastAPI 框架官方文档：路由、依赖注入、Pydantic 集成、安全、测试、部署。",
        url_template="https://fastapi.tiangolo.com/{path}",
        subdirs={"docs/en/docs": ""},
    ),
    "langgraph": Corpus(
        name="langgraph",
        repo="https://github.com/langchain-ai/docs.git",
        title="LangGraph / LangChain 官方文档",
        description="LangGraph 图编排、状态与检查点、持久化、流式输出、中断、记忆，以及 LangChain Agents 与核心概念。",
        url_template="https://docs.langchain.com/oss/python/{path}",
        subdirs={
            "src/oss/langgraph": "langgraph",
            "src/oss/langchain": "langchain",
            "src/oss/concepts": "concepts",
        },
    ),
    "pydantic": Corpus(
        name="pydantic",
        repo="https://github.com/pydantic/pydantic.git",
        title="Pydantic v2 官方文档",
        description="Pydantic 数据校验：模型、字段校验器、类型系统、序列化、配置。",
        url_template="https://docs.pydantic.dev/latest/{path}",
        subdirs={"docs": ""},
    ),
}

# 自动生成 / 低信息密度的目录，按需排除
EXCLUDE_PARTS = {
    "pydantic": ("api/", "integrations/"),
}


def copy_docs(corpus: Corpus, repo_dir: Path) -> int:
    out_root = RAW / corpus.name
    if out_root.exists():
        shutil.rmtree(out_root)
    out_root.mkdir(parents=True, exist_ok=True)
    count = 0
    excludes = EXCLUDE_PARTS.get(corpus.name, ())

    for subdir, prefix in corpus.subdirs.items():
        base = repo_dir / subdir
        if not base.exists():
            log(f"  !! 目录不存在: {subdir}")
            continue
        for src in sorted(base.rglob("*")):
            if not src.is_file() or src.suffix.lower() not in corpus.suffixes:
                continue
            rel = src.relative_to(base).as_posix()
            if any(rel.startswith(ex) for ex in excludes):
                continue
            target = out_root / prefix / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, target)
            count += 1
    return count


def write_manifest(corpus: Corpus, repo_dir: Path, num_files: int) -> None:
    try:
        sha = run(["git", "rev-parse", "HEAD"], cwd=repo_dir, timeout=30)
    except Exception:  # noqa: BLE001
        sha = ""
    manifest = {
        "name": corpus.name,
        "title": corpus.title,
        "description": corpus.description,
        "url_template": corpus.url_template,
        "repo": corpus.repo,
        "git_sha": sha,
        "num_files": num_files,
    }
    (RAW / corpus.name / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def fetch(name: str, proxies: list[str | None]) -> None:
    corpus = CORPORA[name]
    log(f"[{name}] {corpus.title}")
    repo_dir = CACHE / corpus.name
    clone_sparse(corpus.repo, repo_dir, list(corpus.subdirs), proxies)
    n = copy_docs(corpus, repo_dir)
    if n == 0:
        raise RuntimeError(f"{name}: 没有复制到任何文档，检查 subdirs 配置")
    write_manifest(corpus, repo_dir, n)
    log(f"  -> {n} 个文档写入 {RAW / name}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="", help="只拉取指定语料，逗号分隔")
    ap.add_argument("--proxy", default=None, help="HTTP 代理，如 http://127.0.0.1:7890")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    if args.list:
        for k, c in CORPORA.items():
            log(f"{k:10s} {c.title}  <- {c.repo}")
        return

    proxies = proxy_candidates(args.proxy)
    names = [n.strip() for n in args.only.split(",") if n.strip()] or list(CORPORA)
    for n in names:
        if n not in CORPORA:
            sys.exit(f"未知语料 {n}, 可选: {', '.join(CORPORA)}")
        fetch(n, proxies)

    log("\n下一步: python scripts/build_index.py")


if __name__ == "__main__":
    main()
