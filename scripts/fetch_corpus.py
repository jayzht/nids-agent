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
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

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


def log(msg: str) -> None:
    print(msg, flush=True)


def proxy_candidates(cli_proxy: str | None) -> list[str | None]:
    """显式 --proxy 时它优先；否则直连优先，再逐个尝试环境里的代理。"""
    cands: list[str | None] = [cli_proxy, None] if cli_proxy else [None]
    for p in (
        cli_proxy,
        os.environ.get("GIT_PROXY"),
        os.environ.get("HTTPS_PROXY"),
        os.environ.get("https_proxy"),
        os.environ.get("HTTP_PROXY"),
        os.environ.get("http_proxy"),
    ):
        if p and p not in cands:
            cands.append(p)
    return cands


def run(cmd: list[str], cwd: Path | None = None, proxy: str | None = None,
        timeout: int = 120) -> str:
    env = dict(os.environ)
    for key in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "all_proxy"):
        env.pop(key, None)
    env["GIT_TERMINAL_PROMPT"] = "0"
    if proxy:
        env["http_proxy"] = env["https_proxy"] = proxy
    proc = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(f"命令失败: {' '.join(cmd)}\n{(proc.stderr or '')[-800:]}")
    return proc.stdout.strip()


def clone_sparse(corpus: Corpus, proxies: list[str | None], attempts: int = 2) -> Path:
    dest = CACHE / corpus.name
    if (dest / ".git").exists():
        # 缓存可能是「只建了 .git、还没 checkout 文件」的半成品，补一次 checkout
        try:
            run(["git", "sparse-checkout", "set", *corpus.subdirs.keys()], cwd=dest, timeout=300)
            if all((dest / s).exists() for s in corpus.subdirs):
                log(f"  [cache] 复用 {dest}")
                return dest
            log("  [cache] 内容不完整，重新克隆")
        except Exception:  # noqa: BLE001
            log("  [cache] checkout 失败，重新克隆")
        shutil.rmtree(dest, ignore_errors=True)

    last_err: Exception | None = None
    for round_ in range(attempts):
        for proxy in proxies:
            if dest.exists():
                shutil.rmtree(dest)
            dest.parent.mkdir(parents=True, exist_ok=True)
            label = proxy or "直连"
            log(f"  clone 尝试[{round_ + 1}] {label}")
            try:
                run(
                    ["git", "-c", "http.lowSpeedLimit=1000", "-c", "http.lowSpeedTime=25",
                     "clone", "--depth", "1", "--filter=blob:none", "--sparse",
                     corpus.repo, str(dest)],
                    proxy=proxy,
                )
                run(["git", "sparse-checkout", "set", *corpus.subdirs.keys()], cwd=dest,
                    proxy=proxy)
                log(f"  ✔ clone 成功（{label}）")
                return dest
            except Exception as exc:  # noqa: BLE001
                last_err = exc
                log(f"  ✘ 失败：{str(exc).splitlines()[0][:120]}")
                shutil.rmtree(dest, ignore_errors=True)
                time.sleep(1)
    raise RuntimeError(f"无法克隆 {corpus.repo}（直连和代理都失败）：{last_err}")


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
    repo_dir = clone_sparse(corpus, proxies)
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
