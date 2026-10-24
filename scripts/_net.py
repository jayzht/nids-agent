"""脚本共用的网络工具：GitHub 经常时通时不通，所有拉取都要「直连 / 代理」双通道重试。

代理优先级：显式传入 > GIT_PROXY > HTTPS_PROXY 等环境变量。
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time

import httpx


def log(msg: str) -> None:
    print(msg, flush=True)


def proxy_candidates(cli_proxy: str | None = None) -> list[str | None]:
    """显式 --proxy 时它优先；否则直连优先，再逐个尝试环境里的代理。"""
    cands: list[str | None] = [cli_proxy, None] if cli_proxy else [None]
    for p in (
        os.environ.get("GIT_PROXY"),
        os.environ.get("HTTPS_PROXY"),
        os.environ.get("https_proxy"),
        os.environ.get("HTTP_PROXY"),
        os.environ.get("http_proxy"),
    ):
        if p and p not in cands:
            cands.append(p)
    return cands


def _clean_env(proxy: str | None) -> dict[str, str]:
    env = dict(os.environ)
    for key in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "all_proxy"):
        env.pop(key, None)
    env["GIT_TERMINAL_PROMPT"] = "0"
    if proxy:
        env["http_proxy"] = env["https_proxy"] = proxy
    return env


def run(
    cmd: list[str], cwd=None, proxy: str | None = None, timeout: int = 120
) -> str:
    proc = subprocess.run(
        cmd, cwd=cwd, env=_clean_env(proxy), capture_output=True, text=True, timeout=timeout
    )
    if proc.returncode != 0:
        raise RuntimeError(f"命令失败: {' '.join(cmd)}\n{(proc.stderr or '')[-800:]}")
    return proc.stdout.strip()


def clone_sparse(
    repo: str,
    dest,
    subdirs: list[str],
    proxies: list[str | None],
    attempts: int = 2,
    sparse: bool = True,
) -> None:
    """克隆仓库。sparse=True 时只取文档目录（blobless + sparse-checkout），仓库再大也很快。"""
    from pathlib import Path

    dest = Path(dest)
    if (dest / ".git").exists():
        try:
            run(["git", "sparse-checkout", "set", *subdirs], cwd=dest, timeout=300)
            if all((dest / s).exists() for s in subdirs if s):
                log(f"  [cache] 复用 {dest.name}")
                return
            log("  [cache] 内容不完整，重新克隆")
        except Exception:  # noqa: BLE001
            log("  [cache] checkout 失败，重新克隆")
        shutil.rmtree(dest, ignore_errors=True)

    if not sparse:
        if (dest / ".git").exists():
            log(f"  [cache] 复用 {dest.name}")
            return
        for round_ in range(attempts):
            for proxy in proxies:
                if dest.exists():
                    shutil.rmtree(dest)
                dest.parent.mkdir(parents=True, exist_ok=True)
                log(f"  clone 尝试[{round_ + 1}] {proxy or '直连'}")
                try:
                    run(["git", "-c", "http.lowSpeedLimit=1000", "-c", "http.lowSpeedTime=25",
                         "clone", "--depth", "1", repo, str(dest)], proxy=proxy)
                    log("  ✔ clone 成功")
                    return
                except Exception as exc:  # noqa: BLE001
                    log(f"  ✘ 失败：{str(exc).splitlines()[0][:120]}")
                    shutil.rmtree(dest, ignore_errors=True)
                    time.sleep(1)
        raise RuntimeError(f"无法克隆 {repo}")

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
                     "clone", "--depth", "1", "--filter=blob:none", "--sparse", repo, str(dest)],
                    proxy=proxy,
                )
                if subdirs:
                    run(["git", "sparse-checkout", "set", *subdirs], cwd=dest, proxy=proxy)
                log(f"  ✔ clone 成功（{label}）")
                return
            except Exception as exc:  # noqa: BLE001
                last_err = exc
                log(f"  ✘ 失败：{str(exc).splitlines()[0][:120]}")
                shutil.rmtree(dest, ignore_errors=True)
                time.sleep(1)
    raise RuntimeError(f"无法克隆 {repo}（直连和代理都失败）：{last_err}")


def http_get(
    url: str,
    proxies: list[str | None],
    retries: int = 2,
    timeout: float = 60.0,
    headers: dict[str, str] | None = None,
) -> str:
    """带双通道重试的 GET，返回文本。"""
    last_err: Exception | None = None
    for _ in range(retries):
        for proxy in proxies:
            try:
                with httpx.Client(
                    proxy=proxy, timeout=timeout, follow_redirects=True,
                    headers={"User-Agent": "DevRAG-corpus-bot/1.0 (research)"} | (headers or {}),
                ) as client:
                    resp = client.get(url)
                    resp.raise_for_status()
                    return resp.text
            except Exception as exc:  # noqa: BLE001
                last_err = exc
                time.sleep(1)
    raise RuntimeError(f"下载失败 {url}: {last_err}")
