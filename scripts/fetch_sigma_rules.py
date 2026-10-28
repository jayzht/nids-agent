#!/usr/bin/env python3
"""把 Sigma 规则（YAML）转成可检索的 Markdown。

为什么值得放进知识库：Sigma 是检测工程的事实标准，面试常问「怎么检测 X 行为」。
但规则是 YAML，直接丢进向量库没法检索；转成「一条规则一篇文档」后，
既能按行为描述检索，也能把 detection 逻辑原样呈现。

用法：
    python scripts/fetch_sigma_rules.py                 # 用缓存/自动克隆
    python scripts/fetch_sigma_rules.py --limit 2000    # 只取前 N 条
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from _net import clone_sparse, log, proxy_candidates  # noqa: E402

REPO = "https://github.com/SigmaHQ/sigma.git"
CACHE = ROOT / "data" / ".cache" / "sigma"
OUT = ROOT / "data" / "raw" / "ids" / "sigma-rules"


def ensure_source(proxies: list[str | None]) -> Path:
    rules = CACHE / "rules"
    if rules.exists() and any(rules.rglob("*.yml")):
        return CACHE
    if CACHE.exists():
        shutil.rmtree(CACHE, ignore_errors=True)
    log("稀疏克隆 SigmaHQ/sigma（只取 rules 目录）")
    clone_sparse(REPO, CACHE, ["rules"], proxies)
    return CACHE


def render(rule: dict, src_rel: str) -> str:
    title = str(rule.get("title") or "Untitled rule").strip()
    lines = [f"# {title}", ""]
    meta = [
        f"Sigma ID: {rule.get('id', '')}",
        f"级别: {rule.get('level', '')}",
        f"状态: {rule.get('status', '')}",
    ]
    logsource = rule.get("logsource") or {}
    if isinstance(logsource, dict) and logsource:
        meta.append(
            "日志源: " + ", ".join(f"{k}={v}" for k, v in logsource.items() if v)
        )
    lines += [f"> {m}" for m in meta if m.split(": ", 1)[-1]]
    tags = rule.get("tags") or []
    if tags:
        lines.append("> 标签: " + ", ".join(str(t) for t in tags[:12]))
    lines += ["", f"> 源文件: {src_rel}", ""]

    desc = (rule.get("description") or "").strip()
    if desc:
        lines += ["## 描述", "", desc, ""]

    detection = rule.get("detection")
    if detection:
        lines += ["## 检测逻辑", "", "```yaml",
                  yaml.safe_dump(detection, allow_unicode=True, sort_keys=False).strip(),
                  "```", ""]

    fps = rule.get("falsepositives") or []
    if fps:
        lines += ["## 误报", ""] + [f"- {f}" for f in fps] + [""]

    refs = rule.get("references") or []
    if refs:
        lines += ["## 参考", ""] + [f"- {r}" for r in refs[:8]] + [""]

    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--proxy", default=None)
    args = ap.parse_args()

    src = ensure_source(proxy_candidates(args.proxy))
    rules_dir = src / "rules"
    files = sorted(rules_dir.rglob("*.yml"))
    if args.limit:
        files = files[: args.limit]
    log(f"发现 {len(files)} 条规则")

    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True, exist_ok=True)

    ok = bad = 0
    for f in files:
        try:
            rule = yaml.safe_load(f.read_text(encoding="utf-8", errors="ignore"))
        except Exception:  # noqa: BLE001
            bad += 1
            continue
        if not isinstance(rule, dict) or not rule.get("detection"):
            bad += 1
            continue
        rel = f.relative_to(rules_dir).with_suffix("").as_posix()
        target = OUT / f"{rel}.md"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(render(rule, rel + ".yml"), encoding="utf-8")
        ok += 1

    log(f"完成：{ok} 篇（跳过 {bad} 条无效/无 detection）-> {OUT}")


if __name__ == "__main__":
    main()
