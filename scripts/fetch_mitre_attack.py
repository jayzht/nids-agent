#!/usr/bin/env python3
"""把 MITRE ATT&CK（STIX 2.1）转成可检索的 Markdown。

为什么值得放进来：ATT&CK 是蓝队事实标准，安全岗面试必问「这个行为对应哪个技术/战术」。
STIX 是 JSON，直接丢给 RAG 没法用；转成「一个技术一篇文档」后，
检索「PowerShell 下载执行」就能命中 T1059.001 及其检测建议。

用法：
    python scripts/fetch_mitre_attack.py                 # 自动下载/复用缓存
    python scripts/fetch_mitre_attack.py --source /path/enterprise-attack.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from _net import clone_sparse, log, proxy_candidates  # noqa: E402

OUT = ROOT / "data" / "raw" / "ids" / "mitre"
CACHE = ROOT / "data" / ".cache" / "attack-stix"
REPO = "https://github.com/mitre-attack/attack-stix-data.git"


def slug(text: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "-", text.lower()).strip("-")
    return s[:60] or "x"


def attack_id(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return str(ref.get("external_id", ""))
    return ""


def ensure_source(explicit: str | None, proxies: list[str | None]) -> Path:
    if explicit:
        return Path(explicit).expanduser().resolve()
    cached = CACHE / "enterprise-attack" / "enterprise-attack.json"
    if cached.exists():
        return cached
    log("稀疏克隆 attack-stix-data（只取 enterprise-attack 目录）")
    clone_sparse(REPO, CACHE, ["enterprise-attack"], proxies)
    if not cached.exists():
        raise SystemExit(f"没有找到 {cached}")
    return cached


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default=None)
    ap.add_argument("--proxy", default=None)
    args = ap.parse_args()

    src = ensure_source(args.source, proxy_candidates(args.proxy))
    log(f"解析 {src} ({src.stat().st_size/1e6:.0f} MB)")
    objects = json.loads(src.read_text(encoding="utf-8"))["objects"]

    techniques = [
        o for o in objects
        if o.get("type") == "attack-pattern"
        and not o.get("revoked") and not o.get("x_mitre_deprecated")
        and attack_id(o)
    ]
    tactics = [
        o for o in objects
        if o.get("type") == "x-mitre-tactic" and not o.get("revoked")
    ]
    log(f"技术 {len(techniques)} 条，战术 {len(tactics)} 个")

    (OUT / "techniques").mkdir(parents=True, exist_ok=True)
    (OUT / "tactics").mkdir(parents=True, exist_ok=True)

    for o in techniques:
        tid = attack_id(o)
        phases = [p.get("phase_name", "") for p in o.get("kill_chain_phases", [])]
        platforms = o.get("x_mitre_platforms", [])
        lines = [
            f"# {tid} {o.get('name', '')}",
            "",
            f"> ATT&CK ID: {tid}",
            f"> 战术: {', '.join(phases) or 'unknown'}",
            f"> 平台: {', '.join(platforms) or 'unknown'}",
            f"> 类型: {'子技术' if o.get('x_mitre_is_subtechnique') else '技术'}",
            "",
            "## 描述",
            "",
            (o.get("description") or "").strip(),
            "",
        ]
        detection = (o.get("x_mitre_detection") or "").strip()
        if detection:
            lines += ["## 检测建议", "", detection, ""]
        path = OUT / "techniques" / f"{tid}-{slug(o.get('name', ''))}.md"
        path.write_text("\n".join(lines), encoding="utf-8")

    for t in tactics:
        ta_id = attack_id(t)
        short = t.get("x_mitre_shortname", "")
        related = [
            o for o in techniques
            if short in [p.get("phase_name") for p in o.get("kill_chain_phases", [])]
        ]
        lines = [
            f"# {ta_id} {t.get('name', '')}",
            "",
            f"> ATT&CK 战术: {ta_id}（{short}）",
            f"> 包含 {len(related)} 条技术",
            "",
            (t.get("description") or "").strip(),
            "",
            "## 相关技术",
            "",
        ]
        for o in sorted(related, key=lambda x: attack_id(x)):
            lines.append(f"- {attack_id(o)} {o.get('name', '')}")
        path = OUT / "tactics" / f"{ta_id}-{slug(t.get('name', ''))}.md"
        path.write_text("\n".join(lines), encoding="utf-8")

    total = len(techniques) + len(tactics)
    log(f"完成：{total} 篇 -> {OUT}")
    log("下一步: python scripts/fetch_domain_corpus.py --manifest-only && python scripts/build_index.py --kb ids")


if __name__ == "__main__":
    main()
