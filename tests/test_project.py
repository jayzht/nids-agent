"""项目级测试：评估集质量、脚本健壮性、分块兜底。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def test_dataset_rows_are_well_formed():
    ids = set()
    for line in (ROOT / "app" / "eval" / "dataset.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        assert row["id"] not in ids, f"重复 id: {row['id']}"
        ids.add(row["id"])
        assert row["kb"] in {"fastapi", "langgraph", "pydantic", "ids"}
        assert row["question"] and row["search_query"]
        assert row["expected_docs"], f"{row['id']} 没有期望文档"


def test_dataset_covers_all_kbs():
    kbs = set()
    for line in (ROOT / "app" / "eval" / "dataset.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            kbs.add(json.loads(line)["kb"])
    assert {"fastapi", "langgraph", "pydantic", "ids"} <= kbs


def test_copy_docs_ignores_non_markdown(tmp_path, monkeypatch):
    """回归测试：fetch_corpus 重构后一度漏了 import shutil。"""
    from scripts import fetch_corpus as fc

    repo = tmp_path / "repo"
    (repo / "docs").mkdir(parents=True)
    (repo / "docs" / "a.md").write_text("# A\n\nbody", encoding="utf-8")
    (repo / "docs" / "img.png").write_bytes(b"\x89PNG")
    corpus = fc.Corpus(name="t", repo="x", title="t", description="",
                       url_template="", subdirs={"docs": ""})
    monkeypatch.setattr(fc, "RAW", tmp_path / "raw")
    n = fc.copy_docs(corpus, repo)
    assert n == 1
    assert (tmp_path / "raw" / "t" / "a.md").exists()


def test_chunker_falls_back_to_doc_title_for_generic_headings():
    from app.ingest.chunker import chunk_document
    from app.ingest.types import Document

    doc = Document(
        doc_id="d", kb="ids", path="mitre/T1059.001.md",
        title="T1059.001 PowerShell",
        text="# T1059.001 PowerShell\n\n## 描述\n\nAdversaries may abuse PowerShell commands.",
    )
    chunks = chunk_document(doc)
    assert chunks
    assert chunks[0].embed_text.startswith("T1059.001 PowerShell")
