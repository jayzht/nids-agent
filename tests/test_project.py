"""项目级测试：评估集质量、脚本健壮性、分块兜底。"""

from __future__ import annotations

import json
from pathlib import Path

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


def test_binetflow_parse_and_flow_metrics():
    """CTU-13 标注解析 + 流级混淆矩阵（含反向匹配、坏行跳过）。"""
    from app.eval.labeled import flow_metrics, parse_binetflow

    text = "\n".join([
        "StartTime,Dur,Proto,SrcAddr,Sport,DstAddr,Dport,State,sTos,dTos,TotPkts,TotBytes,SrcBytes,Label",
        "2011-08-10 10:00:00.100000,1.0,TCP,147.32.84.165,6667,147.32.84.164,1024,S_RA,0,0,3,120,60,flow=From-Botnet-V42-TCP",
        "2011-08-10 10:00:01.200000,0.5,TCP,147.32.84.165,6667,147.32.84.164,1025,S_RA,0,0,4,220,110,flow=From-Botnet-V42-TCP",
        "2011-08-10 10:00:02.300000,0.4,UDP,147.32.84.160,53,8.8.8.8,53,S_RA,0,0,2,180,90,flow=Background",
        "坏的,行,少字段",
    ])
    flows = parse_binetflow(text)
    assert len(flows) == 3, "表头 + 坏行都要跳过"
    assert sum(f.malicious for f in flows) == 2
    assert flows[0].start_ts > 0

    # 只命中第一条（正向），第二条不该被算进去；反向五元组也要能匹配
    m = flow_metrics(flows, {("147.32.84.165", 6667, "147.32.84.164", 1024)})
    assert (m["tp"], m["fn"], m["fp"], m["tn"]) == (1, 1, 0, 1)
    reversed_hit = flow_metrics(flows, {("147.32.84.164", 1024, "147.32.84.165", 6667)})
    assert reversed_hit["tp"] == 1

    # 命中正常流算误报
    m2 = flow_metrics(flows, {("147.32.84.160", 53, "8.8.8.8", 53)})
    assert m2["fp"] == 1 and m2["false_positive_rate"] == 1.0
