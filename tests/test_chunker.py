"""分块器测试：这些 case 就是线上真正会踩的坑。"""

from __future__ import annotations

from app.ingest.chunker import chunk_document, chunk_documents, pack_blocks, split_sections
from app.ingest.types import Document


def make_doc(text: str, path: str = "tutorial/test.md") -> Document:
    return Document(doc_id="d1", kb="kb", path=path, title="Test Doc", text=text)


def test_split_sections_builds_heading_path():
    text = "# Title\n\nintro\n\n## Install\n\npip install x\n\n### Note\n\ncareful"
    sections = split_sections(text)
    paths = [s.heading_path for s in sections]
    assert paths == ["Title", "Title > Install", "Title > Install > Note"]


def test_heading_inside_code_fence_is_not_a_heading():
    text = "# Real\n\n```bash\n# this is a comment, not a heading\napt install y\n```\n\nbody"
    sections = split_sections(text)
    assert len(sections) == 1
    assert sections[0].heading_path == "Real"
    assert "apt install y" in sections[0].body


def test_code_block_never_split_across_chunks():
    code = "```python\n" + "\n".join(f"x{i} = {i}" for i in range(120)) + "\n```"
    text = f"# Doc\n\nintro line\n\n{code}\n\nafter"
    chunks = chunk_document(make_doc(text), max_tokens=80, overlap_tokens=10)
    # 超大代码块一定会被切开，但每一片都要自带成对围栏，不能出现半截代码
    for c in chunks:
        assert c.text.count("```") % 2 == 0, f"围栏不成对: {c.text[:60]!r}"
    code_chunks = [c for c in chunks if "x0 = 0" in c.text]
    assert code_chunks and "```python" in code_chunks[0].text
    all_code = "\n".join(c.text for c in chunks if "```" in c.text)
    assert "x119 = 119" in all_code


def test_chunk_has_breadcrumb_and_metadata():
    chunks = chunk_document(make_doc("# A\n\n## B\n\ncontent here that is long enough to pass"))
    assert chunks[0].heading_path == "A > B"
    assert chunks[0].embed_text.startswith("A > B")  # 文档标题不进前缀，避免 hubness
    assert chunks[0].source_url == ""  # 未配置 url_template 时为空


def test_dedup_across_documents():
    body = "# Same\n\n" + "identical content " * 40
    docs = [make_doc(body, "a.md"), make_doc(body, "b.md")]
    chunks, dup = chunk_documents(docs, max_tokens=500, overlap_tokens=0)
    assert len(chunks) == 1
    assert dup == 1


def test_pack_blocks_overlap_and_progress():
    blocks = ["a" * 400, "b" * 400, "c" * 400]
    out = pack_blocks(blocks, max_tokens=300, overlap_tokens=50)
    assert len(out) >= 3
    assert all(out)


def test_tiny_sections_are_dropped():
    chunks = chunk_document(make_doc("# T\n\nok\n\n## Nav\n\nnext\n"))
    assert all(c.tokens >= 12 for c in chunks)
