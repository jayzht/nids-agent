"""PDF 转换的纯函数测试（不依赖真实 PDF）。"""

from __future__ import annotations

from app.ingest.pdf import _clean_lines, _reflow


def test_clean_lines_drops_page_numbers_and_headers():
    lines = [
        "51 / 499",
        "[MS-SMB2] - v20260928",
        "Copyright © 2026 Microsoft Corporation",
        "HashAlgorithmCount (2 bytes): The number of hash algorithms.",
        "",
        "SaltLength (2 bytes): The size of the Salt field.",
    ]
    out = _clean_lines(lines, (r"^\[MS-SMB2\]", r"^Copyright ©"))
    assert "51 / 499" not in out
    assert all("[MS-SMB2]" not in x for x in out)
    assert any("HashAlgorithmCount" in x for x in out)


def test_reflow_joins_midsentence_breaks():
    lines = ["This value MUST be greater than", "zero and less than the limit.", ""]
    text = _reflow(lines)
    assert "greater than zero" in text


def test_reflow_keeps_bullets_and_headings_separate():
    lines = ["Introduction", "- first item", "- second item"]
    text = _reflow(lines)
    assert text.splitlines() == ["Introduction", "- first item", "- second item"]


def test_reflow_joins_hyphenated_words():
    lines = ["The HashAlgo-", "rithm field."]
    assert "HashAlgorithm field." in _reflow(lines)


def test_reflow_collapses_blank_lines():
    assert "\n\n\n" not in _reflow(["a.", "", "", "b."])
