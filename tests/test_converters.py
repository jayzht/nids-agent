"""格式转换器测试：三种格式各挑最容易出错的点。"""

from __future__ import annotations

from app.ingest.converters import html_to_markdown, rfc_to_markdown, rst_to_markdown


def test_rst_headings_use_underline_hierarchy():
    rst = """Title
=====

Section
-------

Sub
~~~
text
"""
    md = rst_to_markdown(rst)
    assert "# Title" in md
    assert "## Section" in md
    assert "### Sub" in md


def test_rst_code_block_becomes_fence():
    rst = """Example
=======

.. code-block:: python

    print("hi")
    x = 1
"""
    md = rst_to_markdown(rst)
    assert "```python" in md
    assert 'print("hi")' in md


def test_rst_admonition_becomes_blockquote():
    rst = """Title
=====

.. note::

    careful here
"""
    md = rst_to_markdown(rst)
    assert "> **Note**" in md
    assert "careful here" in md


def test_rst_toctree_and_roles_are_stripped():
    rst = """Title
=====

.. toctree::
   :maxdepth: 2

   other

See :ref:`some-label` for details, and ``inline`` code.
"""
    md = rst_to_markdown(rst)
    assert "toctree" not in md
    assert "maxdepth" not in md
    assert "some-label" in md
    assert "`inline`" in md


def test_rst_multiline_role_content():
    """Suricata 的规则示例里 role 会跨行，不能留下 :role: 残渣。"""
    rst = """Title
=====

.. container:: example-rule

  alert http any any -> any any (msg:"x"; \\
  :example-rule-options:`http.uri; content:"/a";`)
"""
    md = rst_to_markdown(rst)
    assert ":example-rule-options:" not in md
    assert 'content:"/a"' in md


def test_rfc_toc_is_not_treated_as_headings():
    rfc = """RFC 793          Transmission Control Protocol       September 1981

                          TABLE OF CONTENTS

   1.  INTRODUCTION ..................................................... 1
   1.1  Motivation ..................................................... 1
   [Page 1]

                            1.  INTRODUCTION

The Transmission Control Protocol is intended for use.

                            1.1  Motivation

Some motivation text.
"""
    md = rfc_to_markdown(rfc, 793, "Transmission Control Protocol")
    assert md.startswith("# RFC 793: Transmission Control Protocol")
    assert "INTRODUCTION ....." not in md
    assert "## 1. INTRODUCTION" in md or "## 1 INTRODUCTION" in md
    assert "### 1.1 Motivation" in md
    assert "[Page 1]" not in md


def test_html_to_markdown_keeps_text_and_drops_scripts():
    html = """
    <html><body>
      <script>alert(1)</script>
      <nav>menu</nav>
      <article><h2>Detection</h2><p>Use <code>http.uri</code>.</p>
        <math alttext="x^2"><mi>x</mi></math></article>
    </body></html>
    """
    md = html_to_markdown(html, title="Paper", meta_lines=["arXiv: 2501.00001"])
    assert "# Paper" in md
    assert "> arXiv: 2501.00001" in md
    assert "Detection" in md
    assert "http.uri" in md
    assert "alert(1)" not in md
    assert "x^2" in md
