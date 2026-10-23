"""ReAct Agent 的工具集。

工具是 Agent 的「手」：这里暴露三个粒度不同的工具，
让模型自己决定「先看有哪些库 → 换关键词多搜几次 → 需要时读整篇」。
"""

from __future__ import annotations

from langchain_core.tools import tool

from app.core.text import truncate
from app.kb import KBManager
from app.retrieval.service import Retriever


def build_tools(retriever: Retriever, manager: KBManager) -> list:
    @tool
    async def list_knowledge_bases() -> str:
        """列出当前可用的知识库（名称、标题、文档数、片段数）。不确定问题属于哪个库时先调用它。"""
        metas = manager.list_meta()
        if not metas:
            return "当前没有可用的知识库。"
        return "\n".join(
            f"- {m['name']}：{m['title']}（{m['num_docs']} 篇文档 / {m['num_chunks']} 个片段）— {m['description']}"
            for m in metas
        )

    @tool
    async def search_knowledge_base(query: str, kb: str = "") -> str:
        """在知识库中做「向量 + BM25」混合检索，返回最相关的文档片段。

        Args:
            query: 检索关键词或整句问题，中英文都可以。保留 API 名、类名、报错信息效果更好。
            kb: 可选，知识库名称；留空表示在所有知识库中检索。
        """
        hits = await retriever.search(query, kbs=[kb] if kb else None, k=6)
        if not hits:
            return f"没有检索到与「{query}」相关的片段。可以换关键词，或先用 list_knowledge_bases 确认知识库。"
        lines = [f"检索到 {len(hits)} 个片段："]
        for i, h in enumerate(hits, 1):
            c = h.chunk
            lines.append(
                f"\n[{i}] kb={c.kb} | {c.heading_path or c.title} | path={c.path} | doc_id={c.doc_id}"
                f"\n{truncate(c.text, 900)}"
            )
        return "\n".join(lines)

    @tool
    async def read_document(doc_id: str, kb: str = "") -> str:
        """读取某个文档的完整内容（当片段不够、需要上下文时使用）。

        Args:
            doc_id: 文档 id，来自 search_knowledge_base 返回的 doc_id。
            kb: 可选，文档所在知识库；留空则在所有库中查找。
        """
        names = [kb] if kb else manager.names()
        for name in names:
            try:
                doc = await retriever.get_document(name, doc_id)
            except KeyError:
                continue
            if doc:
                return f"doc_id={doc_id} kb={name} path={doc['path']}\n\n{truncate(doc['text'], 6000)}"
        return f"没有找到 doc_id={doc_id} 对应的文档。"

    return [list_knowledge_bases, search_knowledge_base, read_document]
