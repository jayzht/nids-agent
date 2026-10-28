# 进阶路线（做成「你自己的项目」该往哪走）

这个仓库已经能跑通全链路，但作为简历项目，**最怕的是「一看就是抄的」**。
下面按「性价比」排序，做 3~5 个就足够撑起一场 40 分钟的深聊。

## A. 必做（1~2 天，直接提升面试通过率）

1. ✅ **换一个你自己的领域语料**（已完成：`ids` 库，Suricata/Zeek/nDPI + RFC + arXiv，538 篇）
   原始建议：
   现在的语料是技术文档，回答的是「框架怎么用」。建议再加一个非技术知识库（法律法规 / 医疗指南 / 公司制度 / 论文），
   只要 Markdown/PDF 都能进 `data/raw/<kb>/`。领域知识库能让你讲「业务」，而不只是「框架」。
   命令：`python scripts/fetch_corpus.py --only xxx` 或直接把文件丢进 `data/raw/<kb>/` 后 `POST /api/kbs`。

2. **接 LangSmith / OpenTelemetry**
   环境变量 `LANGCHAIN_TRACING_V2=true` + `LANGCHAIN_API_KEY`，把每个节点的输入输出、token 数、耗时打上去。
   面试时能说「我怎么定位一次慢查询」比「我知道 LangSmith」值钱得多。

3. ~~把检查点从内存换成 SQLite / Postgres~~ ✅ **已完成**
   `MemorySaver` → `AsyncSqliteSaver`（`langgraph-checkpoint-sqlite`），落 `data/checkpoints.sqlite`；
   已实测「杀掉进程、重启、用同一 `session_id` 追问，记忆还在」。
   这一步能讲清 checkpointer 与 messages 的区别：messages 只是状态里的一个字段，
   checkpointer 存的是**整个图状态在每个 super-step 的快照**，所以能断点续跑和时间旅行。

## B. 加分（3~5 天，拉开与「调包侠」的差距）

4. **真正的 cross-encoder 重排**
   现在 `rerank.py` 只有规则版。换成 `bge-reranker-v2-m3`（或 Cohere Rerank），
   对比「有/无 rerank」在 golden set 上的 nDCG 差异，把数字写进 README。

5. **增量索引**
   现在改一篇文档要全量重建。用 `chunk 内容指纹` 做 diff：只重算变化的片段，
   并支持「索引版本号 + 原子切换」，做到更新期间线上可查。

6. **多路召回**
   加一路「标题/关键词精确匹配」（title index）和一路「HyDE」（让 LLM 先写假设答案再检索），
   在评测集上验证哪一路对哪类问题有效。

7. **父子检索（small-to-big）**
   小块用于召回，命中后用父块（整节）喂给 LLM。对比「只有小块」的回答完整度。

8. **query 层面的路由**
   已经有 router，但只做了「闲聊 vs 提问」。再加：代码类问题 → 偏好带代码块的片段；
   版本类问题 → 过滤 release notes；「和 X 的区别」→ 强制多文档检索。

## C. 工程/规模（有时间再说）

9. **Qdrant 真正跑起来**：`docker compose up -d qdrant` + `VECTOR_BACKEND=qdrant`，做一次 10w 片段压测。
10. **uvicorn 多 worker + 压测**：locust/k6 打 `/api/chat`，给出 P95 延迟与 QPS，找出瓶颈（LLM 还是检索）。
11. **鉴权与多租户**：API Key + KB 级 ACL，讲清「谁能查哪个库」。
12. **结构化输出与工具协议**：把工具改成 MCP server 形式，说明为什么 MCP 比自定义 tool schema 更通用。
13. **human-in-the-loop**：用 `interrupt_before` 做一个「危险工具需人工确认」的流程演示。

## D. 评估进阶

14. **扩充 golden set 到 100+ 题**，按类型分桶（是什么 / 怎么做 / 为什么报错 / 对比），分桶看 recall。
15. **引入 RAGAS 对比**：把自研指标与 RAGAS 的 faithfulness 对齐，解释口径差异。
16. **失败分析**：把每次低分 case 归类（检索没召回 / 召回但排序错 / 召回对但生成跑偏），
    在 README 里贴一张失败归因表 —— 这是最能体现工程素养的部分。

## E. 写进简历的模板

> **DevRAG · 文档智能问答 Agent**（个人项目）
> - 基于 LangGraph 搭建 Corrective RAG 工作流（路由 → 多查询改写 → 混合检索 → LLM 相关性打分 → 带引用生成 → 引用校验回环），
>   在 28 题自建 golden set 上 recall@6 **0.89**、MRR **0.76**、nDCG@6 **0.79**；
> - 实现 Markdown 结构化分块（标题面包屑 + 代码块原子化 + 跨文档去重），并定位到「文档 H1 与产品名相同导致向量空间 hubness」的问题，
>   通过短标题策略使 Top-1 命中率显著提升；
> - 检索层实现 BM25 + bge-m3 双路召回与可切换融合（RRF / 归一化加权），用自建 sweep 脚本扫参选型；
> - FastAPI + SSE 流式输出，节点级 trace 前端可视；Ollama 本地推理零 API 成本，支持任意 OpenAI 兼容后端。
