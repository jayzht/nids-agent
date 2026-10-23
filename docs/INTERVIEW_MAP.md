# Agent / RAG 岗位知识点地图

这个文件是项目的「面试导航」：每个知识点都对应到具体代码位置，方便你讲的时候直接翻。

## 一、RAG 基础链路

| 知识点 | 代码位置 | 面试常见问法 / 你要能说出的点 |
|---|---|---|
| 文档解析 | `app/ingest/loader.py` | MDX 里的 import/JSX/frontmatter 对检索全是噪音，怎么清洗；PDF 怎么处理（版面分析 vs 纯文本） |
| 分块策略 | `app/ingest/chunker.py` | 固定窗口 / 语义分块 / 结构分块各自适用场景；为什么代码块必须原子；chunk size 与召回的权衡 |
| 去重 | `chunk_documents()` | 内容指纹（normalize + sha1）；同一文档多语言版本重复问题 |
| 元数据 | `Chunk.heading_path / path / source_url` | 元数据为什么比 chunk 内容还重要：过滤、引用、排序、增量更新 |
| 建索引 | `app/retrieval/index.py` | 索引产物设计；为什么不序列化 BM25；embedding 模型升级怎么迁移 |

## 二、检索

| 知识点 | 代码位置 | 要点 |
|---|---|---|
| Embedding 选型 | `app/core/llm.py`, `settings.embedding_model` | bge-m3 vs nomic vs OpenAI：维度、多语言、成本、是否需要指令前缀 |
| 向量库 | `app/retrieval/vectorstore.py` | numpy vs Qdrant vs pgvector：HNSW 参数、过滤、水平扩展 |
| ANN 索引 | `QdrantVectorStore` | HNSW 的 M / ef_construct / ef_search 怎么调；召回与延迟 |
| 稀疏检索 | `app/retrieval/bm25.py` | BM25 公式、k1/b、IDF 平滑；中文要不要分词（bigram 折中） |
| 混合检索 | `KBIndex.hybrid_search()` | 为什么 RRF 比加权求和稳；两路召回深度（candidate_k）怎么定 |
| 多库融合 | `app/retrieval/service.py` | 跨库分数不可比 → 二次 RRF |
| 重排 | `app/retrieval/rerank.py` | 规则重排 vs cross-encoder；为什么要「多召回少入参」；rerank 的延迟成本 |
| 查询改写 | `agent/graph.py: node_rewrite` | 多查询（multi-query）、HyDE、跨语言改写；改写带来的召回 vs 噪音 |
| 检索评估 | `app/eval/metrics.py` | recall@k / MRR / nDCG 定义与差别；离线评估集怎么构造 |

## 三、Agent 编排（LangGraph）

| 知识点 | 代码位置 | 要点 |
|---|---|---|
| 图 vs 链 | `agent/graph.py` | 为什么 RAG 要用图：需要条件边和循环（重试/纠错） |
| 状态设计 | `agent/state.py` | TypedDict + reducer（`Annotated[list, add]`）；状态必须可序列化 |
| 条件边 | `route_after_grade / route_after_verify` | 把「决策」写成纯函数，便于单测和回放 |
| 循环与上限 | `max_retrieval_attempts`, `recursion_limit` | 没有上限的 Agent 循环 = 线上事故 |
| 检查点 / 记忆 | `MemorySaver` + `thread_id` | 多轮会话、断点续跑、时间旅行（replay）；生产换 PostgresSaver |
| 流式 | `RAGAgent.astream` | `stream_mode=["updates","messages"]`；节点级事件 vs token 级事件 |
| 工具调用 | `agent/tools.py`, `agent/react.py` | tool schema 设计、工具数量与选择准确率、工具返回值要给模型「下一步提示」 |
| 人机协同 | 未实现（见 ROADMAP） | `interrupt_before` + 人工审批；什么场景需要 |
| 多 Agent | 未实现 | supervisor / handoff / 共享状态；什么时候不该上多 Agent |

## 四、幻觉与可控性

| 知识点 | 代码位置 | 要点 |
|---|---|---|
| 引用生成 | `prompts.GENERATE_SYSTEM` | 编号由系统注入、禁止模型自造；引用粒度（块 vs 句） |
| 引用校验 | `node_verify` | 无引用 → 判 ungrounded → 强制重生成（一次） |
| 检索质量闸门 | `node_grade` | 相关性打分过滤；全不相关时拒答而不是硬答 |
| 拒答策略 | `prompts.NO_ANSWER` | 「不知道」是功能不是 bug；拒答文案要给下一步建议 |
| 越权/注入 | 未实现 | 文档里的 prompt injection；要加内容隔离与指令消毒 |

## 五、工程化

| 知识点 | 代码位置 | 要点 |
|---|---|---|
| FastAPI 异步 | `app/api/chat.py` | async 里不能有阻塞调用；`asyncio.to_thread` 的用法 |
| SSE 流式 | `event_stream()` | 事件协议设计、断线、`X-Accel-Buffering`、Nginx 超时 |
| 后台任务 | `app/api/kb.py` | 202 + 轮询 vs WebSocket vs 任务队列（Celery/Arq） |
| 依赖注入 | `app/deps.py` | 单例的构建时机；测试时怎么替换（`dependency_overrides`） |
| 配置管理 | `app/settings.py` | pydantic-settings、环境变量注入、不把密钥写进代码 |
| 日志/可观测 | `main.py` logging | 结构化日志、trace id、LangSmith 接入点 |
| 部署 | `Dockerfile`, `docker-compose.yml` | uvicorn workers、模型服务与 API 分离、Qdrant 持久化 |
| 成本优化 | `llm_fast_model` 设计 | 小模型做路由/打分，大模型只做最终生成；缓存 embedding |

## 六、高频追问（自测）

1. chunk 从 400 改成 800 token，recall 和成本分别怎么变？怎么验证？
2. RRF 的 k 取 60 是为什么？取 1 和取 1000 分别会怎样？
3. 为什么 rerank 只对 top-12 做，而不是对全部候选做？
4. LangGraph 的检查点和「对话历史」有什么区别？为什么不能只靠 messages？
5. Agent 陷入死循环怎么发现、怎么兜底？
6. 用户问「FastAPI 怎么限流」，文档里没有，系统应该怎么表现？
7. 怎么证明你的 RAG 比「直接把文档塞进 128k 上下文」更好？
8. 引用编号对不上怎么办？你怎么自动发现？
9. 索引更新时线上还在查询，怎么做到不停机？
10. 如果 embedding 模型从 bge-m3 换到别的，历史索引怎么办？
