# DevRAG 设计文档：它是怎么做的

> 这份文档讲**实现**，不讲卖点。读者是想改它、复现它、或者面试前把细节捋一遍的人。
> 快速上手看 [`README.md`](../README.md)；评测数字的出处见
> [`REAL_TRAFFIC_BENCHMARK.md`](REAL_TRAFFIC_BENCHMARK.md)、[`LABELED_EVAL.md`](LABELED_EVAL.md)。

---

## 0. 一句话概括

一个**双领域**（技术文档 + 网络流量检测）的 RAG 系统：

```
文档/日志/pcap ──▶ 统一分块与索引 ──▶ 混合检索（BM25 + 向量 + 重排）
                                              │
                                              ▼
                        LangGraph 编排的 Agent（问答 / 流量取证 / 多 Agent 融合）
                                              │
                                              ▼
                        带引用的答案 · 带证据的技术报告 · SIEM 告警与研判
```

规模：`app/` 约 8.3k 行，17 个测试文件（174 个用例），23 个脚本，知识库 5,839 篇 / 49,044 片段。

---

## 1. 分层与数据流

```
┌──────────────────────────── 接入层 app/ingest ────────────────────────────┐
│ loader（发现文件） → converters（RST/HTML/RFC/PDF → Markdown） → chunker  │
│                                    │                                      │
│                          结构化分块：按标题切、代码块原子、标题面包屑      │
└────────────────────────────────────┼──────────────────────────────────────┘
                                     ▼
┌──────────────────────────── 索引层 app/retrieval ─────────────────────────┐
│ chunker 产物 → embedder（bge-m3, 1024 维）→ numpy/qdrant 向量库           │
│                    └→ BM25（手写）→  内存倒排                             │
│ 落盘：data/index/<kb>/{vectors.npy, ids.json, chunks.jsonl, meta.json}     │
└────────────────────────────────────┼──────────────────────────────────────┘
                                     ▼
┌────────────────────── 检索层 app/retrieval/service.py ────────────────────┐
│ 查询改写 → 多路召回（dense ∥ sparse）→ 融合（normalized/RRF）             │
│        → 后处理（同文档限流 / 碎片过滤）→ 重排（none|lexical|local|http|llm）│
└────────────────────────────────────┼──────────────────────────────────────┘
                                     ▼
┌──────────────────────── 编排层 app/agent ─────────────────────────────────┐
│ graph.py          文档问答：router→chat|rewrite→retrieve→grade→generate→verify│
│ traffic_graph.py  pcap 取证：load→triage→collect→ground→report→verify      │
│ fusion_graph.py   多 Agent：behavior ∥ signature → fuse → attack → …      │
│ checkpointer.py   记忆：AsyncSqliteSaver + 保留期清理                      │
└────────────────────────────────────┼──────────────────────────────────────┘
                                     ▼
┌─────────────────── 服务层 app/api + app/web ──────────────────────────────┐
│ SSE 流式（step/token/final）· KB 管理 · 评测 · 流量分析 · SIEM 告警/研判   │
└───────────────────────────────────────────────────────────────────────────┘
```

**为什么这么分**：`ingest` 只认识文件，`retrieval` 只认识片段，`agent` 只认识检索到的证据，
`api` 只认识事件流。任何一层要换实现（换成 Qdrant、换成云端重排、换掉某个图），
都不需要动别的层。

---

## 2. 关键设计决策（每条都有代价）

### 2.1 按结构分块，不按字符数切

- **做法**（`app/ingest/chunker.py`）：按 Markdown 标题层级切；代码围栏整体保留，
  超长才在内部按行切；每个片段带 `heading_path`（如 `Engines > Protocol detection`）。
- **为什么**：字符切分会把「函数签名」和「参数说明」切到两个片段里，检索命中一个、
  模型看不到另一个。标题面包屑还能让 API 名（`http.user_agent`）参与检索。
- **代价**：片段大小不均（有的 1k token，有的 50），对 embedding 的批量效率不友好。
- **踩过的坑**：文档 H1 等于产品名（如 `FastAPI`）时，每个片段都带这个前缀，
  整篇文档在向量空间里变成「万能命中」的 hub。`short_heading()` 丢掉与文档标题
  相同的一级标题，只保留最近两层。

### 2.2 混合检索 + normalized 融合

- **做法**：dense（bge-m3 余弦）与 sparse（手写 BM25）各自 min-max 后加权，
  `bm25_weight=0.2`；也保留 RRF 作为可切换实现。
- **为什么**：纯向量丢精确词（`T1048.003`、`HTTPBearer`、`--max-tokens`），
  纯 BM25 丢语义（中文问「怎么发现隧道」匹配不到 `dns.query.name`）。
- **代价**：归一化融合对**候选池大小敏感**——把池子从 20 扩到 60，MRR 掉了 0.03。
  这是实测踩到的（见 §7），不是理论担心。
- **代码**：`app/retrieval/index.py::hybrid_search`。

### 2.3 重排：用 cross-encoder，且输入要「喂对」

- **做法**：`RERANK_MODE=none|lexical|local|http|llm`；本地用 `transformers` 裸调用
  （不用 `sentence-transformers` 的 CrossEncoder），passage = `heading_path + 正文`，
  融合分与 CE 分 min-max 后按 `RERANK_BLEND=0.5` 混合。
- **为什么**：CrossEncoder 会给部分模型自动套 prompt，把排序搞反；`heading_path`
  里才有 API 名这类强信号；纯 CE 分（blend=0）明显更差（MRR 0.841 vs 0.895）。
- **代价**：本地 CPU 3~5 秒/次。所以默认走云端（200ms），`local` 作为离线选项。
- **代码**：`app/retrieval/rerank.py`。

### 2.4 检索后处理：限流、过滤、补邻居

| 后处理 | 参数 | 解决什么 |
|---|---|---|
| 同文档限流 | `MAX_PER_DOC=5` | 论文有 70+ 片段且 heading 全是论文标题，一篇能占掉 6 个坑位里的 4 个 |
| 碎片过滤 | `MIN_CHUNK_TOKENS=32` | 作者列表、目录残行这类片段没有信息量 |
| 相邻片段补全 | `CONTEXT_NEIGHBORS=1`，只补 top-1 | 跨节问题（「detection 和 condition 什么关系」）两节各讲一半 |

**代价**：补得太猛会稀释 context——补 top-3 时 faithfulness 0.896 → 0.808，
所以只补 top-1（0.871，citation_precision 仍从 0.400 升到 0.430）。

### 2.5 RAG 图：先判「能不能答」，再答

```
router ─┬─ chat ──────────────────────────────────────────────▶ END
        └─ rewrite → retrieve → grade ─┬─ generate → verify ─┬─ generate（重试）
                                       │                      └─ finalize → END
                                       ├─ rewrite（改写重试，有上限）
                                       └─ no_answer → END
```

- **为什么需要 `grade`**：检索到东西 ≠ 能回答。grade 用 LLM 逐片段打 0/1/2 分，
  全 0 就直接回「知识库没有」，避免编造。
- **踩过的坑**：prompt 写「严格一点，宁可给 0」后，大量「能靠背景回答」的问题被判 0，
  用户体感是「怎么什么都没找到」。改成「只有完全无关才判 0」后：
  keyword_coverage 0.917 → 1.000，relevance 0.821 → 0.838，faithfulness 只掉 0.008
  （因为还有 verify 兜底）。**闸门该拦「编造」，不是「不完整」。**
- **三道闸**：grade（相关性）、verify（引用编号是否存在/是否编造）、citation 校验
  （最终答案里的 `[n]` 必须对应真实片段）。

### 2.6 多 Agent 融合：并行 fan-out，不是一个 supervisor

```
        ┌─ behavior  （规则引擎：扫描/爆破/隧道/心跳/…）─┐
load ──┤                                                ├── fuse ─→ attack ─→ ground ─→ report ─→ verify ─→ finalize
        └─ signature （Suricata + 5.2 万条 ET 规则）─────┘
```

- **为什么是「并行 + 归并」而不是 supervisor**：两个检测器**互不依赖**，串行只是白等；
  融合逻辑（`app/signature/fusion.py`）按 (ip, port) 端点对齐、按阶段归并
  （侦察/凭据攻击/漏洞利用/C2/外传），并对 ET INFO 类规则降级。
- **收益**：真实样本上行为单独 10/30、签名补足到 30/30；两引擎盲区几乎不重叠。

### 2.7 确定性优先：能算出来的结论不交给模型

- 规则引擎（`app/traffic/analyzer.py`，14 个检测器）产出**结构化 finding**：
  `kind / severity / title / detail / metrics / evidence(帧号)`。
- LLM 只负责「把这些证据组织成可读报告」和「给出处置建议」，且报告要过
  `validate_report`（引用编号存在、数字与 finding 一致）。
- **代价**：规则阈值是人工定的，会漏低频攻击（见 §7 的 Rbot 案例）。

### 2.8 载荷级检测：请求体单独走 JSON 输出

- **做法**：`read_http_bodies()` 用 `tshark -T json` 单独抽 HTTP 请求体（只读前 4KB、
  最多 60 条），用 9 条公开利用特征匹配（XMLDecoder / `${jndi:` / OGNL / XXE /
  `/wls-wsat/` / Java 序列化魔术字节 …），映射 T1190/T1059。
- **为什么不用 `-T fields`**：body 里有换行就会把行切碎，后面的字段全部错位。
- **收益**：WebLogic 那份「12 个包、ET 没有规则」的样本从漏检变成命中，真实样本 29/30 → 30/30。

### 2.9 记忆：异步检查点 + 保留期

- **做法**：`AsyncSqliteSaver` 落 `data/checkpoints.sqlite`，启动时 `setup()` 建表，
  关闭时释放；`CHECKPOINT_BACKEND=memory` 可退回内存（测试/脚本用，不产生文件）。
- **为什么必须异步版**：四个图都是 `astream`/`aget_state`，同步 `SqliteSaver`
  没实现异步接口，直接不可用。
- **保留期**：`checkpoint_id` 是 **UUIDv6**（前 60 bit 是时间戳、字典序等于时间序），
  所以 `MAX(checkpoint_id) < 阈值` 就能在 SQL 里筛闲置会话，不用加时间列。
- **验证方式**：发一轮 → `kill` 掉 uvicorn → 重启 → 同 `session_id` 追问，仍记得上下文。

### 2.10 评测与代码解耦：一种格式一次，一个数据集零次

```
任意数据集 ──▶ 格式转换器 ──▶ 规范化流 {src,sport,dst,dport,label} ──▶ 评测器
              （按格式，不按数据集）        （唯一契约）              （永不改）
```

| 格式 | 转换器覆盖 | 新增数据集代价 |
|---|---|---|
| `binetflow` | CTU-13（13 场景）+ CTU-Malware-Capture（411 个抓包） | 0 行 |
| `zeek_conn` | IoT-23（23 场景） | 0 行 |
| `csv`（`--columns`） | 一类有标注但无固定格式的 flow CSV | 仅参数 |

格式按文件头自动识别，标签用词表归一（`flow=From-Botnet-…` / `C&C-HeartBeat` /
`Malicious` 都映射成恶意）。**代码**：`app/eval/formats.py`。

---

## 3. 模块逐个讲

### 3.1 语料接入 `app/ingest/`

| 文件 | 职责 | 关键函数 |
|---|---|---|
| `loader.py` | 发现文件、按扩展名分派 | `load_documents()` |
| `converters.py` | RST / HTML / RFC 转 Markdown | `rst_to_markdown`, `html_to_markdown`, `rfc_to_markdown` |
| `pdf.py` | PDF → 文本行 → 段落回流 | `pdf_to_markdown`, `_clean_lines`, `_reflow` |
| `chunker.py` | 结构化分块、去重、指纹 | `chunk_documents()` |
| `types.py` | `Document` / `Chunk` 数据结构 | `Chunk.seq` 用于相邻片段 |

PDF 的处理要点：丢掉页码/页眉行、把被硬换行切断的句子接回来、连字符断词合并。
不做 OCR（扫描版 PDF 直接跳过并在建库报告里计数）。

### 3.2 索引与检索 `app/retrieval/`

| 文件 | 职责 |
|---|---|
| `bm25.py` | 手写 BM25（k1=1.5, b=0.75），中英文混合分词 |
| `vectorstore.py` | numpy（默认，单文件 `.npy`）与 Qdrant 两种后端 |
| `index.py` | `KBIndex`：`hybrid_search()`、`dense_search()`、`sparse_search()`、`neighbors()` |
| `service.py` | `Retriever.search()`：多库并行召回 + RRF 跨库融合 + `diversify()` + 重排 |
| `rerank.py` | 五种重排实现 + 统一的 `_blend_and_rank()` |

检索路径（一次 `search()`）：

1. `retrieval_mode=sparse` 时跳过 embedding；否则 `embed_query()`（带 LRU 缓存）；
2. 每个目标库并行 `hybrid_search(query, qvec, candidate_k)`；
3. 多库时用 RRF 做第二层融合（跨库分数不可比）；
4. `diversify()`：同文档限流 + 碎片过滤；
5. `rerank()`：none / lexical / local / http / llm，失败自动降级到 lexical；
6. 返回 `Hit`（chunk + 分数 + 来源通道 + 排名）。

### 3.3 文档问答图 `app/agent/graph.py`

状态 `RAGState`（TypedDict）字段：`messages / question / queries / candidates /
relevant / answer / citations / attempts / gen_attempts / context / steps / route / kbs / sources`。

- `router`：LLM 判断「闲聊」还是「查知识库」，避免对「你好」也去检索；
- `rewrite`：把中文问题改写成英文关键词式检索式（保留 API 名、错误码），可多查询；
- `retrieve`：多查询各召回 `candidate_k`，合并去重后**只重排一次**（重排很贵）；
- `grade`：逐片段 0/1/2 打分，全 0 → 重试改写（有上限）→ 仍无 → `no_answer`；
- `generate`：拼 context（带 `[n]` 编号）→ 流式生成；
- `verify`：检查引用编号是否合法、是否有未标注的事实句，不通过则重生成一次；
- `finalize`：输出 `answer + citations + steps + 耗时`。

### 3.4 流量取证 `app/traffic/`

**抽取层 `pcap.py`**：一次 `tshark -T fields` 抓主字段（帧号/时间/五元组/标志/协议），
另按需抽 DNS、HTTP（含 body）、TLS（SNI + JA3）、非标准端口明文 HTTP。

**检测层 `analyzer.py`**：14 个检测器，每个输出 `Finding`（含 `evidence` 帧号与
`metrics.scope` / `scope_rules` 供评测精确匹配）。

| 检测器 | 触发条件（默认） | kind |
|---|---|---|
| `detect_port_scan` | ≥20 个目标端口、≤5 台主机、SYN 后无数据 | `port_scan` |
| `detect_horizontal_scan` | ≥10 台主机、≤5 个端口、SYN 后无数据 | `horizontal_scan` |
| `detect_repeated_attempts` | 同一目标端口 ≥20 次 SYN | `repeated_attempts` |
| `detect_fanout_attempts` | 短连接（≤6 包）覆盖 ≥50 台主机、≤8 个端口 | `fanout_attempts` |
| `detect_beacon` | ≥6 次连接、平均间隔 ≥5s、cv ≤0.25 | `beacon` |
| `detect_irc_c2` | 端点落在 6667/6668/6669/7000、同一被控端 ≥3 条会话 | `irc_c2` |
| `detect_tls_c2` | 强信号（无 SNI ≥3）+ 弱信号加权 ≥2 分 | `tls_c2` |
| `detect_dns_tunnel` | 长随机子域、高查询量、可疑 TLD | `dns_tunnel` |
| `detect_dns_volume` | 单主机查询 ≥5000 次 | `dns_volume` |
| `detect_smtp_fanout` | 单主机对 ≥50 个目标发 25 端口 | `smtp_fanout` |
| `detect_exploit_payload` | 请求体命中 9 条公开利用特征 | `exploit_payload` |
| `detect_suspicious_http` | UA 命中扫描器/自动化工具清单 | `suspicious_http` |
| `detect_cleartext_http` | 443/8443 等端口出现明文 HTTP | `cleartext_http` |
| `detect_prompt_injection` | 抓包里出现注入指令特征 | `prompt_injection` |

**取证图 `traffic_graph.py`**：`load`（解析）→ `triage`（LLM 决定要不要深入/查哪些知识）
→ `collect`（工具调用：读 findings、查 ATT&CK、检索知识库）→ `ground`（把结论落到证据帧）
→ `report`（生成 Markdown 报告）→ `verify`（`sanitize.py` 校验引用与数字）。

**提示注入防护**（`traffic/sanitize.py`）：pcap 里的 HTTP 内容是不可信输入，
用 nonce 包裹、剥离指令性语句、输出校验（报告里不允许出现 nonce 之外的指令）。

### 3.5 多 Agent 融合 `app/agent/fusion_graph.py` + `app/signature/`

- `behavior` 与 `signature` 两个分支并行执行（LangGraph 的 fan-out）；
- `signature/suricata.py`：`docker run jasonish/suricata -r <pcap> -S all.rules -k none -l <dir>`，
  解析 `eve.json` 的 `event_type=alert`；**`-k none` 是关键**（见 §7）；
- `signature/fusion.py`：按 (ip, port) 端点对齐两路结果，映射到阶段
  （侦察/凭据攻击/漏洞利用/C2/外传/异常），ET INFO 规则降级，置信度 0.90/0.75/0.55；
- `signature/attack.py`：静态表 + 关键词 + `BEHAVIOR_MAP` 把 finding 映射到 ATT&CK 技术，
  输出覆盖矩阵。

### 3.6 SIEM `app/siem/`

| 文件 | 职责 |
|---|---|
| `parsers.py` | Suricata / Wazuh / ECS 三种告警格式 → 统一 `Alert` |
| `store.py` | SQLite：`alerts / incidents / analyses / cursors` 四张表 + 状态机 + 回写 |
| `tailer.py` | `EveTailer.poll()`：offset + inode + 半行缓冲 + 截断检测；`watch()` 定时轮询 |

去重键（source + rule_id + 五元组 + 时间窗），状态机 `open → triaged → closed`，
研判结果（结论/证据/建议）回写到 `analyses`，可按 incident 取回。

### 3.7 记忆 `app/agent/checkpointer.py`

见 §2.9。要点：`setup()` / `close()` 由 FastAPI lifespan 管理，
`get_checkpointer()` 在未初始化时退回 `MemorySaver`，所以脚本和单测不需要事件循环。

### 3.8 服务与可观测 `app/api/`、`app/main.py`

- `POST /api/chat`：默认 SSE，事件 `start → step* → token* → final`；`stream=false` 返回完整 JSON；
- 建库：`202 + 轮询 /status`，不阻塞 HTTP；
- `step` 事件带节点名、标题、耗时、候选片段 —— 前端直接渲染执行轨迹；
- 日志：每个 LLM/HTTP 调用都有耗时；请求带 `X-Accel-Buffering: no`。

---

## 4. 评测体系

### 4.1 两套数据，回答两个不同的问题

| 数据集 | 回答什么 | 规模 |
|---|---|---|
| golden set（`app/eval/dataset.jsonl`） | 检索排得对不对、答案有没有依据 | 50 题（技术 28 + 领域 22） |
| 真实样本（30 份精选 pcap） | **能不能检出** | 30 恶意 + 1 正常对照 |
| 带标注流量（CTU-13 / IoT-23 / 自建 TLS C2） | **误报率多少、召回多少** | 9 个场景，最多 100 万条流 |

### 4.2 指标与口径

- 检索：`recall@k / hit@1 / hit@3 / MRR / nDCG@k`；
- 流级检测：`recall / FPR / precision`，混淆矩阵按**五元组双向匹配**或**覆盖规则**；
- 答案质量：`keyword_coverage / citation_precision / faithfulness / relevance / clarity`
  （LLM judge + 引用编号校验）。

**三条口径写死在代码里**，避免数字被误读：

1. 只按「两端 IP 都在 pcap 里」裁剪标注，不按时间（CTU-13 部分场景 binetflow 用
   本地时区、pcap 是 epoch，差 2 小时，自动估偏移会把不同时刻的告警匹配到流上）；
2. 大告警用 `scope_rules`（如 `{"src": "...", "dport": 23}`）而不是逐条五元组，
   内存从 O(流数) 降到 O(规则数)；
3. 打印「与恶意流同源同端口的正常流」占比 —— IoT-23 3-1 是 57.1%，
   说明那里的 FPR 几乎全是标注噪声。

### 4.3 当前数字（详见各文档）

| 项 | 值 |
|---|---|
| 检索（NIDS 域，22 题） | recall@6 **1.000** / MRR **0.895** / nDCG **0.922** / hit@1 0.818 |
| 精选真实样本 | **30/30** 检出，误报对照 0/1 |
| CTU-13（3 场景） | recall 0.994 / 1.000 / 0.949，FPR 0.03 / 0.06 / 0.001 |
| IoT-23（3 场景） | recall 1.000 / 1.000 / 1.000 |
| 自建 TLS C2 | recall 1.000 / FPR 0.000 |
| 端到端问答 | 5~9 秒/问（hybrid + 云端重排） |

---

## 5. 配置与运行

```bash
# 1) 依赖
pip install -r requirements.txt          # 运行时
pip install -r requirements-dev.txt      # 语料采集 / 测试 / 重排

# 2) 语料 + 索引（首次约 1~2 分钟，取决于 embedding 速度）
python scripts/fetch_domain_corpus.py --only suricata,zeek,sigma-spec,nist
python scripts/build_index.py --kb ids

# 3) 起服务
uvicorn app.main:app --port 8123
```

`.env` 里最常改的 8 个：

| 键 | 说明 |
|---|---|
| `LLM_BASE_URL / LLM_MODEL / LLM_API_KEY` | 任何 OpenAI 兼容服务 |
| `EMBEDDING_BASE_URL / EMBEDDING_MODEL / EMBEDDING_DIM` | 维度必须与索引一致 |
| `RETRIEVAL_MODE` | `hybrid`（向量+BM25）或 `sparse`（纯 BM25，零依赖） |
| `RERANK_MODE` + `RERANK_API` | `none/local/http/llm`；http 支持 `tei` 与 `siliconflow` |
| `CANDIDATE_K / MAX_PER_DOC / MIN_CHUNK_TOKENS` | 检索后处理 |
| `CHECKPOINT_BACKEND / CHECKPOINT_RETENTION_DAYS` | 多轮记忆与保留期 |

换后端之后先跑体检：

```bash
python scripts/check_providers.py --kb ids     # LLM / embedding / rerank 三项自检
```

---

## 6. 代码地图

```
app/
├── api/             # chat（SSE）/ kb / evals / traffic / siem
├── agent/
│   ├── graph.py          # 文档问答图（9 节点）
│   ├── traffic_graph.py  # pcap 取证图
│   ├── fusion_graph.py   # 行为 ∥ 签名 融合图
│   ├── react.py          # ReAct 对照实现（工具调用）
│   ├── checkpointer.py   # AsyncSqliteSaver + 保留期
│   ├── prompts.py        # 所有提示词（含 grade 的松紧度）
│   └── state.py          # RAGState / Step
├── core/llm.py      # LLM 客户端（含 ainvoke_text 非流式兜底）、EmbeddingClient
├── ingest/          # loader / converters / pdf / chunker / types
├── retrieval/       # bm25 / vectorstore / index / service / rerank
├── traffic/         # pcap 抽取 / analyzer（14 检测器）/ sanitize / tools
├── signature/       # suricata / fusion / attack
├── siem/            # parsers / store / tailer
├── eval/            # dataset / runner / metrics / formats（数据格式解耦）
└── web/             # 单页前端
scripts/             # 语料采集、建库、评测、抓包生成、体检（23 个）
tests/               # 17 个文件 / 174 个用例
docs/                # 本文件 + 架构、评测、路线图、面试对照
```

---

## 7. 踩坑清单（这些比设计更能说明「怎么做的」）

| 坑 | 现象 | 根因 | 修法 |
|---|---|---|---|
| H1 是产品名 | 整篇文档变成向量空间 hub，压掉真正相关页 | 每个片段都带产品名前缀 | `short_heading()` 丢掉与文档标题相同的一级标题 |
| 重排第一版是负收益 | MRR 0.835 → 0.744 | 用英文改写式喂 CE；片段丢了标题 | 用原始中文问题 + `heading_path`，MRR → 0.895 |
| 候选池放大 | MRR 0.898 → 0.865 | 融合分是 min-max 归一化，池子大小改变尺度 | 池子回到 `candidate_k`，想加深先换 RRF |
| 云端重排 blend 无效 | 0.3/0.5/0.7 结果完全一样 | `top_n` 只传了最终条数，后面候选没有 CE 分 | `top_n=len(texts)`，让所有候选都有分 |
| LLM 重排在 hybrid 上是负的 | 0.835 → 0.758，还慢 17s | listwise 打分方差大 | hybrid 上不用 LLM 重排，只用 CE |
| grade 过严 | 大量「知识库没找到」 | prompt 写「宁可给 0」 | 改成「只有完全无关才给 0」 |
| Suricata 静默漏检 | 5 份单包利用全漏 | 回放样本 checksum 无效，规则不匹配 | `-k none`，25/30 → 29/30 |
| 证据粒度不足 | Rbot 场景 recall 0.000 | 告警只带 12 个证据帧，2.7 万条恶意流匹配不上 | 检测器输出 `metrics.scope` 精确五元组 |
| 扫描检测有盲区 | IoT 场景 53 万条恶意流漏掉 | `horizontal_scan` 只算「SYN 后无数据」，爆破握手会完成 | 新增 `fanout_attempts`（短连接扇出） |
| 证据装不下 | 53 万条流无法逐条塞进告警 | —— | `scope_rules`：一条规则表达整批 |
| IoT-23 标签全错 | 恶意/正常判断反了 | 标注列用三个空格追加，不是 TAB | 检测行段数不足并按 2+ 空格补切 |
| 时间对齐骗人 | 自动估时区偏移后数字「变好」 | 把不同时刻的告警匹配到流上，不可解释 | 只按 IP 裁剪，不做时间偏移 |
| TLS 检测两次误报 | 正常 RDP 被报 | 弱信号相加；裸 IP SNI 当强信号 | 只有「无 SNI ≥3」算强信号 |

---

## 8. 已知边界

- **加密 C2 只用自建样本验证过**：真实世界的 TLS C2 没有逐流标注数据；
  `tls_c2` 的阈值还没在真实 HTTPS 海量流量上做过压力测试。
- **单包利用依赖载荷特征**：ET 规则 + 9 条公开利用特征覆盖不到零日，
  也覆盖不到只有 header 没有 body 的攻击。
- **低频 IRC C2 之外的低频行为**仍可能漏：规则阈值来自有限样本。
- **检查点是单机 SQLite**：多实例部署要换 `PostgresSaver`。
- **无鉴权 / 无多租户**：单机 Demo。
- **评测集偏小**：golden set 50 题，带标注场景 9 个，结论是「可用」不是「统计显著」。

---

## 9. 复现清单

想验证文档里的每个数字，按这个顺序跑：

```bash
# 检索质量（22 题 / 50 题）
python scripts/eval_rerank.py --modes none,http --kb ids --candidate-k 20

# 端到端答案质量（含 LLM judge）
python scripts/run_eval.py --kb ids --mode end2end --limit 12

# 精选真实样本：检出 + 误报对照
python scripts/benchmark_real.py --with-signature --write-doc

# 带标注流量：召回 / FPR / precision（先把数据拉下来）
python scripts/fetch_ctu13.py --scenarios 1
python scripts/eval_labeled.py --dir data/labeled/ctu13 --scenario 1 --write-doc

# 自建 TLS C2 样本（需要 docker，用容器抓包）
python scripts/make_tls_c2_pcap.py --beacons 8
python scripts/eval_labeled.py --dir data/labeled --scenario tls-c2

# 单元测试
python -m pytest -q
```
