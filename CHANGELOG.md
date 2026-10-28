# Changelog

## v2.2.0 — cross-encoder 重排接入（先负后正）

- 新增 `RERANK_MODE=local`：bge-reranker-v2-m3（2.27GB）+ transformers 裸打分，
  支持 `RERANK_BLEND` 把融合分与重排分归一化后混合。
- 也支持 `RERANK_MODE=http`（TEI 兼容 `/rerank` 接口），便于换成 GPU 服务。
- **第一版是负结果**（MRR 0.744），排查后修正两处输入：
  1. 用「原始中文问题」做重排而不是英文改写式（0.744 → 0.865）
  2. rerank 的 passage 拼上 heading_path（0.865 → 0.895）
- **最终 A/B（ids 22 题，candidate_k=20，blend=0.5）**：hit@1 0.727→0.818，
  MRR 0.835→0.895，nDCG 0.876→0.922。
- 新增 `RERANK_USE_QUESTION`（默认 true）与 `RERANK_BLEND`（0.5 最优）；
  `scripts/rerank_server.py` 提供 GPU 容器用的最小 TEI 兼容服务。

## v2.1.0 — 支持 PDF/HTML 语料（NIST / MS-SMB2 / Snort 3）

- 新增 `app/ingest/pdf.py`：去页眉页脚、行重排成段落、`## Page N` 保留页码定位。
- 新增 `scripts/fetch_pdf_docs.py` + `make pdf-docs`：
  - NIST SP 800-61 r3 / r2（事件响应）
  - MS-SMB2（微软 SMB 2/3 协议规范，499 页）
  - Snort 3 官方文档（docs.snort.org 整本 print.html）
- `scan_urls` 增加 nist / ms-smb2 / snort 前缀映射。
- 至此语料格式覆盖：Markdown / RST / RFC 纯文本 / STIX JSON / 规则 YAML / PDF / HTML。

## v2.0.0 — 知识库扩容到业内常用语料（1,265 → 5,505 篇）

先用查询实测缺口，再针对性补：
- **Snort**：只有 Suricata 文档里一页对比 → 仓库文档太薄，暂不纳入
- **协议规范**：RFC 从 7 篇扩到 21 篇（新增 TCP/9293、TLS1.2、HTTP/2、QUIC、DoH、
  Kerberos、LDAP、IPFIX、NetFlow v9、Syslog、DHCP、RADIUS、ICMPv6、DNS 1034）
- **恶意家族**：ATT&CK 增加 software 842 / group 178 / mitigation 44（Mirai、APT28 等可直接查）
- **防御映射**：用 ATT&CK mitigations 替代 D3FEND（后者只有 TTL 本体，不好转）
- **检测工程**：Sigma 规则 3,161 条转成 Markdown（含 detection 逻辑与误报说明）
- 新增 `scripts/fetch_sigma_rules.py`、`make sigma`；`fetch_mitre_attack.py` 扩展三类实体

## v1.9.0 — 云后端（DeepSeek）+ 纯 BM25 检索模式

- 新增 `RETRIEVAL_MODE=hybrid|sparse`：sparse 模式跳过 embeddings，只走 BM25。
- 适配 DeepSeek（无 embeddings 接口）：`LLM_MODEL=deepseek-chat` + `RETRIEVAL_MODE=sparse`。
- 实测：50 题 recall@6 0.94 / MRR 0.68；文档问答 5.0s，多 Agent 研判 25.8s。
- `/api/info` 暴露 `retrieval_mode`。
- 测试保持 138 个全绿。

## v1.8.0 — 映射评测 + 前端契约测试 + 容器验证

- **ATT&CK 映射评测**：29 条真实签名的标注集 + 三种方案对比（关键词 60.3%、
  语义兜底 0/7、LLM 受限分类 2/7）→ 默认改为 `keyword`，负结果留在
  `docs/ATTACK_MAPPING_EVAL.md`。
- **前端契约测试**：从 `index.html` 抽 fetch 目标与 FastAPI 路由比对、元素 ID 引用、
  按钮绑定、node 语法检查，共 7 个用例。
- **容器**：补 `.dockerignore`（构建上下文 500MB → 1.9MB），基础镜像改用 `python:3.12-slim`，
  镜像内安装 tshark；`docker compose up` 实测通过（4 个 KB 全加载、文档问答命中 T1003.001）；
  compose 的 LLM/Embedding/向量后端均可通过环境变量覆盖。
- **流式兼容**：部分 OpenAI 兼容网关忽略 `stream: true`，LangChain 会抛
  `No generations found in stream`；新增 `ainvoke_text()` 自动回退非流式。
- 依赖拆分：`requirements.txt`（运行时）/ `requirements-dev.txt`（采集 + 测试），镜像不需要 scapy/bs4。
- 实测 vLLM（Qwen2.5-3B）后端单次问答 **2.2s**。
- 测试 131 → 138。

### 修正
- `ATTACK_MAPPING_EVAL.md` 早期把 LLM 的「6/7 待兜底签名给出预测」误写成「覆盖率 85.7%」，
  实际整体覆盖率 72.4%；已更正，并统一表头为「覆盖率（总体）/ 加权准确率」。

## v1.7.0 — ATT&CK 自动映射

- `app/signature/attack.py`：三层映射（行为静态表 / 签名关键词 / ATT&CK 知识库语义兜底），
  置信度分 high/medium/low，避免把猜测当结论。
- 融合图新增 `attack` 节点，报告强制输出「ATT&CK 覆盖」并按战术顺序排列；
  引用未映射的技术编号会被 `verify` 打回。
- 新增 `GET /api/traffic/attack/{pcap}`：不调 LLM 的覆盖度查询。
- 前端在报告下方渲染 ATT&CK 技术徽章。
- 测试 116 → 131。

## v1.6.0 — 增量消费 + SIEM 面板 + 真实样本扩到 30 份

- **eve.json 增量消费**：SQLite 游标表（path/inode/offset/lines），支持重启续读、
  半行等待、日志轮转自动重置；`POST /api/siem/tail`、`GET /api/siem/cursors`、
  `scripts/tail_eve.py --follow`，配置 `SIEM_TAIL_PATHS` 后随服务自动轮询。
- **前端 SIEM 面板**：告警统计、incident 列表、详情（告警明细 + 历史研判）、
  一键研判（SSE 流式）、关闭并写备注。
- **真实样本 13 → 31 份**（30 恶意 + 1 对照），基准支持 `--with-signature`：
  行为 9/30、签名补足 16、合计 **25/30（83%）**，误报 0/1。
- 基准结果缓存（`--from-cache`），避免每次重跑 6 分钟。
- 测试 103 → 116。

## v1.5.0 — SIEM 持久化 + 研判回写闭环

- 存储层从内存 ring buffer 换成 **SQLite（WAL）**：`alerts` / `incidents` / `analyses` 三张表。
- 去重改由数据库唯一索引保证，跨进程重启依然有效。
- **结论回写**：研判结束自动写入 `analyses` 并把 incident 推进到 `triaged`；
  新增 `GET /api/siem/incidents/{id}`（含告警与历史研判）与 `PATCH`（人工改状态 + 备注）。
- 状态机 `open → triaged → closed`，刷新聚合不会覆盖人工状态。
- 测试从 87 增至 103，新增持久化、跨实例去重、回写、状态机、API 闭环测试。

## v1.4.0 — 多 Agent 融合 + 真实样本 + 注入防护

- **多 Agent 检测**：`behavior`（规则引擎）与 `signature`（Suricata 8.0.7 + ET Open 52,752 条规则）
  在 LangGraph 中并行执行，`fuse` 节点做实体关联、置信度定级、攻击阶段排序。
- **真实样本验证**：12 份公开恶意流量 + 1 份正常 RDP 对照，检出 5/12、误报 0。
  新增横向扫描、同端口高频重试两个检测器（真实样本暴露的盲区）。
- **提示注入防护**：检测 → 隔离（随机 nonce）→ 消毒 → 输出校验四层，
  含对抗样本 `prompt_injection.pcap`。
- **SIEM 接入**：Suricata / Wazuh / ECS 归一化、去重、incident 聚合、知识增强研判。
- **引用校验升级**：包号与 pcap 实际长度比对、SID 存在性校验。

## v1.3.0 — 流量取证 Agent

- `app/traffic`：tshark 字段提取、规则引擎（扫描 / DNS 隧道 / beacon / 可疑 UA / 明文协议）、
  证据渲染与路径安全。
- `app/agent/traffic_graph.py`：load → triage → collect → ground → report → verify。
- 中文报告强制 `[pkt #N]` + `[K1]` 双证据链，校验不过自动重写。

## v1.2.0 — 真实恶意流量基准

- `scripts/fetch_real_pcaps.py`（SpiderLabs/IOCs-IDPS，按需下载，不入库）
- `scripts/benchmark_real.py` → `docs/REAL_TRAFFIC_BENCHMARK.md`

## v1.1.0 — NIDS 领域知识库

- `app/ingest/converters.py`：reStructuredText / IETF RFC / arXiv HTML → Markdown
- `scripts/fetch_domain_corpus.py`：Suricata、Zeek、nDPI、RFC、论文一键拉取
- 检索层新增 `sources` 子集过滤，降低跨来源噪声

## v1.0.0 — 文档 RAG Agent

- 结构化 Markdown 分块（标题面包屑、代码块原子化、跨文档去重）
- BM25 + bge-m3 双路召回，RRF / 归一化两种融合
- Corrective RAG 工作流：路由 → 改写 → 检索 → 打分 → 生成 → 引用校验
- FastAPI SSE + 零构建前端 + 评测集与指标
