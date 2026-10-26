# Changelog

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
