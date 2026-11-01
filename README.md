# NIDS-Agent：把 pcap 变成可复核的检测结论

一个面向**网络流量检测（NIDS）**的 Agent 系统：吃 pcap 和 SIEM 告警，输出**每条结论都能落到包号和文档出处**的检测报告——而不是一个「问答机器人」。

> 检索在这里是**工具**：给检测结论找规则依据、字段语义和 ATT&CK 编号。判定本身由确定性引擎完成。

| 维度 | 现状 |
|---|---|
| 确定性检测器 | **14 个**（扫描/爆破/隧道/心跳/扇出/载荷/注入…），全部可解释、带证据包号 |
| 签名引擎 | Suricata 8.0.7 + ET Open（52,752 条规则），与行为检测并行融合 |
| 精选真实样本 | **30/30 检出**（行为单独 10/30，签名补到 30/30），正常对照 0 误报 |
| 带标注流量 | **9 个场景**（CTU-13 / IoT-23 / 自建 TLS C2），单场景最多 100 万条流 |
| 答案可复核 | 双证据链：`[pkt #12]` 包号 + `[K1]` 文档出处 |
| 实现细节 | [`docs/DESIGN.md`](docs/DESIGN.md)（分层、10 个关键决策、踩坑清单） |

---

## 一、它解决什么问题

安全分析里的两个动作——**「看证据」和「说清楚为什么」**——通常被割裂在两个工具里：

- 规则/IDS 引擎能判定，但输出是一条条告警，分析师还要自己去翻 pcap；
- LLM 能写报告，但它不知道 `dns.query.name` 是什么、T1048.003 和 T1048 差在哪。

这个项目把两者接起来：

```
pcap ──▶ 确定性检测（可解释、带包号）──▶ 融合去重 ──▶ ATT&CK 映射
                                            │
                                            ├──▶ 证据化报告（结论 + 包号 + 文档出处）
                                            └──▶ SIEM：告警聚合 → 研判 → 回写
```

**判断由谁做**：计数、周期性、熵值、扇出规模这些可复现的判定，全部由规则引擎完成；
LLM 只做「解释为什么可疑、对应哪种攻击、建议怎么处置」。所以即使模型没起来，
`GET /api/traffic/findings/{pcap}` 依然返回完整的事实清单。

### 为什么是 Agent，而不是一个分类器

因为真实工作不是「二分类」，而是一条有分支的流程：

```
load ─ triage（要不要深挖、该查什么）─ collect（补证据：查 ATT&CK、查规则）
     ─ ground（把结论落到包号/文档）─ report ─ verify（包号与引用双校验）─ finalize
```

`triage` 决定查什么、`collect` 多轮取证据、`verify` 不通过会重写——这些不是「一次前向推理」
能做到的。三张图（取证 / 多 Agent 融合 / 文档问答）都用 LangGraph 的显式状态机表达，
每个节点可单测、可回放（见 §六）。

---

## 二、检测能力

### 2.1 确定性检测器（14 个）

| 检测器 | 触发条件（默认） | ATT&CK |
|---|---|---|
| `port_scan` | ≥20 个目标端口、≤5 台主机、SYN 后无数据 | T1046 |
| `horizontal_scan` | ≥10 台主机、≤5 个端口、SYN 后无数据 | T1046 / T1210 |
| `fanout_attempts` | 短连接（≤6 包）覆盖 ≥50 台主机、≤8 个端口 | T1110.001 / T1210 |
| `repeated_attempts` | 同一目标端口 ≥20 次 SYN | T1110.001 |
| `beacon` | ≥6 次连接、平均间隔 ≥5s、cv ≤0.25 | T1071 / T1573 |
| `irc_c2` | 端点落在 6667/6668/6669/7000、同一被控端 ≥3 条会话 | T1071 / T1573 |
| `tls_c2` | 强信号（无 SNI ≥3 次）+ 弱信号加权 ≥2 | T1071.001 / T1573 |
| `dns_tunnel` | 高熵长域名、高查询量、可疑 TLD | T1071.004 |
| `dns_volume` | 单主机查询 ≥5000 次 | T1071.004 |
| `smtp_fanout` | 单主机对 ≥50 个目标发 25 端口 | T1048 |
| `exploit_payload` | 请求体命中 9 条公开利用特征（XMLDecoder / JNDI / OGNL / XXE …） | T1190 / T1059 |
| `suspicious_http` | UA 命中扫描器/自动化工具清单 | T1071.001 |
| `cleartext_http` | 443/8443 等端口出现明文 HTTP | T1071.001 |
| `prompt_injection` | 抓包里出现指令注入特征 | AML.T0051 |

每条 finding 都带 `kind / severity / title / detail / metrics / evidence(帧号)`；
评测时还能给出 `scope`（精确五元组）或 `scope_rules`（如 `{"src": "...", "dport": 23}`）。

### 2.2 签名引擎：Suricata + ET Open

```bash
docker run jasonish/suricata -r <pcap> -S all.rules -k none -l <dir>
```

解析 `eve.json` 的 alert 事件。**`-k none` 是个关键开关**：回放类样本大量带无效校验和，
Suricata 默认校验后规则**根本不匹配**，表现为「安静地少检出」。加上之后
bluekeep / printnightmare / drupal 立刻命中，精选样本 25/30 → 29/30。

### 2.3 载荷级检测：header 之外还得看 body

单包漏洞利用既没有可统计的行为，ET Open 也常常没有对应规则。所以把 HTTP **请求体**
也抽出来，用公开利用链的固定片段匹配（反序列化、`${jndi:`、OGNL、XXE、WLS 工作区入口…）。

体提取有个坑：`tshark -T fields` 是**按行**解析的，body 一换行后面字段全错位。
所以 body 单独走 `-T json`，只读前 4KB、最多 60 条，取不到就静默跳过。
WebLogic CVE-2017-10271 那份 12 个包的样本就是这样从漏检变成命中的（29/30 → **30/30**）。

### 2.4 两个「不能误报」的对照

| 样本 | 内容 | 结果 |
|---|---|---|
| `benign_web.pcap` | DNS + HTTP 正常访问 | **0 命中** |
| `normal_rdp.pcap` | 5,126 包正常 RDP | **0 命中**（曾把 `tls_c2` 误报打出来，已修） |

---

## 三、多 Agent 融合：行为 ∥ 签名

```
        ┌─ behavior  （14 条规则，统计/行为）──┐
load ──┤                                      ├── fuse ─ attack ─ ground ─ report ─ verify ─ finalize
        └─ signature （Suricata，已知特征）────┘
```

- **并行 fan-out 而不是 supervisor**：两路互不依赖，串行只是白等；
- **按 (ip, port) 端点对齐融合**，映射到阶段（侦察/凭据攻击/漏洞利用/C2/外传），
  ET INFO 类规则降级，置信度 0.90 / 0.75 / 0.55；
- 两引擎盲区几乎不重叠：行为单独 10/30 → 融合 **30/30**。

---

## 四、证据链：结论必须能落到包和文档

```
## 结论
高度疑似 C2 外联：12 次连接间隔高度规律（CV=0.00）[pkt #1,#4,#7...]，
443 端口出现明文 HTTP [pkt #3,#6,#9...]

## 证据链 / ## 建议处置 / ## 参考文档 [K1]..[K4]
```

- `[pkt #n]`：由 `analyzer` 产出的帧号，报告里的数字必须与 finding 一致；
- `[K1]`：知识库出处（Suricata / Zeek / Sigma / ATT&CK 文档），用于解释规则写法和字段语义；
- `verify` 节点做双校验：包号存在、引用编号存在、没有未标注的事实句，不通过就重写一次。

### ATT&CK 自动映射（附实测准确率）

| 方案 | 加权准确率 | 完全命中率 | 覆盖率 |
|---|---:|---:|---:|
| 静态表 + 关键词（默认） | **60.3%** | 58.6% | 51.7% |
| 语义检索兜底 | 试过，无提升 | — | — |

29 条人工标注签名上的结果，见 [`docs/ATTACK_MAPPING_EVAL.md`](docs/ATTACK_MAPPING_EVAL.md)。
覆盖率只有 51.7% 是**如实记录**：大量 ET 签名没有明确对应的技术编号，硬映射只会制造错误结论。

---

## 五、SIEM 闭环：告警不只是弹窗

```
eve.json ──▶ EveTailer（offset + inode + 半行缓冲 + 截断检测）
              │
              ▼
        SQLite：alerts / incidents / analyses / cursors
              │  去重键（source + rule_id + 五元组 + 时间窗）
              ▼
        incidents（聚合）──▶ 研判 ──▶ 回写结论/证据/建议 ──▶ 状态机 open→triaged→closed
```

接口：`POST /api/siem/ingest`、`GET /api/siem/incidents`、`POST /api/siem/incidents/{id}/analyze`。
消费位点也落库，进程重启不会重复消费。

---

## 六、Agent 设计里几个不显然的点

| 点 | 做法 | 为什么 |
|---|---|---|
| 提示注入 | 抓包内容视为不可信输入：nonce 包裹、剥离指令性语句、输出校验 | pcap 里的 HTTP 内容可能包含「忽略以上指令」；对抗样本验证过模型没有照做，反而把它当攻击上报 |
| 记忆 | `AsyncSqliteSaver` 落 `data/checkpoints.sqlite`，7 天保留期 | 同步版 `SqliteSaver` 在 `astream`/`aget_state` 下不可用；UUIDv6 的 checkpoint_id 自带时间序，清理不用加时间列 |
| 重试上限 | `max_retrieval_attempts` + `recursion_limit` | 没有上限的 Agent 循环就是线上事故 |
| 流式 | SSE：`step`（节点进展）/ `token`（逐字）/ `final` | 前端能直接渲染执行轨迹，而不是干等 20 秒 |

更细的取舍（图结构、状态字段、节点职责）见 [`docs/DESIGN.md`](docs/DESIGN.md) §2.5、§3.3。

---

## 七、评测：三套数据回答三个问题

| 数据 | 回答什么 | 结果 |
|---|---|---|
| 精选真实样本（30 恶意 + 1 对照） | **能不能检出** | **30/30**；误报对照 0/1 |
| 带标注流量（9 场景） | **召回多少、误报多少** | 见 §7.1 |
| golden set（50 题） | 检索与答案是否可靠 | recall@6 1.000 / MRR 0.895 / nDCG 0.922 |

### 7.1 带标注流量：真实召回与误报

| 场景 | 家族/行为 | 流数 | recall | FPR | precision |
|---|---|---:|---:|---:|---:|
| CTU-13 / 1 | Neris（IRC + DGA + 垃圾邮件） | 46,712 | 0.994 | 0.0329 | 0.995 |
| CTU-13 / 3 | Rbot（SSH 传播 + IRC C2） | 72,115 | 1.000 | 0.0617 | 0.906 |
| CTU-13 / 8 | Murlo（Qvod） | 268,428 | 0.949 | 0.0014 | 0.941 |
| IoT-23 / 1-1 | Hide-and-Seek（Telnet 扇出） | 1,008,748 | 1.000 | 0.0002 | 1.000 |
| IoT-23 / 3-1 | IoT 恶意软件（SSH 扇出） | 156,103 | 1.000 | 0.5692\* | 0.983 |
| IoT-23 / 20-1 | Torii（TLS C2） | 3,209 | 1.000 | 0.0000 | 1.000 |
| 自建 TLS C2 | 无 SNI + 抖动心跳 | 15 | 1.000 | 0.0000 | 1.000 |

\* 3-1 的 57% 几乎全是**标注噪声**：评测脚本会打印「与恶意流同源同端口的正常流」占比
（2591/4536 = 57.1%），即同一波扫描里被标成 Benign 的流；要跟 precision 一起读。

**口径写死在代码里**（`scripts/eval_labeled.py`）：

1. 只按「两端 IP 都在 pcap 里出现过」裁剪标注，**不按时间**——部分场景 binetflow 用本地时区、
   pcap 是 epoch，差 2 小时，自动估偏移会把不同时刻的告警匹配到流上，数字不可解释；
2. 大告警用 `scope_rules` 表达覆盖范围（一条 `{"src": "...", "dport": 23}` 覆盖 53 万条流），
   内存从 O(流数) 降到 O(规则数)；
3. 打印标注歧义占比，避免把标签噪声当成误报。

归因详见 [`docs/LABELED_EVAL.md`](docs/LABELED_EVAL.md) 与 [`docs/REAL_TRAFFIC_BENCHMARK.md`](docs/REAL_TRAFFIC_BENCHMARK.md)。

### 7.2 性能

| 场景 | 耗时 |
|---|---|
| 规则分析（不调 LLM） | 接口秒回（tshark 解析为主） |
| 完整取证报告（含 LLM） | 16~39 秒/pcap（CPU 跑 8B 模型时的实测） |

---

## 八、支撑层：知识库与检索（为什么 NIDS 需要它）

检测结论要引用依据，否则无法复核。知识库就是「规则怎么写、字段什么含义、这个行为对应哪条 ATT&CK」
的依据库：

- **规模**：5,839 篇文档 / 49,044 片段；NIDS 域 `ids` 5,523 篇 / 41,428 片段
- **来源**：Suricata、Zeek、nDPI、Snort、IETF RFC、Sigma（3,161 条规则 + 规范页）、
  MITRE ATT&CK（技术/软件/组织/缓解）、NIST SP 800-61、MS-SMB2、arXiv 论文
- **多格式**：Markdown / RST / HTML / PDF / RFC / YAML(→MD)

检索不是「够用就行」——它是 grounding 的来源。所以做了混合检索（BM25 + bge-m3）、
cross-encoder 重排、同文档限流、相邻片段补全。实测（NIDS 域 22 题）：

| 配置 | recall@6 | MRR | nDCG@6 |
|---|---:|---:|---:|
| 纯 BM25 | 0.955 | 0.776 | 0.822 |
| 混合检索 | 1.000 | 0.814 | 0.862 |
| **混合 + cross-encoder 重排** | **1.000** | **0.895** | **0.922** |

实现细节（分块策略、融合方式、重排的两次负结果、grade 松紧度）见
[`docs/DESIGN.md`](docs/DESIGN.md) §2.1~2.5。

---

## 九、快速开始

### 9.1 只跑确定性检测（不需要模型）

```bash
pip install -r requirements.txt && apt install -y tshark
python scripts/make_sample_pcaps.py                 # 生成 9 个样本 pcap
uvicorn app.main:app --port 8123

curl localhost:8123/api/traffic/findings/samples/port_scan.pcap   # 秒回事实清单
curl localhost:8123/api/traffic/attack/samples/beacon_c2.pcap     # 含 ATT&CK 映射
```

### 9.2 完整 Agent（需要 LLM + 知识库）

```bash
cp .env.example .env        # 填 LLM / embedding；Ollama 或任意 OpenAI 兼容服务

python scripts/fetch_domain_corpus.py --only suricata,zeek,sigma-spec,nist
python scripts/build_index.py --kb ids

curl -N -X POST localhost:8123/api/traffic/analyze \
  -H 'Content-Type: application/json' \
  -d '{"pcap":"samples/beacon_c2.pcap","question":"这是不是 C2 外联？"}'
```

换后端之前先体检（验证 embedding 维度与索引是否一致——不一致不会报错，只会悄悄变差）：

```bash
python scripts/check_providers.py --kb ids
```

### 9.3 Docker

```bash
docker compose up -d --build      # API + 可选 Qdrant；镜像内固定 tshark
```

### 9.4 评测

```bash
python scripts/eval_rerank.py --modes none,http --kb ids       # 检索
python scripts/run_eval.py --kb ids --mode end2end --limit 12  # 端到端答案
python scripts/benchmark_real.py --with-signature --write-doc  # 精选真实样本
python scripts/fetch_ctu13.py --scenarios 1 && python scripts/eval_labeled.py --scenario 1
python scripts/make_tls_c2_pcap.py && python scripts/eval_labeled.py --dir data/labeled --scenario tls-c2
```

---

## 十、代码结构（NIDS 视角）

```
app/
├── traffic/            # 检测核心：pcap 抽取 → 14 个检测器 → Finding
│   ├── pcap.py         # tshark 封装（主字段 / DNS / HTTP+body / TLS+JA3 / cleartext）
│   ├── analyzer.py     # 检测器与阈值
│   ├── sanitize.py     # 提示注入防护（不可信输入隔离 + 输出校验）
│   └── tools.py        # 取证 Agent 的工具层
├── signature/          # 签名引擎：suricata 运行 / 融合 / ATT&CK 映射
├── agent/
│   ├── traffic_graph.py    # pcap 取证图（load→triage→collect→ground→report→verify）
│   ├── fusion_graph.py     # 行为 ∥ 签名 融合图
│   ├── graph.py            # 文档问答图（检索作为工具）
│   └── checkpointer.py     # 持久化记忆
├── siem/               # 告警解析 / SQLite 存储 / 增量消费 / 状态机
├── retrieval/          # 混合检索 + 重排（支撑层）
├── ingest/             # 多格式 → Markdown → 结构化分块
├── eval/               # 评测：golden set、带标注流量（格式自动识别）
└── api/                # chat / kb / evals / traffic / siem
```

---

## 十一、已知边界（如实写）

| 边界 | 现状 |
|---|---|
| 加密 C2 | `tls_c2` 只在**自建样本**上验证过（recall 1.0 / FPR 0）；真实 TLS C2 缺逐流标注数据，阈值还没在真实 HTTPS 海量流量上压测 |
| 零日 / 仅 header 的攻击 | 载荷特征覆盖不到；需要漏洞库或流量行为建模 |
| 低频行为 | 阈值来自有限样本；Rbot 类低频 C2 靠专门的 `irc_c2` 补上，其它新形态未必有 |
| 单机 | 检查点是 SQLite；多实例要换 `PostgresSaver` |
| 无鉴权 | 单机 Demo |
| 标注质量 | 公开数据集普遍有噪声（CTU-13 只给已知感染主机打标签；IoT-23 有同源同端口被标 Benign 的流），FPR 应视为上界 |

---

## 十二、文档索引

| 文档 | 内容 |
|---|---|
| [`docs/DESIGN.md`](docs/DESIGN.md) | 实现向设计文档：分层、10 个关键决策（含代价）、模块逐个讲、13 条踩坑、复现清单 |
| [`docs/LABELED_EVAL.md`](docs/LABELED_EVAL.md) | 9 个带标注场景的召回 / 误报 / 口径 |
| [`docs/REAL_TRAFFIC_BENCHMARK.md`](docs/REAL_TRAFFIC_BENCHMARK.md) | 30 份真实恶意样本逐条明细 |
| [`docs/ATTACK_MAPPING_EVAL.md`](docs/ATTACK_MAPPING_EVAL.md) | ATT&CK 映射的 29 条标注与准确率 |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | 架构图与模块职责（含取舍） |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | 已完成 / 下一步 |
| [`docs/INTERVIEW_MAP.md`](docs/INTERVIEW_MAP.md) | 知识点 → 代码位置 → 面试问法 |
| [`docs/README_V1_RAG.md`](docs/README_V1_RAG.md) | 旧版 README（RAG 视角，保留历史） |

---

## License

MIT，见 [LICENSE](LICENSE)。
