# DevRAG · 文档智能问答 Agent

> 一个**完整可跑**的 RAG 项目：拿开源框架的官方文档做知识库，用 LangGraph 搭 Agent 工作流，FastAPI 提供 SSE 流式接口，本地 Ollama 推理，**零 API 费用**。

```bash
git clone 本项目 && pip install -r requirements-dev.txt
ollama pull qwen3:8b && ollama pull bge-m3
python scripts/fetch_corpus.py && python scripts/build_index.py
uvicorn app.main:app --port 8000     # http://127.0.0.1:8000
```

---

## 一、先解决「做什么方向」和「没有文档」

你提的两个问题，这个项目是这么解的：

**文档从哪来？** GitHub 上的开源项目文档本身就是最好的语料：纯 Markdown、带标题层级、带代码块、可复现、免授权。
`scripts/fetch_corpus.py` 用 sparse clone 只拉文档目录，40 秒就能拿到 300+ 篇文档。

**做什么方向？** 下面 5 个方向都「文档现成」，按落地难度排序：

| 方向 | 语料来源（都能直接 clone） | 难度 | 适合谁 |
|---|---|---|---|
| **① 技术文档助手（本项目）** | `tiangolo/fastapi` → `docs/en/docs`；`langchain-ai/docs` → `src/oss`；`pydantic/pydantic` → `docs` | ★★☆ | 想同时展示 RAG + Agent + 后端工程 |
| **①' 领域知识库（本项目已内置）** | Suricata / Zeek / nDPI 文档 + IETF RFC + arXiv 论文 | ★★★ | 有自己的研究方向（如流量检测） |
| ② 法律法规问答 | 国家法律法规数据库（`flk.npc.gov.cn`）抓条文，转 Markdown | ★★★ | 想强调「领域知识 + 引用溯源」 |
| ③ 论文阅读助手 | arXiv API 按主题批量下 PDF，`pypdf` 解析 | ★★★☆ | 想练 PDF 版面解析 + 长文档切分 |
| ④ 上市公司年报分析 | 巨潮资讯网 PDF 年报 | ★★★★ | 想练表格/图表抽取、财报问答 |
| ⑤ 个人知识库 | 自己的笔记 / Obsidian 导出 | ★☆ | 想快速出 Demo |

我选 ① 的原因很实在：**面试官问的技术点，正好就是知识库里的内容**。你可以用它答「LangGraph 的检查点怎么工作」，
也可以翻出源码说「我就是这么实现的」—— 讲业务和讲技术是同一条线，不容易被问穿。
后面的 `data/raw/<kb>/` 目录支持任意 Markdown，随时可以再塞一个领域知识库进去。

---

## 二、它到底做了什么

一次提问的完整链路（不是「向量库 + 拼 prompt」那种玩具版）：

```
用户问题（中文）
  │
  ├─ router      判断意图：闲聊直接答 / 提问走检索；多库时由 LLM 选库
  ├─ rewrite     改写成 3 条检索式（中文 → 英文关键词，保留 API 名）
  ├─ retrieve    bge-m3 稠密召回 + BM25 稀疏召回，归一化加权融合
  ├─ grade       LLM 逐条打 0/1/2 分，只留 ≥1 的片段；全废则改写重试（最多 2 轮）
  ├─ generate    带 [1][2] 编号的引用式生成，SSE 逐字吐给前端
  ├─ verify      正则校验引用编号是否合法；没有有效引用 → 强制重生成一次
  └─ finalize    输出答案 + 可点开的来源卡片
```

另有一条 ReAct 模式（`mode=react`）：模型自己决定调 `list_knowledge_bases / search_knowledge_base / read_document`，
多次换关键词搜索再作答 —— 用来对比「固定编排 vs 自主 Agent」的取舍。

### 实测数字

| 指标 | 值 | 说明 |
|---|---|---|
| 知识库规模 | 1,582 篇文档 / 23,796 个片段 | 技术文档 3 库（316 篇）+ 领域库 `ids`（1,266 篇，含 ATT&CK 721） |
| 索引构建 | 约 53 秒（CPU，8 核并行向量化） | bge-m3，1024 维 |
| 检索质量（技术文档） | recall@6 **0.893** / MRR 0.757 / nDCG@6 0.791 | 28 题 golden set |
| 检索质量（NIDS 领域） | recall@6 **1.00** / MRR 0.837 / nDCG@6 0.878 | 22 题 golden set（含 6 题 ATT&CK） |
| 单次问答 | **2.2 秒**（vLLM 3B）/ 16~40 秒（CPU Ollama） | 4 次 LLM 调用；换后端只改环境变量 |
| 流量取证 | 16~39 秒/份 pcap | 规则引擎 <1s，其余是 LLM；确定性结论没 LLM 也能出 |
| 真实样本（30 份） | 行为 9/30，签名补足 16，**合计 25/30（83%）** | 误报对照 0/1 |
| 真实恶意流量 | 12 份，**5 份产生告警（42%）**，误报对照 0 触发 | 见 `docs/REAL_TRAFFIC_BENCHMARK.md` |
| 提示注入 | 检测 + 隔离 + 消毒 + 输出校验 | 对抗样本验证：模型没有照做，反而把注入当攻击上报 |
| 多 Agent 融合 | 行为 + Suricata(52,752 条 ET 规则) 并行 | dnscat2 的 4,837 条告警 → 1 条结论 |
| 成本 | 0 元 | 全部本地 Ollama |

> 数字不好看没关系，**能解释为什么**才是重点。比如 recall@6 只有 0.89，我会说：
> 3 道题失败在「LangChain 与 LangGraph 文档内容重叠」，属于语料本身的歧义，不是检索器的问题。

---

## 三、领域知识库：网络流量检测（NIDS）

技术文档库证明「会做 RAG」，领域库证明「能在自己的方向上做出东西」。所以项目内置了第二个知识库 `ids`。

### 语料：三类源、三种格式

| 来源 | 内容 | 格式 | 为什么需要 |
|---|---|---|---|
| **Suricata** `OISF/suricata` → `doc/userguide` | 规则关键字、`eve.json`、抓包性能 | reStructuredText | 规则怎么写、字段什么含义 |
| **Zeek** `zeek/zeek-docs` | 日志字段、脚本语言、Notice / Intel / SumStats 框架 | reStructuredText | 事件从哪拿、策略怎么写 |
| **nDPI** `ntop/nDPI` → `doc` | 流风险定义、协议识别 | RST | 加密流量的风险标签 |
| **IETF RFC** 791/793/768/792/1035/8446/9110 | IP、TCP、UDP、ICMP、DNS、TLS、HTTP 规范 | 定宽纯文本 | 协议事实的权威来源 |
| **arXiv** 18 篇论文 | 入侵检测、加密流量分类、无监督异常检测、LLM 日志安全 | HTML（LaTeXML） | 方法论与数据集 |
| **MITRE ATT&CK**（721 篇） | 700+ 技术的描述与检测建议、15 个战术 | STIX 2.1 → Markdown | 蓝队事实标准，「这个行为对应哪个技术」 |
| **Sigma** 文档 | 规则规范与日志源字段映射 | Markdown | 检测工程事实标准 |

一句话：**NIDS 没有一份覆盖全部内容的文档**，知识散在「工具文档 / 协议规范 / 论文」三类源里，而且格式各不相同。
这也是这个领域真正的工作量所在 —— 不是找不到数据，是数据不齐、格式不一。

### 三种格式怎么统一

`app/ingest/converters.py` 在接入层做格式归一化，输出统一 Markdown，下游分块/索引完全不用改：

- **RST → MD**：标题下划线/上划线转 `#`、`.. code-block::` 转围栏、`.. note::` 转引用块、`.. toctree::`/图片/包含指令丢弃、`:ref:` 这类角色去掉；
- **RFC → MD**：去分页符与页眉页脚，靠「下一行是空行且不含点线」识别章节标题 —— RFC 目录行长这样 `1.  INTRODUCTION ....... 1`，不加这条规则会把整份目录当标题；
- **arXiv HTML → MD**：BeautifulSoup 取正文、MathML 的 `alttext` 保留公式、html2text 转换，公式和表格结构不丢。

### 建库与效果

```bash
python scripts/fetch_domain_corpus.py --proxy http://127.0.0.1:7890
python scripts/build_index.py --kb ids
```

产物：**1,265 篇文档 / 16,180 个片段**；22 题领域评测集成绩 **recall@6 1.00、MRR 0.84、nDCG@6 0.88**。

### 知识库覆盖（都是业内常用的源）

| 层 | 覆盖内容 |
|---|---|
| 协议事实 | RFC 791/793/768/792/1035/8446/9110 |
| 检测引擎 | Suricata 规则/输出、Zeek 脚本与日志字段、nDPI 风险 |
| 攻击知识 | **MITRE ATT&CK 700+ 技术 + 15 战术**（含检测建议），Sigma 规则规范 |
| 研究前沿 | 18 篇 arXiv（加密流量、异常检测、LLM 日志安全） |

这四层刚好对应安全分析的四个问题：**协议长什么样 → 引擎怎么配 → 攻击叫什么 → 学界怎么看**。

### 跨来源噪声：`sources` 过滤

混合语料有个副作用：问「Suricata 规则怎么写」，可能同时召回 nDPI 的风险定义和 RFC 原文。
检索层因此支持按来源子集过滤：

```bash
curl -N -X POST localhost:8000/api/chat -H 'Content-Type: application/json' \
  -d '{"question":"Suricata 怎么检测可疑 User-Agent","kbs":["ids"],"sources":["suricata"]}'
```

实测：过滤后单题耗时从 53s 降到 16s，引用从 3 条（含无关来源）变成 2 条纯 Suricata 文档。

这也解释了「多知识库」和「单库多来源」的分工：分库更适合**主题差异大**（技术文档 vs 领域文档），
`kbs` 多选即可跨库检索；单库多来源适合**同一主题的不同侧面**（工具/规范/论文），用 `sources` 收窄。

## 四、流量取证 Agent：pcap → 可复核的报告

知识库解决「怎么解释」，但安全分析的一半是「看证据」。这一节把 pcap 接进来，
做成一条和文档 RAG 平行的链路：

```
pcap ──▶ tshark 结构化提取 ──▶ 规则引擎（扫描/DNS隧道/beacon/可疑HTTP）
                                      │  每条命中都带证据包号
                                      ▼
                              LangGraph Agent
                    triage（决定查什么）→ collect（补证据）
                              → ground（查 ids 知识库）
                              → report → verify（包号 + 文档引用双校验）
                                      │
                                      ▼
                   结论 + [pkt #12] + [K1] 双证据链
```

### 确定性优先（照搬 pcap-hunter 的哲学）

| 层 | 负责什么 | 出了问题会怎样 |
|---|---|---|
| tshark | 协议解析、字段提取 | 不会，20 年积累 |
| 规则引擎 | 计数、周期性、熵值等可解释判定 | 阈值可调，结论可复现 |
| LLM | 解释「为什么可疑、对应哪种攻击、怎么处置」 | 最坏情况是解释得不好，**不会凭空造出包** |

所以模型挂了、Ollama 没启动，`GET /api/traffic/findings/{pcap}` 依然返回完整的事实清单。

### 四个可复现的样本

`python scripts/make_sample_pcaps.py` 用 scapy 生成，随仓库提交到 `tests/fixtures/`：

| 样本 | 内容 | 预期检测 |
|---|---|---|
| `benign_web.pcap` | DNS + HTTP 正常访问 | **0 命中**（验证不误报） |
| `port_scan.pcap` | 单源扫 120 个端口，SYN 不走完握手 | `port_scan` (high) |
| `dns_tunnel.pcap` | 40 个高熵长域名查询 | `dns_tunnel` (medium) |
| `beacon_c2.pcap` | 每 60 秒一次 HTTP 心跳 + 明文 HTTP 打 443 | `beacon` + `cleartext_http` + `suspicious_http` |

### 怎么用

```bash
# 界面：右上角「流量取证」→ 选样本 → 看报告（SSE 流式 + 执行轨迹）

# 只跑确定性分析，不调 LLM（秒回）
curl localhost:8000/api/traffic/findings/samples/port_scan.pcap

# 完整 Agent 报告
curl -N -X POST localhost:8000/api/traffic/analyze \
  -H 'Content-Type: application/json' \
  -d '{"pcap":"samples/beacon_c2.pcap","question":"这是不是 C2 外联？"}'
```

实测：端口扫描 39s，C2 beacon 16s（CPU 跑 8B 模型）。报告形如：

```
## 结论
高度疑似 C2 外联：12 次连接间隔高度规律（CV=0.00）[pkt #1,#4,#7...]，
443 端口出现明文 HTTP [pkt #3,#6,#9...]
## 证据链 / ## 建议处置 / ## 参考文档 [K1]..[K4]
```

### 多 Agent 融合：行为检测 + 签名检测

单个检测器一定会有盲区：行为规则抓不到「只有几个包的漏洞利用」，签名规则抓不到「未知变种」。
所以拆成两个 Agent 并行跑，再仲裁：

```
                ┌─────────────────────────────┐
                │  behavior Agent             │  统计/行为：扫描、爆破、beacon、隧道
START ──────────┤                             ├──┐
                │  signature Agent            │  │   Suricata 8.0.7 + ET Open（52,752 条规则）
                └─────────────────────────────┘  │
                                                 ▼
                                    fuse（实体关联 + 置信度 + 攻击阶段）
                                                 │
                                    ground → report → verify
```

LangGraph 里 `behavior` 和 `signature` 在同一超级步并发，`fuse` 等两者都完成才执行（fan-out / join）。

**融合不是拼接**，做了三件事：

1. **实体关联**：行为 Agent 说「186.220.245.254 → 192.168.0.2:23 重试 42 次」，
   签名 Agent 说「192.168.0.2:23 → 攻击者:xxxxx 命中 GPL TELNET root login」——
   方向是反的，只能按 `(IP, 端口)` 关联。先端口级匹配，端口对不上才退化成 IP 级，
   否则一个受害者 IP 会把所有无关流合并进来（这是第一版踩的坑）。
2. **定级**：双源印证 0.93 / 仅签名 0.78 / 仅行为 0.55；`ET INFO` 这类信息规则不参与定级。
3. **排序**：按攻击阶段（侦察 → 凭据 → 利用 → C2 → 外传）而不是按告警条数。

真实效果（Mirai 样本）：

| Agent | 原始输出 |
|---|---|
| behavior | 1 条（42 次重试） |
| signature | **144 条告警 / 75 个流** |
| 融合后 | **1 条双源印证（0.93）+ 3 条单源线索** |

dnscat2 更夸张：**4,837 条 Suricata 告警 → 融合成 1 条「数据外传」结论**。
这正是需要融合层的原因——原始告警不可能直接喂给 LLM。

```bash
# 规则与镜像（一次性）
python scripts/fetch_suricata_rules.py

# 多 Agent 分析
curl -N -X POST localhost:8000/api/traffic/analyze \
  -H 'Content-Type: application/json' \
  -d '{"pcap":"real/mirai/2016-11-07-10:35.pcap","mode":"multi"}'
```

界面里每个 pcap 现在有两个按钮：**单 Agent** / **多 Agent 融合**。
没有 docker 时签名 Agent 自动降级，行为检测照常工作。

### 在真实恶意流量上验证（不是自己造的数据）

自己造的样本只能证明代码跑得通。所以从公开仓库拉了 **30 份真实恶意流量 + 1 份正常 RDP** 做误报对照：

```bash
python scripts/fetch_real_pcaps.py          # SpiderLabs/IOCs-IDPS，约 19MB，不入 git
python scripts/benchmark_real.py --with-signature --write-doc   # 结果写入 docs/
```

| 指标 | 数值 |
|---|---|
| 恶意样本 | 30 份（APT41、Mirai、Emotet、Locky、Petya、PrintNightmare、Heartbleed…） |
| **合计检出** | **25/30（83%）** |
| 行为引擎单独 | 9/30 |
| 签名引擎补足 | +16 |
| 误报对照 | 0/1 触发 |

这个数字是这套多 Agent 架构最直接的证据：**单靠行为规则只能抓 30%，加上 Suricata 签名后到 83%**。

漏掉的 5 份是单包漏洞利用（BlueKeep、PrintNightmare 扫描/SMBv1、WebLogic 反序列化、Drupalgeddon2）——
只有几个包、没有可统计的行为模式，ET Open 也没有覆盖，属于签名与行为共同的能力边界。

完整明细与归因：`docs/REAL_TRAFFIC_BENCHMARK.md`。

### 自动映射 ATT&CK：检测结果 → 技术编号

安全报告里最有价值的一句话往往是「这次覆盖了哪些 ATT&CK 技术」。所以加了一层映射：

| 层 | 输入 | 方法 | 置信度 |
|---|---|---|---|
| 静态 | 行为检测的 kind | 查表（扫描→T1046、爆破→T1110、DNS隧道→T1071.004） | high |
| 关键词 | Suricata 签名文本 | `scan/brute/exploit/ransom/mimikatz…` → 技术 | medium |
| 语义 | 前两者都没命中时 | **用 721 篇 ATT&CK 技术文档做检索**，取最相关的一篇 | low |

第三层是复用现有能力：`retriever.search(..., prefixes=["mitre/techniques"])`，
不需要再维护几百条关键词规则。低置信度会明确标注，避免「猜出来的技术」被当成结论。

**但这层兜底实测下来不成立**，我把它做成了默认关闭的实验开关：

| 方案 | 覆盖率（总体） | 加权准确率 | 7 条待兜底里救回 |
|---|---:|---:|---:|
| 静态 + 关键词（默认） | 51.7%（15/29） | 60.3% | — |
| + ATT&CK 知识库语义检索 | 75.9%（22/29） | 60.3% | 0~1 / 7 |
| + LLM 受限分类（Qwen2.5-3B） | 72.4%（21/29） | 58.6% | 0~2 / 7 |

