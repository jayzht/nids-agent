# 相关工作调研：Agent × 流量检测（NIDS）

> 调研时间：2026-10 · 数据来源：GitHub Search API、arXiv API、项目 README 原文
> 用途：给自己的项目定位，也是面试时「你知道这个赛道做到什么程度了吗」的答案。

## 结论先行

这个方向**不是空白**，但存在一个明显的结构性错位：

- **做的人很多的是「告警研判」**：拿 SIEM 告警/日志，让 agent 调查、关联、出结论。项目成熟、star 高，但和「流量」本身关系不大。
- **做的人少的是「原始流量语义」**：从 pcap/flow 里读出攻击意图，或者反过来生成检测规则。这块工程门槛高（要懂协议、要能跑 Zeek/Suricata），但学术上更热。
- **几乎没人做的是「流量证据 + 文档知识」的联合推理**：agent 一边看包，一边查「这条规则该怎么写」「这个字段是什么含义」。这恰好是当前项目 `ids` 知识库能补上的位置。

## 一、开源项目（按类型分）

### A. SOC / 告警研判 Agent（成熟，star 高）

| 项目 | ★ | 技术栈 | 一句话 | 对我们的价值 |
|---|---|---|---|---|
| [beenuar/AiSOC](https://github.com/beenuar/AiSOC) | 3.6k | LangGraph + MCP + MITRE ATT&CK | 开源自托管 AI SOC：告警融合、agent 研判、**每一步决策可回放审计** | 架构最值得抄：可审计决策账本 + MCP server 设计 |
| [FunnyWolf/agentic-soc-platform](https://github.com/FunnyWolf/agentic-soc-platform) | 1.2k | Dify / LangChain / LangGraph | 国人项目，agent 为中心的安全运营平台，有中文文档 | 中文社区参照物；看它怎么做「工作区 + 案例」 |
| [SecurityClaw/SecurityClaw](https://github.com/SecurityClaw/SecurityClaw) | 278 | Skill 体系 | 基于技能的自治 SOC agent，监听 OpenSearch/ES | 「技能化」的工具抽象方式 |
| [zhadyz/AI_SOC](https://github.com/zhadyz/AI_SOC) | 172 | Wazuh + Ollama + RAG | 本地化 SOC：Wazuh 接入、本地模型研判、检索安全知识、Sigma 规则导出 | **和本项目最像的工程结构**：本地模型 + RAG + 多 agent |
| [gensecaihq/Wazuh-Autopilot](https://github.com/gensecaihq/Wazuh-Autopilot) | 60 | Strands Agents | 13 个 agent 的 swarm，37 个 Wazuh 技能 | 多 agent 拆分粒度参考 |

### B. 流量 / 包分析 Agent（和「流量检测」最贴）

| 项目 | ★ | 技术栈 | 一句话 | 对我们的价值 |
|---|---|---|---|---|
| [0xKoda/WireMCP](https://github.com/0xKoda/WireMCP) | 599 | MCP + tshark | 把 tshark 包成 MCP 工具：抓包、协议统计、会话统计、威胁情报比对、pcap 分析 | **「手」的标准做法**：确定性工具交给 tshark，LLM 只做解释 |
| [ninedter/pcap-hunter](https://github.com/ninedter/pcap-hunter) | 166 | Zeek + tshark + Streamlit | AI 辅助威胁狩猎工作台：C2/beacon 检测、JA3 指纹、ATT&CK 映射、OSINT、报告 | **工程化标杆**：确定性证据始终可用，LLM 只是可选增强 |
| [pzambare3/NetMoniAI](https://github.com/pzambare3/NetMoniAI) | 36 | 论文实现 | 每个节点跑微 agent 做本地流量分析，中心控制器聚合检测协同攻击 | 分布式 agent 架构（论文 2508.10052） |
| [GH05TCREW/eidolon](https://github.com/GH05TCREW/eidolon) | 19 | Neo4j | 扫描资产建图，用自然语言执行安全运营操作 | 图存储 + NL 查询的组合 |
| [Nikhil-creat/AI-NIDS-RAG-SOC-Platform](https://github.com/Nikhil-creat/AI-NIDS-RAG-SOC-Platform) | 4 | CICIDS + RF/IForest + SHAP + Chroma + Gemini | 检测模型 → SHAP 解释 → RAG 查 MITRE → 三个 agent 串联自动响应 | **最接近「检测 + RAG + agent」的完整小项目**，但很浅 |

### C. 商业产品（闭源，只能看方向）

国内外安全厂商的安全大模型/SOC 助手基本都聚焦「告警研判、事件调查、报告生成」，不碰原始流量解析。
这条路线上，开源项目已经把「SOC agent」做成了红海。

## 二、学术前沿（arXiv，2024–2026）

| 论文 | 主题 | 为什么值得看 |
|---|---|---|
| [2507.04752](https://arxiv.org/abs/2507.04752) | LLMs for NIDS: Foundations, Implementations, Future Directions | **必读综述**，把「LLM 在 NIDS 里能干什么」分成了几层 |
| [2512.22223](https://arxiv.org/abs/2512.22223) | ReGAIN: Retrieval-Grounded AI Framework for Network Traffic Analysis | **检索增强直接用在流量分析上**：流量摘要 + 检索 + 生成，与本项目思路同源 |
| [2609.16231](https://arxiv.org/abs/2609.16231) | RuleAutoPilot: Synthesizing Deployable Suricata Rules from Network Traffic | 从真实流量**生成可部署的 Suricata 规则**，直击「规则编写」痛点 |
| [2607.28100](https://arxiv.org/abs/2607.28100) | PCAP-LM: LLM-Native Text Representation for TLS Bulk Traffic | 怎么把 pcap 变成 LLM 能吃的文本（表示层问题） |
| [2504.04222](https://arxiv.org/abs/2504.04222) | TrafficLLM | 通用流量表示 + 微调，解决「流量特征和文本空间不对齐」 |
| [2503.20798](https://arxiv.org/abs/2503.20798) | Payload-Aware IDS with CMAE and LLMs | 不看统计特征，直接看 payload 语义 |
| [2605.21773](https://arxiv.org/abs/2605.21773) | HIDBench | **评测基准**：LLM 做主机侧入侵检测到底行不行 |
| [2607.14493](https://arxiv.org/abs/2607.14493) | Context Contamination in LLM Analysis of Network Security Logs | **安全 agent 的命门**：日志里可以藏被动 prompt injection |
| [2608.05199](https://arxiv.org/abs/2608.05199) | Post-Hoc Trajectory-Risk Certification for LLM Security Agents | 事后给 agent 轨迹做风险认证 |
| [2404.13402](https://arxiv.org/abs/2404.13402) | Intrusion Detection at Scale with a Command-line LM | 命令行文本当输入做大规模入侵检测 |

## 三、差距在哪（也是机会在哪）

看完全部项目，有四个共同的空白：

1. **「会看包」和「会查文档」是割裂的**
   WireMCP 给包、pcap-hunter 给报告，但没人让 agent 在分析时去查「Suricata 这条规则该用什么关键字」「TLS 1.3 的 record 结构是什么」。
   → 这正是 `ids` 知识库的位置：**把协议规范和工具文档变成 agent 的一个工具**。

2. **评估几乎没有**
   除了 HIDBench 这类基准，工业项目普遍只展示 demo，不讲 recall/误报率/引用准确率。
   → 本项目已有的 golden set + recall/MRR/nDCG 是稀缺品，可以成为差异点。

3. **提示注入完全没防**
   流量日志里可以埋 `ignore previous instructions`，而 agent 会把日志当上下文。
   现有项目 0 防护。→ 加一层「日志内容隔离 + 指令消毒 + 引用白名单」，是很好的面试谈资。

4. **不会解释「为什么不是攻击」**
   所有项目都在讲「检测到了什么」，没人做「排除」——而安全分析师 80% 的时间在做误报排除。

## 四、如果要在这个方向立项，三个可行切口

**切口 A：流量取证 + 文档知识的联合 Agent（✅ 已实现，见 README 第四节）**
```
pcap/flow  ──▶ Zeek/tshark 工具（确定性）
                    │
                    ▼
            LangGraph Agent ──▶ 工具: 查询规则写法/字段含义（本项目 ids KB）
                    │               查询 ATT&CK 技术描述
                    ▼
            结论 + 证据链（每个结论都要能指回包和文档）
```
差异化：**「结论可追溯到第 N 个包 + 第 M 篇文档」**，现在的项目都没做到。

**切口 B：规则生成闭环**
输入一批恶意流量样本 → agent 生成 Suricata 规则 → 用真实流量回放验证 → 自动修规则。
对应 RuleAutoPilot，但你可以用本地环境 + 公开数据集做，成本低。

**切口 C：抗注入的日志分析**
把「日志 = 不可信数据」写进架构：内容隔离、指令白名单、输出校验。
论文 2607.14493 证明了攻击可行，但没给工程方案。

## 五、面试里怎么用这份调研

一句话版：

> 我调研过这个方向。开源侧 AiSOC（3.6k star）和 pcap-hunter 已经把「SOC 告警研判」和「pcap 威胁狩猎」做得很完整，
> 学术侧 ReGAIN 和 RuleAutoPilot 分别解决了「检索增强的流量分析」和「规则自动生成」。
> 但它们有两个共同空白：一是「看包」和「查文档」是割裂的，二是几乎没有可复现的评估。
> 我的项目从「文档知识 + 可评测检索」切入，正好补这两块。

这段话的作用不是炫耀，而是告诉面试官：**你知道自己在赛道里的位置，不是闭门造车。**

## 六、本项目实际照搬了什么

| 来源 | 照搬的东西 | 落在哪个文件 |
|---|---|---|
| WireMCP | 把 tshark 包成受控工具、过滤器白名单 | `app/traffic/tools.py` |
| pcap-hunter | **确定性证据优先**：LLM 挂了也要能出结论 | `app/traffic/analyzer.py` |
| AiSOC | agent 每步可回放的轨迹（steps 事件） | `app/agent/traffic_graph.py` |
| ReGAIN | 检索增强用在「解释层」而不是「检测层」 | `node_ground` |
| RuleAutoPilot | 检测结论要落到可执行的规则建议 | `REPORT_SYSTEM` 的「建议处置」 |
| 论文 2607.14493 | **未实现**：日志/流量里的指令注入没有隔离 | 记在 README「已知问题」 |

再强调一次定位：本项目做的是**知识层 + 取证层**，不做检测模型、不做分布式探针。
那两块别人已经做得很好，重复造没有意义。
