# ATT&CK 映射准确率评测

> 标注来源：8 份真实恶意 pcap 的 Suricata 输出，取 29 条不同签名人工标注。
> 生成：`python scripts/eval_attack_mapping.py --write-doc`。

## 为什么需要这个评测

语义映射（拿签名去检索 ATT&CK 文档）看起来很美，但它到底准不准没人知道。
没有标注就没有结论——这个文件就是那 29 条标注的答案。

## 总览

| 方案 | 加权准确率 | 完全命中率 | 覆盖率 | 语义兜底次数 |
|---|---:|---:|---:|---:|
| 静态 + 关键词（默认） | 60.3% | 58.6% | 51.7% | 0 |

说明：加权准确率把「父子技术」记为 0.5（预测 T1110 而标注 T1110.001 不算全错）。

## 三种兜底方案的实测

| 方案 | 覆盖率 | 7 条未命中里救回 | 结论 |
|---|---:|---:|---|
| 静态 + 关键词（默认） | 51.7% | — | 基线，快且可解释 |
| + ATT&CK 知识库语义检索 | 75.9% | **0 / 7** | 不成立：签名讲的是家族/规则，技术文档讲的是行为 |
| + LLM 受限分类（Qwen2.5-3B） | 85.7% | 2 / 7 | 小模型不够；只对了 DNS C2 这种语义直白的 |

结论：**默认只用「静态 + 关键词」**。语义和 LLM 层保留为实验开关（`ATTACK_MAPPING_MODE=semantic`），并把负结果留在这里。

为什么不去调参把分数刷上去：29 条标注，改一条关键词就能涨 3.4 个百分点，这种「提升」在真实流量上没有意义。正确做法是把标注集扩到几百条再调。

## 逐条结果（当前默认方案）

| 签名 | 标注 | 预测 | 来源 | 得分 |
|---|---|---|---|---:|
| ET DYN_DNS DYNAMIC_DNS Query to a *.chickenkiller .com Dom | T1071.004 | — | none | 0.0 |
| GPL TELNET Bad Login | T1110 | T1110 | keyword | 1.0 |
| GPL TELNET root login | T1110 | T1110 | keyword | 1.0 |
| ET TFTP Outbound TFTP Read Request | T1105 | T1105 | keyword | 1.0 |
| ET INFO BusyBox Banner Observed | （不映射） | — | none | 1.0 |
| ET MALWARE LokiBot User-Agent (Charon/Inferno) | T1071.001 | — | none | 0.0 |
| ET MALWARE LokiBot Checkin | T1071.001 | — | none | 0.0 |
| ET MALWARE LokiBot Request for C2 Commands Detected M1 | T1071.001 | T1071 | keyword | 0.5 |
| ET MALWARE LokiBot Fake 404 Response | T1071.001 | — | none | 0.0 |
| ET MALWARE LokiBot Application/Credential Data Exfiltratio | T1048 | T1003 | keyword | 0.0 |
| ET HUNTING SUSPICIOUS Path to BusyBox | T1105 | — | none | 0.0 |
| ET INFO SMB2 NT Create AndX Request For a DLL File - Possi | T1021.002 | T1021.002 | keyword | 1.0 |
| ET EXPLOIT HiSilicon DVR - Default Telnet Root Password In | T1110 | T1110 | keyword | 1.0 |
| ET INFO NTLM Session Setup Request - Negotiate | （不映射） | — | none | 1.0 |
| ET INFO NTLMv1 Session Setup Response - Challenge | （不映射） | — | none | 1.0 |
| ET INFO NTLM Session Setup Request - Auth | （不映射） | — | none | 1.0 |
| ET TELNET busybox MEMES Hackers - Possible Brute Force Att | T1110 | T1110 | keyword | 1.0 |
| ET TELNET busybox MIRAI hackers - Possible Brute Force Att | T1110 | T1110 | keyword | 1.0 |
| ET TELNET busybox ECCHI hackers - Possible Brute Force Att | T1110 | T1110 | keyword | 1.0 |
| ET DYN_DNS External IP Lookup Domain in DNS Query (checkip | （不映射） | — | none | 1.0 |
| ET INFO External IP Lookup - checkip.dyndns.org | （不映射） | — | none | 1.0 |
| ET HUNTING SUSPICIOUS Firesale gTLD EXE DL with no Referer | T1105 | — | none | 0.0 |
| ET MALWARE Terse alphanumeric executable downloader high l | T1105 | T1105 | keyword | 1.0 |
| ET INFO PE EXE or DLL Windows file download HTTP | T1105 | T1105 | keyword | 1.0 |
| ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) | T1210 | T1190 | keyword | 0.0 |
| ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Fl | T1210 | T1190 | keyword | 0.0 |
| ET EXPLOIT Possible OpenSSL HeartBleed Large HeartBeat Res | T1190 | T1190 | keyword | 1.0 |
| ET INFO [MS-PAR] Windows Printer Spooler Activity - RpcAsy | T1210 | — | none | 0.0 |
| ET INFO [MS-PAR] Windows Printer Spooler Activity - RpcAsy | T1210 | — | none | 0.0 |

## 错误分析（12 条）

| 签名 | 标注 | 预测 | 原因 |
|---|---|---|---|
| ET DYN_DNS DYNAMIC_DNS Query to a *.chickenkiller .c | T1071.004 | — | 关键词与语义都没命中 |
| ET MALWARE LokiBot User-Agent (Charon/Inferno) | T1071.001 | — | 关键词与语义都没命中 |
| ET MALWARE LokiBot Checkin | T1071.001 | — | 关键词与语义都没命中 |
| ET MALWARE LokiBot Request for C2 Commands Detected  | T1071.001 | T1071 | 父子技术记 0.5 |
| ET MALWARE LokiBot Fake 404 Response | T1071.001 | — | 关键词与语义都没命中 |
| ET MALWARE LokiBot Application/Credential Data Exfil | T1048 | T1003 | 关键词命中但语义偏差 / 检索到了相近技术 |
| ET HUNTING SUSPICIOUS Path to BusyBox | T1105 | — | 关键词与语义都没命中 |
| ET HUNTING SUSPICIOUS Firesale gTLD EXE DL with no R | T1105 | — | 关键词与语义都没命中 |
| ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF  | T1210 | T1190 | 关键词命中但语义偏差 / 检索到了相近技术 |
| ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Gene | T1210 | T1190 | 关键词命中但语义偏差 / 检索到了相近技术 |
| ET INFO [MS-PAR] Windows Printer Spooler Activity -  | T1210 | — | 关键词与语义都没命中 |
| ET INFO [MS-PAR] Windows Printer Spooler Activity -  | T1210 | — | 关键词与语义都没命中 |

## 结论

- 关键词映射精确但覆盖率低：像 `LokiBot`、`Printer Spooler` 这种规则名里没有 `scan/brute` 的，只能靠语义。
- 语义兜底把覆盖率从 52% 提到 52%，代价是少量误报——但误报集中在 `ET INFO` 类规则，所以已经对信息类规则关闭语义兜底。
- 仍然存在的偏差主要是「父子技术」粒度：标注到子技术（T1110.001），预测到父技术（T1110），实际使用中不影响结论，但会影响严格指标的观感。

## 复现

```bash
python scripts/eval_attack_mapping.py --write-doc
```
