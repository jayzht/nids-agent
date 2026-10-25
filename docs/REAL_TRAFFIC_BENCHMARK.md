# 真实恶意流量验证结果

> 数据来源：SpiderLabs/IOCs-IDPS（公开 IOC/PCAP 仓库），样本不入库，用 `scripts/fetch_real_pcaps.py` 按需下载。
> 生成方式：`python scripts/benchmark_real.py --write-doc`。

## 为什么要做这件事

自己造的样本只能证明「代码能跑」，证明不了「检测有用」。
所以拿真实恶意流量跑一遍，并且**把漏检名单也列出来**——
漏检不是失败，是告诉你「行为规则的能力边界在哪」。

## 结果：5/12 份恶意样本产生告警（42%）

| 样本 | 家族 | 包数 | 期望检测 | 实际命中 | 结果 |
|---|---|---:|---|---|---|
| `dnscat2` | CobaltStrike/C2 隧道 | 10000 | dns_tunnel | dns_tunnel | ✔ 检出 |
| `ps-empire` | PowerShell Empire | 10000 | beacon | repeated_attempts, beacon | ✔ 检出 |
| `blacknet` | BlackNET botnet | 12965 | beacon | beacon, repeated_attempts | ✔ 检出 |
| `bot_scanner` | Bot/Scanner | 2686 | repeated_attempts | repeated_attempts | ✔ 检出 |
| `mirai` | Mirai | 4519 | repeated_attempts | repeated_attempts | ✔ 检出 |
| `njrat` | njRAT | 1963 | beacon | — | ✘ 漏检 |
| `lokibot` | LokiBot | 753 | — | — | ✘ 漏检 |
| `emotet` | Emotet | 676 | — | — | ✘ 漏检 |
| `hancitor` | Hancitor | 436 | — | — | ✘ 漏检 |
| `printnightmare` | PrintNightmare 扫描 | 1910 | port_scan | — | ✘ 漏检 |
| `bluekeep` | CVE-2019-0708 | 59 | — | — | ✘ 漏检 |
| `predator` | Predator RAT | 2079 | — | — | ✘ 漏检 |
| `normal_rdp` | 正常 RDP（误报对照） | 5126 | __none__ | — | ✔ 未误报 |

- 恶意样本：**12** 份，产生告警 **5** 份
- 误报对照（合法 RDP 流量）：1 份，误报 **0** 份

## 漏检的为什么漏（能力边界）

| 漏检样本 | 原因 | 该怎么补 |
|---|---|---|
| `bluekeep`、`printnightmare` | 漏洞利用，只有几个包，没有可统计的行为模式 | **签名检测**（Suricata 规则 / 漏洞特征） |
| `emotet`、`hancitor`、`lokibot`、`predator` | TLS/HTTP 下载器与窃密木马，行为上像正常访问 | 威胁情报（域名/IP 信誉）+ 载荷特征 |
| `njrat` | 单条长连接内的加密 C2，不反复建连 | TLS 指纹（JA3）+ 会话行为基线 |

结论：**行为规则只能覆盖「扫描 / 爆破 / 隧道 / 心跳」这类有统计规律的攻击**，
覆盖不了漏洞利用和加密外联。这也正是要接 SIEM（Suricata 签名告警）的原因——
两者互补，而不是互相替代。

## 复现

```bash
python scripts/fetch_real_pcaps.py      # 按需下载（约 15MB）
python scripts/benchmark_real.py --write-doc
```
