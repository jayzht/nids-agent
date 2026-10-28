# 真实恶意流量验证结果

> 数据来源：SpiderLabs/IOCs-IDPS（公开 IOC/PCAP 仓库），样本不入库，用 `scripts/fetch_real_pcaps.py` 按需下载。
> 生成方式：`python scripts/benchmark_real.py --write-doc`。

## 为什么要做这件事

自己造的样本只能证明「代码能跑」，证明不了「检测有用」。
所以拿真实恶意流量跑一遍，并且**把漏检名单也列出来**——
漏检不是失败，是告诉你「行为规则的能力边界在哪」。

## 结果：29/30 份恶意样本产生告警（97%）

| 样本 | 家族 | 包数 | 行为命中 | 签名告警 | 结果 |
|---|---|---:|---|---:|---|
| `dnscat2` | CobaltStrike/C2 隧道 | 10000 | dns_tunnel | 4837 | ✔ 检出 |
| `ps-empire` | PowerShell Empire | 10000 | repeated_attempts, beacon | 0 | ✔ 检出 |
| `blacknet` | BlackNET botnet | 12965 | beacon, repeated_attempts | 4525 | ✔ 检出 |
| `bot_scanner` | Bot/Scanner | 2686 | repeated_attempts | 12 | ✔ 检出 |
| `mirai` | Mirai | 4519 | repeated_attempts | 144 | ✔ 检出 |
| `njrat` | njRAT | 1963 | — | 1 | ✔ 检出 |
| `njrat_win7` | njRAT | 30 | — | 3 | ✔ 检出 |
| `adwind` | Adwind RAT | 667 | cleartext_http | 0 | ✔ 检出 |
| `apt41_cs` | APT41 CobaltStrike | 480 | cleartext_http | 1 | ✔ 检出 |
| `agenttesla` | Agent Tesla | 803 | — | 2 | ✔ 检出 |
| `amadey` | Amadey | 129 | — | 1 | ✔ 检出 |
| `artemis` | Artemis | 257 | — | 3 | ✔ 检出 |
| `avemaria` | AveMaria | 566 | — | 3 | ✔ 检出 |
| `predator` | Predator RAT | 2079 | — | 4 | ✔ 检出 |
| `lokibot` | LokiBot | 753 | — | 29 | ✔ 检出 |
| `emotet` | Emotet | 676 | — | 2 | ✔ 检出 |
| `hancitor` | Hancitor | 436 | — | 5 | ✔ 检出 |
| `flawedammyy` | FlawedAmmyy | 18 | — | 1 | ✔ 检出 |
| `powershell_loader` | PowerShell Loader | 646 | — | 1 | ✔ 检出 |
| `ta505` | TA505 | 1359 | — | 7 | ✔ 检出 |
| `bluekeep` | CVE-2019-0708 | 59 | — | 2 | ✔ 检出 |
| `printnightmare` | PrintNightmare 扫描 | 1910 | — | 5 | ✔ 检出 |
| `printnightmare_smbv1` | PrintNightmare SMBv1 | 733 | — | 16 | ✔ 检出 |
| `printnightmare_mimikatz` | PrintNightmare Mimikatz | 237 | — | 9 | ✔ 检出 |
| `weblogic` | CVE-2017-10271 | 12 | — | 0 | ✘ 漏检 |
| `drupal` | CVE-2018-7600 | 22 | — | 1 | ✔ 检出 |
| `weblogic_poc` | CVE-2019-2725 | 12 | cleartext_http | 0 | ✔ 检出 |
| `heartbleed` | Heartbleed | 65 | — | 1 | ✔ 检出 |
| `petya` | Petya | 2000 | cleartext_http | 5 | ✔ 检出 |
| `locky` | Locky | 1057 | — | 8 | ✔ 检出 |
| `normal_rdp` | 正常 RDP（误报对照） | 5126 | — | 0 | ✔ 未误报 |

- 恶意样本：**30** 份，产生告警 **29** 份
- 其中行为引擎命中 **9** 份，签名检测补足 **20** 份
- 误报对照（合法 RDP 流量）：1 份，误报 **0** 份

## 漏检的为什么漏（能力边界）

| 漏检样本 | 包数 | 家族 | 原因 |
|---|---:|---|---|
| `weblogic` | 12 | CVE-2017-10271 | 包数极少，没有可统计的行为模式；ET Open 也未覆盖该利用 |

结论：**行为规则抓统计规律（扫描/爆破/隧道/心跳），签名规则抓已知特征**。
两者盲区不重叠，所以组合起来才能从 9/30 提到 29/30。

签名侧还踩过一个坑：Suricata 默认校验 checksum，而抓包/回放的样本经常带无效校验和，
大量规则因此不匹配。加上 `-k none` 之后，bluekeep、printnightmare、drupal 这些
「单包漏洞利用」样本才被 ET Open 规则命中（25/30 → 29/30）。
**这类问题不看引擎日志根本发现不了**：不报错，只是安静地少检出。

## 复现

```bash
python scripts/fetch_real_pcaps.py      # 按需下载（约 15MB）
python scripts/benchmark_real.py --write-doc
```
