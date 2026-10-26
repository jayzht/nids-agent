# 真实恶意流量验证结果

> 数据来源：SpiderLabs/IOCs-IDPS（公开 IOC/PCAP 仓库），样本不入库，用 `scripts/fetch_real_pcaps.py` 按需下载。
> 生成方式：`python scripts/benchmark_real.py --write-doc`。

## 为什么要做这件事

自己造的样本只能证明「代码能跑」，证明不了「检测有用」。
所以拿真实恶意流量跑一遍，并且**把漏检名单也列出来**——
漏检不是失败，是告诉你「行为规则的能力边界在哪」。

## 结果：25/30 份恶意样本产生告警（83%）

| 样本 | 家族 | 包数 | 行为命中 | 签名告警 | 结果 |
|---|---|---:|---|---:|---|
| `dnscat2` | CobaltStrike/C2 隧道 | 10000 | dns_tunnel | 4837 | ✔ 检出 |
| `ps-empire` | PowerShell Empire | 10000 | repeated_attempts, beacon | 0 | ✔ 检出 |
| `blacknet` | BlackNET botnet | 12965 | beacon, repeated_attempts | 4525 | ✔ 检出 |
| `bot_scanner` | Bot/Scanner | 2686 | repeated_attempts | 11 | ✔ 检出 |
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
| `bluekeep` | CVE-2019-0708 | 59 | — | 0 | ✘ 漏检 |
| `printnightmare` | PrintNightmare 扫描 | 1910 | — | 0 | ✘ 漏检 |
| `printnightmare_smbv1` | PrintNightmare SMBv1 | 733 | — | 0 | ✘ 漏检 |
| `printnightmare_mimikatz` | PrintNightmare Mimikatz | 237 | — | 9 | ✔ 检出 |
| `weblogic` | CVE-2017-10271 | 12 | — | 0 | ✘ 漏检 |
| `drupal` | CVE-2018-7600 | 22 | — | 0 | ✘ 漏检 |
| `weblogic_poc` | CVE-2019-2725 | 12 | cleartext_http | 0 | ✔ 检出 |
| `heartbleed` | Heartbleed | 65 | — | 1 | ✔ 检出 |
| `petya` | Petya | 2000 | cleartext_http | 5 | ✔ 检出 |
| `locky` | Locky | 1057 | — | 8 | ✔ 检出 |
| `normal_rdp` | 正常 RDP（误报对照） | 5126 | — | 0 | ✔ 未误报 |

- 恶意样本：**30** 份，产生告警 **25** 份
- 其中行为引擎命中 **9** 份，签名检测补足 **16** 份
- 误报对照（合法 RDP 流量）：1 份，误报 **0** 份

## 漏检的为什么漏（能力边界）

| 漏检样本 | 包数 | 家族 | 原因 |
|---|---:|---|---|
| `bluekeep` | 59 | CVE-2019-0708 | 包数极少，没有可统计的行为模式；ET Open 也未覆盖该利用 |
| `printnightmare` | 1910 | PrintNightmare 扫描 | 流量形态与正常业务接近，缺少载荷级特征或情报 |
| `printnightmare_smbv1` | 733 | PrintNightmare SMBv1 | 流量形态与正常业务接近，缺少载荷级特征或情报 |
| `weblogic` | 12 | CVE-2017-10271 | 包数极少，没有可统计的行为模式；ET Open 也未覆盖该利用 |
| `drupal` | 22 | CVE-2018-7600 | 包数极少，没有可统计的行为模式；ET Open 也未覆盖该利用 |

结论：**行为规则抓统计规律（扫描/爆破/隧道/心跳），签名规则抓已知特征**。
两者盲区不重叠，所以组合起来才能从 9/30 提到 25/30；
而剩下的 5 份是「单包漏洞利用」——既没有行为模式，公开规则也没覆盖，
这类必须靠漏洞库 + 载荷特征（Snort/VRT 商业规则或自研）。

## 复现

```bash
python scripts/fetch_real_pcaps.py      # 按需下载（约 15MB）
python scripts/benchmark_real.py --write-doc
```
