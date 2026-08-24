---
title: AsyncRAT Botnet C2 IOC — ThreatFox Daily Cluster (2026-07-20)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-07-20
severity: medium
confidence: medium
flagged: false
cve: []
family: [AsyncRAT]
attack_techniques: [T1219, T1571]
actors: []
tags: [threat, threatfox, severity/medium]
---

# AsyncRAT Botnet C2 IOC — ThreatFox Daily Cluster (2026-07-20)

## What it is
ThreatFox reported 10 new indicators tied to [[families/AsyncRAT]], a widely available remote access trojan that lets attackers take control of infected Windows machines, log keystrokes, and steal data. This cluster covers four command-and-control server addresses and six file hashes (two payload samples, each reported as SHA-256/SHA-1/MD5). Blocking the C2 addresses and alerting on the hashes gives defenders a quick way to catch or cut off active infections.

## Affected products / versions
Not applicable — this is an IOC cluster, not a vulnerability in a specific product.

## ATT&CK mapping
- [[techniques/T1219]] — Remote Access Software: AsyncRAT is a well-documented remote access trojan; the reported indicators are its C2 infrastructure and payloads.
- [[techniques/T1571]] — Non-Standard Port: all four reported C2 endpoints listen on high, non-standard ports (3232, 34471, 20800, 20700), directly observable in the source data.

## Observed IOCs
| type | value | context |
|------|-------|---------|
| ip:port | 43.130.249.174:3232 | botnet C2, first seen 2026-07-20 12:05 UTC; linked MalwareBazaar sample |
| ip:port | 192.227.219.71:34471 | botnet C2, first seen 2026-07-20 09:44 UTC |
| ip:port | 147.93.191.75:20800 | botnet C2, first seen 2026-07-20 09:43 UTC |
| ip:port | 147.93.191.75:20700 | botnet C2, first seen 2026-07-20 09:43 UTC |
| sha256 | 43fe17a95010413fce338858f7f675708e1f3b9fb1998a436881c35dbe49825f | payload, first seen 2026-07-20 11:23 UTC |
| sha1 | 29fb8a163ec801d7e28fe0e8e817f8501b6cae86 | payload, first seen 2026-07-20 11:23 UTC |
| md5 | eb3fd1706066aecf68f002c744100218 | payload, first seen 2026-07-20 11:23 UTC |
| sha256 | 26fc8807ce9a5e6dc534c237d84c2ac7491755532a2078878bc8fb1695fcb2eb | payload, first seen 2026-07-20 11:22 UTC |
| sha1 | 7a5ce656b36a081d0f93d5add93a9c8ddc329abf | payload, first seen 2026-07-20 11:22 UTC |
| md5 | 44ddc80c714f91959bcaa1aeb3cfe1d5 | payload, first seen 2026-07-20 11:22 UTC |

## Severity assessment
**medium** — Under the rubric, IOC-cluster notes from ThreatFox daily aggregates default to medium unless volume or an associated campaign justifies more. This is routine commodity-malware distribution: 10 indicators is a modest daily volume for [[families/AsyncRAT]], and the source names no campaign, actor, or targeting that would raise it. AsyncRAT is not ransomware, so no one-step severity increase applies. VirusTotal strongly corroborates the payload hashes (21 malicious verdicts, zero harmless), confirming these are real malware, but that supports confidence rather than a higher rating. No factor from the critical or high tiers (active mass exploitation, wormability, large-scale campaign) is present in the source.

## Confidence notes
The IOC values, timestamps, and threat types come directly from the ThreatFox source data, and VirusTotal independently confirms the sampled payload hashes as malicious (21/21 engine verdicts, no harmless votes). Confidence is medium rather than high for two reasons: the C2 IP addresses have weak third-party corroboration (AbuseIPDB shows 0–2% abuse confidence and almost no recent reports, and VirusTotal flags 43.130.249.174 with only 3 malicious verdicts — plausible for fresh infrastructure but unconfirmed), and the T1219 mapping rests on well-established public knowledge of the AsyncRAT family rather than behavior described in this specific source. The T1571 mapping is directly observable from the reported ports. The family attribution itself is ThreatFox's reporter claim, backed at 75% confidence for the C2 entries.
