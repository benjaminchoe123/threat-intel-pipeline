---
title: AsyncRAT Botnet C2 IOC — ThreatFox Daily Cluster (2026-07-17)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-07-17
severity: medium
confidence: high
flagged: false
cve: []
family: [AsyncRAT]
attack_techniques: [T1571]
actors: []
tags: [threat, threatfox, severity/medium]
---

# AsyncRAT Botnet C2 IOC — ThreatFox Daily Cluster (2026-07-17)

## What it is
This is a daily cluster of 7 indicators tied to [[families/AsyncRAT]], a widely used remote access trojan (RAT), reported to ThreatFox on 2026-07-17. The indicators cover three command-and-control (C2) servers (as IP:port pairs), one C2 domain, and three file hashes for a payload sample. AsyncRAT lets an attacker remotely control an infected machine — commodity malware frequently distributed through phishing and malicious downloads, though the delivery method is not stated in this source.

## Affected products / versions
Not applicable — this is an IOC cluster, not a software vulnerability.

## ATT&CK mapping
- [[techniques/T1571]] — Non-Standard Port: the three C2 servers listen on ports 6606, 7707, and 8808 rather than standard web ports (80/443), consistent with AsyncRAT's typical custom C2 channel.

## Observed IOCs
| type | value | context |
|---|---|---|
| ip:port | 45.32.90.122:6606 | botnet C2, first seen 2026-07-16 19:46:15 UTC |
| ip:port | 43.225.157.146:7707 | botnet C2, first seen 2026-07-16 19:46:09 UTC |
| ip:port | 217.60.241.10:8808 | botnet C2, first seen 2026-07-16 19:45:50 UTC |
| domain | orthodontie-ge.ch | botnet C2, first seen 2026-07-16 19:01:09 UTC |
| sha1 | 9b225681a471b474fde2cca61ff61498a7c7f9e8 | payload sample, first seen 2026-07-16 19:26:25 UTC |
| md5 | 2b46ed6e01f2baae933707d06704d14c | payload sample, first seen 2026-07-16 19:26:25 UTC |
| sha256 | e6d51d45edea7591b826b2d703c20a426fffa27a022c0156916ae9c35245bd07 | payload sample, first seen 2026-07-16 19:26:24 UTC |

## Severity assessment
**medium** — Per the rubric, ThreatFox IOC-cluster notes default to medium unless volume or an associated campaign justifies high. This cluster has 7 indicators, which is a routine daily volume, and the source data does not describe a large-scale or targeted campaign. Reputation data corroborates that these are genuinely malicious: the payload hash has 53/69 malicious VirusTotal detections, and all three C2 IPs have 11-13 malicious detections. However, AbuseIPDB abuse-confidence scores are mostly low (4%, 8%), with one moderate exception (43.225.157.146 at 44%), indicating these are freshly-flagged infrastructure rather than long-abused, high-volume nodes. AsyncRAT is not a ransomware family, so the ransomware step-up does not apply. This is standard commodity-RAT infrastructure tracking, keeping the rating at medium.

## Confidence notes
Confidence is high: the family attribution (AsyncRAT) and all IOC values come directly from the ThreatFox source, the ATT&CK mapping is grounded in the literal non-standard ports present in the source data (not inferred from the family name alone), and the reputation lookups independently confirm malicious activity on the sampled IOCs.
