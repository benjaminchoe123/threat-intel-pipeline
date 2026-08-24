---
title: AdaptixC2 C2 Infrastructure — ThreatFox Daily IOC Cluster (2026-07-20)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-07-20
severity: medium
confidence: medium
flagged: false
cve: []
family: [AdaptixC2]
attack_techniques: [T1071.001]
actors: []
tags: [threat, threatfox, severity/medium]
---

# AdaptixC2 C2 Infrastructure — ThreatFox Daily IOC Cluster (2026-07-20)

## What it is
ThreatFox reported 19 new command-and-control (C2) indicators tied to [[families/AdaptixC2]], an open-source post-exploitation and C2 framework that both red teams and criminal operators use to remotely control compromised machines. All 19 indicators are IP:port pairs classified as botnet C2 endpoints, spread across 10 distinct IP addresses. If a machine on your network talks to any of these addresses, it is likely already compromised and under remote control.

## Affected products / versions
Not applicable — this is an IOC cluster describing attacker infrastructure, not a vulnerability in a product.

## ATT&CK mapping
- [[techniques/T1071.001]] — Application Layer Protocol: Web Protocols: the majority of these C2 listeners sit on standard web ports (80, 443, 8080, 8443), consistent with AdaptixC2 beaconing over HTTP/HTTPS to blend with normal web traffic.

## Observed IOCs
| type | value | context |
|------|-------|---------|
| ip:port | 149.104.28.204:443 | AdaptixC2 botnet C2, confidence 100, first seen 2026-07-20 15:05 UTC |
| ip:port | 45.77.89.29:8484 | AdaptixC2 botnet C2, confidence 100, first seen 2026-07-20 14:05 UTC |
| ip:port | 149.104.28.204:80 | AdaptixC2 botnet C2, confidence 100, first seen 2026-07-20 14:05 UTC |
| ip:port | 149.104.28.204:8080 | AdaptixC2 botnet C2, confidence 100, first seen 2026-07-20 14:05 UTC |
| ip:port | 149.104.28.204:9879 | AdaptixC2 botnet C2, confidence 100, first seen 2026-07-20 13:05 UTC |
| ip:port | 89.124.104.192:49999 | AdaptixC2 botnet C2, confidence 75, first seen 2026-07-20 09:45 UTC |
| ip:port | 45.136.13.247:8888 | AdaptixC2 botnet C2, confidence 100, first seen 2026-07-19 22:05 UTC |
| ip:port | 154.219.115.123:60002 | AdaptixC2 botnet C2, confidence 100, first seen 2026-07-19 22:05 UTC |
| ip:port | 45.136.13.247:8443 | AdaptixC2 botnet C2, confidence 100, first seen 2026-07-19 22:05 UTC |
| ip:port | 38.242.212.5:80 | AdaptixC2 botnet C2, confidence 100, first seen 2026-07-19 21:05 UTC |
| ip:port | 38.242.212.5:8080 | AdaptixC2 botnet C2, confidence 100, first seen 2026-07-19 21:05 UTC |
| ip:port | 38.242.212.5:443 | AdaptixC2 botnet C2, confidence 100, first seen 2026-07-19 21:05 UTC |
| ip:port | 38.242.212.5:1390 | AdaptixC2 botnet C2, confidence 100, first seen 2026-07-19 20:05 UTC |
| ip:port | 154.219.115.123:80 | AdaptixC2 botnet C2, confidence 100, first seen 2026-07-19 20:05 UTC |
| ip:port | 1.92.135.168:443 | AdaptixC2 botnet C2, confidence 100, first seen 2026-07-19 20:05 UTC |
| ip:port | 178.105.144.206:4321 | AdaptixC2 botnet C2, confidence 75, first seen 2026-07-19 19:43 UTC |
| ip:port | 1.92.135.168:8080 | AdaptixC2 botnet C2, confidence 100, first seen 2026-07-19 19:05 UTC |
| ip:port | 154.219.115.123:8080 | AdaptixC2 botnet C2, confidence 100, first seen 2026-07-19 19:05 UTC |
| ip:port | 154.219.115.123:443 | AdaptixC2 botnet C2, confidence 100, first seen 2026-07-19 19:05 UTC |

## Severity assessment
**medium** — Under the rubric, IOC-cluster notes from ThreatFox default to medium unless volume or an associated campaign justifies high. This cluster is routine daily C2 infrastructure reporting: 19 indicators across 10 IPs, with no campaign, actor, or victim context in the source that would escalate it. AdaptixC2 is a post-exploitation framework rather than a self-propagating threat, so the critical/high factors (active mass exploitation, wormability, large-scale campaign) do not apply. Reputation data is consistent with active but not exceptional malicious infrastructure: VirusTotal shows 10–14 engines flagging each sampled IP as malicious, while AbuseIPDB scores are mostly 0% (one IP at 92% with 140 reports), suggesting several of these endpoints are fresh and not yet widely reported. The steady stream of new AdaptixC2 sightings across recent daily clusters indicates ongoing operator use, but not at a scale that meets the high bar.

## Confidence notes
The IOC values, types, threat classification (botnet C2), and timestamps come directly from the ThreatFox source data and are corroborated for sampled IPs by VirusTotal detections. Confidence is medium rather than high because two elements go beyond the source: the characterization of AdaptixC2 as an open-source post-exploitation/C2 framework is well-established public knowledge about the family, not stated in the feed; and the T1071.001 mapping is inferred from the prevalence of web ports (80/443/8080/8443) among the listeners plus known AdaptixC2 behavior, since the source describes infrastructure only, not observed traffic. No IOCs, CVEs, or actors were added beyond the source data.
