---
title: AdaptixC2 C2 Infrastructure — ThreatFox Daily IOC Cluster (2026-07-17)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-07-17
severity: high
confidence: medium
flagged: true
cve: []
family: [AdaptixC2]
attack_techniques: [T1071.001, T1571]
actors: []
tags: [threat, threatfox, severity/high]
---

# AdaptixC2 C2 Infrastructure — ThreatFox Daily IOC Cluster (2026-07-17)

## What it is
This is a same-day cluster of command-and-control (C2) server addresses associated with [[families/AdaptixC2]], reported by ThreatFox on 2026-07-17. AdaptixC2 is a publicly known post-exploitation/command-and-control framework in the same category as tools like Cobalt Strike or Sliver — once a host is infected, the framework gives an attacker remote control over it. ThreatFox's metadata reports 62 IOCs submitted for this family on this day; the source data provided to this note contains 50 of those, all flagged as `botnet_cc` (active C2 endpoints) at 100% submitter confidence.

## Affected products / versions
Not applicable — this is an IOC-cluster note describing C2 infrastructure, not a product vulnerability.

## ATT&CK mapping
- [[techniques/T1071.001]] — Application Layer Protocol: Web Protocols: the majority of listed C2 endpoints use ports 80, 443, or 8080, consistent with C2 traffic disguised as ordinary web traffic.
- [[techniques/T1571]] — Non-Standard Port: a substantial share of endpoints use non-standard ports (e.g. 6579, 14888, 8686, 4433, 9200, 3306, 22, 8443), directly observed in the source IOC list rather than inferred from the family name alone.

## Observed IOCs
| type | value | context |
|---|---|---|
| ip:port | 38.54.63.135:8080 | botnet_cc |
| ip:port | 38.54.63.135:443 | botnet_cc |
| ip:port | 38.54.63.135:80 | botnet_cc |
| ip:port | 23.227.203.191:10443 | botnet_cc |
| ip:port | 38.132.122.145:6579 | botnet_cc |
| ip:port | 38.132.122.145:14888 | botnet_cc |
| ip:port | 38.132.122.141:6579 | botnet_cc |
| ip:port | 23.227.203.191:6579 | botnet_cc |
| ip:port | 217.60.97.3:8080 | botnet_cc |
| ip:port | 38.132.122.161:6579 | botnet_cc |
| ip:port | 23.227.203.128:6579 | botnet_cc |
| ip:port | 23.227.203.190:14888 | botnet_cc |
| ip:port | 23.227.203.190:6579 | botnet_cc |
| ip:port | 217.60.97.3:80 | botnet_cc |
| ip:port | 217.60.97.3:443 | botnet_cc |
| ip:port | 217.60.97.3:9200 | botnet_cc |
| ip:port | 23.227.203.205:6579 | botnet_cc |
| ip:port | 23.227.203.246:6579 | botnet_cc |
| ip:port | 79.135.160.20:8080 | botnet_cc |
| ip:port | 85.158.57.247:8080 | botnet_cc |
| ip:port | 23.227.203.71:8080 | botnet_cc |
| ip:port | 23.227.203.71:443 | botnet_cc |
| ip:port | 23.227.203.71:80 | botnet_cc |
| ip:port | 79.135.160.20:443 | botnet_cc |
| ip:port | 79.135.160.20:80 | botnet_cc |
| ip:port | 79.135.160.20:8000 | botnet_cc |
| ip:port | 217.148.142.28:80 | botnet_cc |
| ip:port | 177.153.202.224:8080 | botnet_cc |
| ip:port | 177.153.202.224:80 | botnet_cc |
| ip:port | 177.153.202.224:443 | botnet_cc |
| ip:port | 177.153.202.224:8443 | botnet_cc |
| ip:port | 217.148.142.28:443 | botnet_cc |
| ip:port | 85.158.57.247:80 | botnet_cc |
| ip:port | 85.158.57.247:443 | botnet_cc |
| ip:port | 23.227.199.61:6579 | botnet_cc |
| ip:port | 2.26.229.254:80 | botnet_cc |
| ip:port | 45.136.13.247:8000 | botnet_cc |
| ip:port | 45.136.13.247:3306 | botnet_cc |
| ip:port | 45.136.13.247:22 | botnet_cc |
| ip:port | 45.77.89.29:8080 | botnet_cc |
| ip:port | 2.26.229.254:443 | botnet_cc |
| ip:port | 2.26.229.254:8080 | botnet_cc |
| ip:port | 2.26.229.254:4433 | botnet_cc |
| ip:port | 45.77.89.29:80 | botnet_cc |
| ip:port | 45.77.89.29:8686 | botnet_cc |
| ip:port | 45.77.89.29:443 | botnet_cc |
| ip:port | 154.19.229.186:8080 | botnet_cc |
| ip:port | 154.19.229.186:80 | botnet_cc |
| ip:port | 46.21.153.148:6579 | botnet_cc |
| ip:port | 46.21.153.146:6579 | botnet_cc |

## Severity assessment
**high** — This is an IOC-cluster note, which the rubric defaults to medium unless volume or an associated campaign justifies a higher rating. 50+ distinct C2 endpoints across roughly 20 unique IPs submitted in a single day, all at 100% submitter confidence, is a volume well above routine commodity distribution and indicates active, ongoing operator infrastructure rather than a handful of stale sinkholed addresses. Sampled reputation data corroborates active malicious use: VirusTotal flags several of the sampled IPs as malicious by 6–14 security vendor engines. AbuseIPDB showing 0% abuse confidence on the same IPs is not a contradiction — it reflects that this infrastructure is fresh and hasn't yet accumulated community abuse reports, not that it's benign. No KEV listing or ransomware association is established in the source data, so this does not meet the critical bar, but the scale and corroborated maliciousness support high over medium.

## Confidence notes
This note mixes source-supported facts with inference and is flagged accordingly. The IOC table, ports, and ATT&CK technique mappings (T1071.001, T1571) are directly supported by the source data. However, the characterization of AdaptixC2 as a post-exploitation/C2 framework relies on well-established public knowledge about the family rather than anything present in the ThreatFox JSON itself, which contains no behavioral description — treat that characterization as informed inference, not source-confirmed fact. Additionally, ThreatFox's daily metadata reports 62 total IOCs for this family, but only 50 were present in the source data supplied to this enrichment; the table above reflects only those 50. No CVEs or named threat actors are asserted, as none are supported by the source.
