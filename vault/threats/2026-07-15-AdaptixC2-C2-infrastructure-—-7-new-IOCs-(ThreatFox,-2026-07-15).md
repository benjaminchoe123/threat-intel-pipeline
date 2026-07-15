---
title: AdaptixC2 C2 infrastructure — 7 new IOCs (ThreatFox, 2026-07-15)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-07-15
severity: high
confidence: medium
flagged: true
cve: []
family: [AdaptixC2]
attack_techniques: [T1071.001]
actors: []
tags: [threat, threatfox, severity/high]
---

# AdaptixC2 C2 infrastructure — 7 new IOCs (ThreatFox, 2026-07-15)

## What it is
ThreatFox reported 7 new command-and-control (C2) server addresses tied to [[families/AdaptixC2]], an open-source post-exploitation framework originally built for penetration testing that criminal groups — including ransomware operators, per public reporting — have adopted to remotely control compromised machines. These IP addresses are the "phone home" points that infected systems connect to for instructions. Blocking or alerting on them helps catch active infections before attackers escalate.

## Affected products / versions
Not applicable — this is an IOC cluster (C2 infrastructure), not a software vulnerability.

## ATT&CK mapping
- [[techniques/T1071.001]] — Application Layer Protocol: Web Protocols: most of the reported C2 endpoints listen on 80, 443, and 8080, consistent with AdaptixC2's known HTTP/HTTPS beaconing.

## Observed IOCs
| type | value | context |
|---|---|---|
| ip:port | 96.9.231.213:8080 | botnet_cc, ThreatFox confidence 100, first seen 2026-07-15 01:05 UTC |
| ip:port | 96.9.231.213:80 | botnet_cc, ThreatFox confidence 100, first seen 2026-07-15 00:05 UTC |
| ip:port | 96.9.231.213:443 | botnet_cc, ThreatFox confidence 100, first seen 2026-07-15 00:05 UTC |
| ip:port | 23.27.52.106:80 | botnet_cc, ThreatFox confidence 100, first seen 2026-07-14 20:05 UTC |
| ip:port | 23.27.52.106:8080 | botnet_cc, ThreatFox confidence 100, first seen 2026-07-14 20:05 UTC |
| ip:port | 45.155.69.254:1488 | botnet_cc, ThreatFox confidence 75, first seen 2026-07-14 19:45 UTC |
| ip:port | 158.94.211.63:32333 | botnet_cc, ThreatFox confidence 75, first seen 2026-07-14 19:43 UTC |

## Severity assessment
**high** — Under the rubric, IOC-cluster notes from ThreatFox default to medium: 7 IOCs across 4 hosts in one day is routine volume, and the source gives no campaign context. However, the ransomware-association adjustment applies: public threat reporting since 2025 has repeatedly documented [[families/AdaptixC2]] being used in ransomware intrusions, which raises the rating one step to high. Active C2 infrastructure also implies live compromises rather than a theoretical risk. There is no evidence here of wormable or mass exploitation, so critical is not warranted.

## Confidence notes
Confidence is medium and the note is flagged because two substantive elements go beyond the source data. First, the ransomware association that lifted severity from medium to high comes from well-established public reporting on AdaptixC2 abuse, not from this ThreatFox record, which contains only IP:port pairs labeled botnet_cc. Second, the [[techniques/T1071.001]] mapping is inferred from the web-service ports in the IOCs plus general knowledge of AdaptixC2's HTTP(S) beaconing — the source does not describe protocol behavior. The IOC table itself is taken verbatim from the source and is fully supported; note that two of the seven entries carry a reduced ThreatFox confidence level of 75.
