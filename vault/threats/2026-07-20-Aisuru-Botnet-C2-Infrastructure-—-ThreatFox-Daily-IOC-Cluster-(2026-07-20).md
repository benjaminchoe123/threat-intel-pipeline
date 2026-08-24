---
title: Aisuru Botnet C2 Infrastructure — ThreatFox Daily IOC Cluster (2026-07-20)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-07-20
severity: medium
confidence: medium
flagged: false
cve: []
family: [Aisuru]
attack_techniques: [T1071, T1498]
actors: []
tags: [threat, threatfox, severity/medium]
---

# Aisuru Botnet C2 Infrastructure — ThreatFox Daily IOC Cluster (2026-07-20)

## What it is
ThreatFox reported 19 new command-and-control (C2) endpoints for the [[families/Aisuru]] botnet on 2026-07-20, spanning 8 distinct IP addresses, many hosting C2 listeners on multiple ports. Aisuru is a Mirai-derived botnet that infects poorly secured internet-of-things devices (routers, DVRs, cameras) and rents out their combined bandwidth for very large distributed denial-of-service (DDoS) attacks. These IPs are the servers infected devices call home to — blocking them cuts compromised devices off from their operators.

## Affected products / versions
Not applicable — this is an IOC cluster for botnet C2 infrastructure, not a vulnerability in a specific product.

## ATT&CK mapping
- [[techniques/T1071]] — Application Layer Protocol: the listed endpoints are botnet C2 channels, several on common web/application ports (8080, 8443).
- [[techniques/T1498]] — Network Denial of Service: [[families/Aisuru]] is publicly documented as a DDoS-for-hire botnet; this mapping comes from family knowledge, not from behavior described in this source (see Confidence notes).

## Observed IOCs
| type | value | context |
|---|---|---|
| ip:port | 45.76.146.2:8443 | Aisuru botnet C2, first seen 2026-07-20 |
| ip:port | 162.243.163.143:9034 | Aisuru botnet C2, first seen 2026-07-20 |
| ip:port | 162.243.163.143:12345 | Aisuru botnet C2, first seen 2026-07-20 |
| ip:port | 162.243.163.143:8080 | Aisuru botnet C2, first seen 2026-07-20 |
| ip:port | 162.243.163.143:8443 | Aisuru botnet C2, first seen 2026-07-20 |
| ip:port | 167.172.80.107:8443 | Aisuru botnet C2, first seen 2026-07-20 |
| ip:port | 167.172.80.107:9035 | Aisuru botnet C2, first seen 2026-07-20 |
| ip:port | 167.172.80.107:9034 | Aisuru botnet C2, first seen 2026-07-19 |
| ip:port | 159.65.143.171:8080 | Aisuru botnet C2, first seen 2026-07-20 |
| ip:port | 159.65.143.171:37215 | Aisuru botnet C2, first seen 2026-07-20 |
| ip:port | 159.65.143.171:34567 | Aisuru botnet C2, first seen 2026-07-20 |
| ip:port | 159.65.143.171:8443 | Aisuru botnet C2, first seen 2026-07-19 |
| ip:port | 137.184.135.42:9034 | Aisuru botnet C2, first seen 2026-07-20 |
| ip:port | 137.184.135.42:8443 | Aisuru botnet C2, first seen 2026-07-19 |
| ip:port | 137.184.135.42:34567 | Aisuru botnet C2, first seen 2026-07-19 |
| ip:port | 168.144.135.136:8443 | Aisuru botnet C2, first seen 2026-07-20 |
| ip:port | 168.144.135.136:34567 | Aisuru botnet C2, first seen 2026-07-19 |
| ip:port | 161.35.125.247:9035 | Aisuru botnet C2, first seen 2026-07-20 |
| ip:port | 161.35.125.247:8443 | Aisuru botnet C2, first seen 2026-07-19 |

## Severity assessment
**medium** — Per the rubric, ThreatFox family-day IOC aggregates default to medium, and this cluster does not clearly exceed that bar. The 19 endpoints across 8 IPs represent routine daily C2 infrastructure churn rather than evidence of a specific new campaign in this source. [[families/Aisuru]] itself is associated with very large DDoS activity, which argues toward high, but the source contains only C2 coordinates with no campaign scale or targeting detail, and it is not ransomware-associated, so no step-up applies. External corroboration is mixed: VirusTotal shows modest malicious verdicts (4–5 engines) on the sampled IPs, while AbuseIPDB shows zero abuse reports on all four sampled IPs in 90 days, consistent with fresh or low-noise C2 infrastructure rather than an established attack wave.

## Confidence notes
The IOC list, C2 designation, and 100% ThreatFox confidence ratings come directly from the source. The characterization of [[families/Aisuru]] as a Mirai-derived IoT DDoS botnet, and the T1498 mapping, are well-established public knowledge about the family rather than behavior described in this source — hence confidence is medium, not high. AbuseIPDB returned 0% abuse confidence for all sampled IPs, which neither confirms nor refutes the C2 designation for indicators this fresh; VirusTotal provides partial corroboration (4–5 malicious verdicts per IP).
