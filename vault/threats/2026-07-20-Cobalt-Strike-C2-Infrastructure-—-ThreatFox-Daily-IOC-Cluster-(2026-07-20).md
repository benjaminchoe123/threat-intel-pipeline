---
title: Cobalt Strike C2 Infrastructure — ThreatFox Daily IOC Cluster (2026-07-20)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-07-20
severity: high
confidence: medium
flagged: false
cve: []
family: [Cobalt Strike]
attack_techniques: [T1071.001, T1571]
actors: []
tags: [threat, threatfox, severity/high]
---

# Cobalt Strike C2 Infrastructure — ThreatFox Daily IOC Cluster (2026-07-20)

## What it is

ThreatFox reported 36 new command-and-control (C2) server addresses tied to [[families/Cobalt Strike]], a commercial penetration-testing framework that is widely pirated and abused by criminal and state-linked intrusion operators. These are the servers infected machines call home to for instructions. Cobalt Strike beacons on a network are a strong signal of an active hands-on-keyboard intrusion, and are one of the most common precursors to ransomware deployment.

## Affected products / versions

Not applicable — this is an IOC cluster note, not a vulnerability in a product.

## ATT&CK mapping

- [[techniques/T1071.001]] — Application Layer Protocols: Web Protocols: many of the listed C2 endpoints use standard web ports (80, 443, 8443, 81), consistent with Cobalt Strike Beacon's well-documented HTTP/HTTPS C2 channels.
- [[techniques/T1571]] — Non-Standard Port: a large share of the cluster listens on unusual ports for C2 (e.g. 38721, 44323, 20091, 123, 3306, 22), observed directly in the source data.

## Observed IOCs

| type | value | context |
|------|-------|---------|
| ip:port | 47.236.130.154:38721 | botnet_cc, first seen 2026-07-20 17:05 UTC |
| ip:port | 120.76.143.184:111 | botnet_cc, first seen 2026-07-20 17:05 UTC |
| ip:port | 47.236.130.154:443 | botnet_cc, first seen 2026-07-20 17:05 UTC |
| ip:port | 47.236.130.154:80 | botnet_cc, first seen 2026-07-20 17:05 UTC |
| ip:port | 101.42.255.92:3306 | botnet_cc, first seen 2026-07-20 17:05 UTC |
| ip:port | 52.86.125.111:8443 | botnet_cc, first seen 2026-07-20 16:05 UTC |
| ip:port | 47.236.130.154:7627 | botnet_cc, first seen 2026-07-20 16:05 UTC |
| ip:port | 52.86.125.111:81 | botnet_cc, first seen 2026-07-20 16:05 UTC |
| ip:port | 101.200.193.211:44323 | botnet_cc, first seen 2026-07-20 15:05 UTC |
| ip:port | 45.87.53.6:38778 | botnet_cc, first seen 2026-07-20 15:05 UTC |
| ip:port | 117.72.39.83:44333 | botnet_cc, first seen 2026-07-20 15:05 UTC |
| ip:port | 117.72.39.83:20091 | botnet_cc, first seen 2026-07-20 15:05 UTC |
| ip:port | 117.72.39.83:20443 | botnet_cc, first seen 2026-07-20 14:05 UTC |
| ip:port | 20.230.138.200:81 | botnet_cc, first seen 2026-07-20 09:14 UTC |
| ip:port | 121.40.141.52:80 | botnet_cc, first seen 2026-07-20 09:14 UTC |
| ip:port | 216.250.255.1:443 | botnet_cc, first seen 2026-07-20 09:14 UTC |
| ip:port | 115.191.29.91:5000 | botnet_cc, first seen 2026-07-20 09:14 UTC |
| ip:port | 124.220.6.158:123 | botnet_cc, first seen 2026-07-20 04:05 UTC |
| ip:port | 139.199.89.128:45251 | botnet_cc, first seen 2026-07-20 03:05 UTC |
| ip:port | 139.199.89.128:3000 | botnet_cc, first seen 2026-07-20 03:05 UTC |
| ip:port | 124.220.6.158:8097 | botnet_cc, first seen 2026-07-20 03:05 UTC |
| ip:port | 120.76.143.184:3306 | botnet_cc, first seen 2026-07-20 02:05 UTC |
| ip:port | 117.72.175.125:22 | botnet_cc, first seen 2026-07-20 01:05 UTC |
| ip:port | 117.72.39.83:58080 | botnet_cc, first seen 2026-07-20 01:05 UTC |
| ip:port | 116.198.233.179:3344 | botnet_cc, first seen 2026-07-20 00:05 UTC |
| ip:port | 117.72.175.125:58888 | botnet_cc, first seen 2026-07-20 00:05 UTC |
| ip:port | 117.72.39.83:20081 | botnet_cc, first seen 2026-07-20 00:05 UTC |
| ip:port | 116.198.233.179:4433 | botnet_cc, first seen 2026-07-20 00:05 UTC |
| ip:port | 117.72.181.104:22 | botnet_cc, first seen 2026-07-19 23:05 UTC |
| ip:port | 117.72.39.83:28395 | botnet_cc, first seen 2026-07-19 23:05 UTC |
| ip:port | 117.72.39.83:22 | botnet_cc, first seen 2026-07-19 22:05 UTC |
| ip:port | 101.33.225.32:888 | botnet_cc, first seen 2026-07-19 18:05 UTC |
| ip:port | 81.70.21.248:8082 | botnet_cc, first seen 2026-07-19 18:05 UTC |
| ip:port | 82.156.139.85:22 | botnet_cc, first seen 2026-07-19 18:05 UTC |
| ip:port | 81.70.21.248:5672 | botnet_cc, first seen 2026-07-19 18:05 UTC |
| ip:port | 64.90.17.181:22 | botnet_cc, first seen 2026-07-19 18:05 UTC |

## Severity assessment

**high** — Under the rubric, IOC-cluster notes default to medium, but two adjustments apply here. First, [[families/Cobalt Strike]] is strongly ransomware-associated: it is the standard post-exploitation framework in ransomware intrusions, and the rubric raises a ransomware-associated family one step. Second, the volume is substantial — 36 distinct C2 endpoints across roughly 20 unique IPs in a single day, all reported at ThreatFox confidence 100. Reputation data partially corroborates active maliciousness: three of the four sampled IPs have double-digit or near-double-digit VirusTotal malicious verdicts (up to 15 engines on 101.42.255.92). This is C2 infrastructure for hands-on intrusions rather than commodity spam distribution, so the impact of any single beacon check-in from a corporate network is high.

## Confidence notes

The IOC values, ports, timestamps, and the Cobalt Strike attribution all come directly from the ThreatFox source data. The [[techniques/T1571]] mapping is supported by the non-standard C2 ports observed in the source itself; the [[techniques/T1071.001]] mapping rests on the web ports in the source plus well-established public knowledge of Cobalt Strike Beacon's HTTP/HTTPS C2, not on behavior described in this specific report — hence confidence is medium rather than high. AbuseIPDB scores for the sampled IPs are low (0–12%), which is common for freshly stood-up C2 servers and does not contradict the ThreatFox reporting, but it means third-party corroboration is only partial.
