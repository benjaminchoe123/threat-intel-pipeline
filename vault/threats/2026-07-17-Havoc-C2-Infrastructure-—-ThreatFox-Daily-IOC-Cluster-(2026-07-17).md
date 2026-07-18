---
title: Havoc C2 Infrastructure — ThreatFox Daily IOC Cluster (2026-07-17)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-07-17
severity: high
confidence: medium
flagged: true
cve: []
family: [Havoc]
attack_techniques: [T1071]
actors: []
tags: [threat, threatfox, severity/high]
---

# Havoc C2 Infrastructure — ThreatFox Daily IOC Cluster (2026-07-17)

## What it is
ThreatFox reported 16 active command-and-control (C2) endpoints for [[families/Havoc]] on 2026-07-17, spanning 10 distinct IP addresses. [[families/Havoc]] is a free, open-source post-exploitation C2 framework — a "red team" tool in the same category as Cobalt Strike or Sliver — that has also been adopted by criminal and state-linked intrusion actors as a no-cost alternative once a host is compromised. Several of the listed IPs expose multiple listener ports (e.g., 212.103.26.10 on three separate ports, and three other IPs on two ports each), consistent with operators standing up or rotating multiple listener configurations across the same infrastructure.

## Affected products / versions
Not applicable — this is an IOC cluster describing attacker infrastructure, not a product vulnerability.

## ATT&CK mapping
- [[techniques/T1071]] — Application Layer Protocol: infected hosts check in to these operator-controlled listeners to maintain remote control; the source confirms each endpoint as botnet C2 but does not state the specific wire protocol in use on each port.

## Observed IOCs

| type | value | context |
|---|---|---|
| ip:port | 212.103.26.10:22 | botnet_cc, ThreatFox confidence 100, first seen 2026-07-17 15:05 UTC |
| ip:port | 146.190.80.105:22 | botnet_cc, ThreatFox confidence 100, first seen 2026-07-17 15:05 UTC |
| ip:port | 212.103.26.10:40056 | botnet_cc, ThreatFox confidence 100, first seen 2026-07-17 15:05 UTC |
| ip:port | 212.103.26.10:8000 | botnet_cc, ThreatFox confidence 100, first seen 2026-07-17 15:05 UTC |
| ip:port | 47.83.134.97:22 | botnet_cc, ThreatFox confidence 100, first seen 2026-07-17 14:05 UTC |
| ip:port | 146.190.80.105:40056 | botnet_cc, ThreatFox confidence 100, first seen 2026-07-17 14:05 UTC |
| ip:port | 20.188.119.195:22 | botnet_cc, ThreatFox confidence 100, first seen 2026-07-17 14:05 UTC |
| ip:port | 20.39.60.137:22 | botnet_cc, ThreatFox confidence 100, first seen 2026-07-17 14:05 UTC |
| ip:port | 20.39.60.137:80 | botnet_cc, ThreatFox confidence 100, first seen 2026-07-17 13:05 UTC |
| ip:port | 161.35.176.231:22 | botnet_cc, ThreatFox confidence 100, first seen 2026-07-17 13:05 UTC |
| ip:port | 161.35.176.231:8080 | botnet_cc, ThreatFox confidence 100, first seen 2026-07-17 13:05 UTC |
| ip:port | 104.251.181.73:22 | botnet_cc, ThreatFox confidence 100, first seen 2026-07-17 13:05 UTC |
| ip:port | 161.35.239.147:22 | botnet_cc, ThreatFox confidence 100, first seen 2026-07-17 12:05 UTC |
| ip:port | 142.93.88.220:22 | botnet_cc, ThreatFox confidence 100, first seen 2026-07-17 12:05 UTC |
| ip:port | 47.251.241.59:80 | botnet_cc, ThreatFox confidence 100, first seen 2026-07-17 12:05 UTC |
| ip:port | 47.251.241.59:22 | botnet_cc, ThreatFox confidence 100, first seen 2026-07-17 12:05 UTC |

## Severity assessment
**high** — Per the rubric, IOC-cluster notes default to medium unless volume or an associated campaign justifies high. This cluster reports 10 distinct C2 hosts across 16 endpoints in a single day for one family, with four of those hosts running multiple simultaneous listener ports — a scale and operational tempo above a routine single-host C2 sighting, which supports the volume-based bump to high. All 16 entries carry ThreatFox's maximum confidence level (100). The sampled reputation data is corroborating but not overwhelming: VirusTotal shows 8-14 malicious engine detections per sampled IP (out of roughly 55-65 total engines), while AbuseIPDB abuse-confidence scores are near zero (0-2%) — a pattern consistent with newly stood-up infrastructure that hasn't yet accumulated a long external abuse history, rather than with the IOCs being unreliable.

## Confidence notes
The bump from the rubric's medium default to high rests on the volume and multi-port pattern of this cluster (10 hosts, 16 endpoints, several multi-listener), which is an inference from the source's aggregate shape rather than an explicit campaign attribution stated by ThreatFox — no named campaign or actor accompanies this data. The ATT&CK mapping to T1071 is derived from Havoc's known behavior as a beaconing C2 framework rather than from any protocol detail confirmed in the source, and no more specific sub-technique is claimed since the wire protocol per port is not stated. Because both the severity bump and the technique mapping rely on this inference beyond the literal source data, confidence is set to medium and the note is flagged.
