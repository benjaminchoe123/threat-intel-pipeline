---
title: Ave Maria Botnet C2 IOC — ThreatFox Daily Cluster (2026-07-20)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-07-20
severity: medium
confidence: medium
flagged: false
cve: []
family: [Ave Maria]
attack_techniques: [T1571]
actors: []
tags: [threat, threatfox, severity/medium]
---

# Ave Maria Botnet C2 IOC — ThreatFox Daily Cluster (2026-07-20)

## What it is
ThreatFox reported one new command-and-control (C2) server tied to [[families/Ave Maria]] (also known as Warzone RAT), a commodity remote access trojan sold to criminals that lets an attacker fully control an infected Windows computer — reading files, capturing passwords, and watching the screen. The indicator is a server address that infected machines call home to. Blocking it cuts off the attacker's control channel for any infections that use this server.

## Affected products / versions
Not applicable — this is an IOC cluster note for C2 infrastructure, not a product vulnerability.

## ATT&CK mapping
- [[techniques/T1571]] — Non-Standard Port: the C2 listener runs on TCP port 5202, a non-standard port, per the ThreatFox record.

## Observed IOCs
| type | value | context |
|------|-------|---------|
| ip:port | 104.245.245.146:5202 | [[families/Ave Maria]] botnet C2, first seen 2026-07-19 20:05:03 UTC, ThreatFox confidence 100 |

## Severity assessment
**medium** — Per the rubric, ThreatFox family-day IOC-cluster notes default to medium, and nothing here justifies raising it: the cluster contains a single indicator, so there is no volume signal, and the source ties it to no named campaign. [[families/Ave Maria]] is commodity malware distributed routinely rather than a ransomware-associated family, so no one-step uplift applies. Reputation data is mixed — VirusTotal shows 4 malicious and 1 suspicious engine verdicts for the IP, consistent with active C2, while AbuseIPDB has zero reports, which is common for infrastructure this fresh (first seen the prior day).

## Confidence notes
Medium. The IOC value, port, threat type (botnet C2), and first-seen timestamp come directly from the ThreatFox source data, and ThreatFox rates the indicator at 100 confidence; VirusTotal's 4 malicious verdicts corroborate it, though AbuseIPDB shows no corroborating reports yet. The description of Ave Maria/Warzone RAT capabilities is well-established public knowledge about the family, not something in the source. The single ATT&CK mapping (T1571) is limited to what the source observably supports — a C2 on a non-standard port; broader mappings for the family's behavior were deliberately omitted rather than pattern-matched from the family name.
