---
title: Aisuru Botnet C2 IOC — ThreatFox Daily Cluster (2026-07-17)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-07-17
severity: medium
confidence: medium
flagged: true
cve: []
family: [Aisuru]
attack_techniques: [T1071, T1498]
actors: []
tags: [threat, threatfox, severity/medium]
---

# Aisuru Botnet C2 IOC — ThreatFox Daily Cluster (2026-07-17)

## What it is
This note tracks a single command-and-control (C2) indicator that ThreatFox associated with [[families/Aisuru]] on 2026-07-17: an IP:port pair flagged as botnet C2 infrastructure with 100% source confidence. Aisuru is publicly documented as a Mirai-derived botnet that infects IoT devices and has been linked to large-scale DDoS activity — that background is well-established public knowledge about the family, not something confirmed by this specific IOC record. The practical risk to an organization is twofold: outbound connections to this address/port from any internal host would indicate a compromised device, and if Aisuru's DDoS capability is accurate, infected devices could be conscripted into attacks against third parties.

## Affected products / versions
Not applicable — this is a C2 infrastructure IOC, not a vulnerability advisory. Aisuru, like other Mirai-family botnets, is generally understood to target internet-facing IoT and networking devices, but the source data does not name specific affected products.

## ATT&CK mapping
- [[techniques/T1071]] — Application Layer Protocol: ThreatFox categorizes 159.89.132.240:37215 as botnet C2 (`threat_type: botnet_cc`), consistent with malware beaconing to a C2 server over a network application protocol. This is directly supported by the source's own classification.
- [[techniques/T1498]] — Network Denial of Service: Aisuru is publicly reported as a DDoS-focused botnet. This mapping is inferred from the family's known purpose rather than any behavior observed in this specific IOC record, so treat it as lower-confidence pattern-matching on the family name.

## Observed IOCs
| type | value | context |
|---|---|---|
| ip:port | 159.89.132.240:37215 | Botnet C2 (ThreatFox confidence 100, first seen 2026-07-17 11:33:21 UTC). VirusTotal: 5/91 engines flag as malicious, 0 suspicious, 50 harmless, 36 undetected. AbuseIPDB: 0% abuse confidence, 0 reports in last 90 days. |

## Severity assessment
**Medium** — Per the rubric, ThreatFox family-day IOC clusters default to medium unless volume or an associated campaign justifies a higher rating. This cluster contains only a single IOC, so there is no volume signal here to elevate it. It is not KEV-listed, and Aisuru is a DDoS botnet rather than ransomware, so neither of the automatic severity floors/bumps applies. Reputation data is mixed and thin: VirusTotal shows a low detection ratio (5/91) and AbuseIPDB shows no abuse reports at all, which is typical for freshly stood-up C2 infrastructure and does not indicate benignity, but also doesn't independently corroborate high-confidence malicious activity beyond ThreatFox's own classification.

## Confidence notes
This note carries two distinct confidence levels that don't fully align. ThreatFox itself reports 100% confidence that this IP:port is Aisuru C2 — that part of the record is well-supported. However: (1) the characterization of Aisuru as a large-scale DDoS botnet, and the resulting T1498 mapping, comes from general public knowledge of the family rather than anything in this specific source record; (2) reputation data (VT, AbuseIPDB) provides only weak corroboration, which is expected for a newly-seen indicator but means this note can't independently confirm the C2's activity level or scale. Confidence is set to medium and the note is flagged because a substantive claim (the DDoS/botnet-scale characterization) extends beyond what the source data alone establishes.
