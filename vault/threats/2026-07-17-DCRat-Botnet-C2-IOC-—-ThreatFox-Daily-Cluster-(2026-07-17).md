---
title: DCRat Botnet C2 IOC — ThreatFox Daily Cluster (2026-07-17)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-07-17
severity: medium
confidence: medium
flagged: true
cve: []
family: [DCRat]
attack_techniques: [T1071]
actors: []
tags: [threat, threatfox, severity/medium]
---

# DCRat Botnet C2 IOC — ThreatFox Daily Cluster (2026-07-17)

## What it is
This note tracks a single command-and-control (C2) indicator that ThreatFox associated with [[families/DCRat]] on 2026-07-17: an IP:port pair flagged as botnet C2 infrastructure with 75% source confidence. DCRat (also known as Dark Crystal RAT) is publicly documented as a low-cost, plugin-based remote access trojan sold as malware-as-a-service, giving operators remote control, keylogging, screen capture, and credential-theft capabilities on infected Windows hosts — that background is well-established public knowledge about the family, not something confirmed by this specific IOC record. The practical risk to an organization is that any outbound connection to this address/port from an internal host would indicate a compromised machine under attacker control.

## Affected products / versions
Not applicable — this is a C2 infrastructure IOC, not a vulnerability advisory. DCRat targets Windows endpoints generally; the source data does not name specific affected products or versions.

## ATT&CK mapping
- [[techniques/T1071]] — Application Layer Protocol: ThreatFox categorizes 5.200.192.159:8848 as botnet C2 (`threat_type: botnet_cc`), consistent with malware beaconing to a C2 server over a network application protocol. This is directly supported by the source's own classification.

## Observed IOCs
| type | value | context |
|---|---|---|
| ip:port | 5.200.192.159:8848 | Botnet C2 for DCRat (ThreatFox confidence 75, first seen 2026-07-16 19:46:28 UTC). VirusTotal: 7/91 engines flag as malicious, 2 suspicious, 50 harmless, 32 undetected. AbuseIPDB: 0% abuse confidence, 0 reports in last 90 days. |

## Severity assessment
**Medium** — Per the rubric, ThreatFox family-day IOC clusters default to medium unless volume or an associated campaign justifies a higher rating. This cluster contains only a single IOC, so there is no volume signal to elevate it. It is not KEV-listed, and DCRat is a remote access trojan rather than a ransomware family, so neither of the automatic severity floors/bumps applies. Reputation data is mixed and thin: VirusTotal shows a modest detection ratio (7 malicious/2 suspicious out of 91 engines) and AbuseIPDB shows no abuse reports at all, which is typical for a freshly reported indicator and does not indicate benignity, but also doesn't independently corroborate large-scale malicious activity beyond ThreatFox's own classification.

## Confidence notes
This note carries two distinct confidence levels that don't fully align. ThreatFox itself reports 75% confidence that this IP:port is DCRat C2, and the `botnet_cc` threat_type directly supports the T1071 mapping — that part of the record is reasonably well-supported. However: (1) the characterization of DCRat as a RAT-as-a-service with keylogging/credential-theft capability comes from general public knowledge of the family rather than anything in this specific source record; (2) reputation data (VT, AbuseIPDB) provides only weak corroboration, expected for a newly-seen indicator but meaning this note can't independently confirm the C2's activity level or scale. Confidence is set to medium and the note is flagged because a substantive claim (the RAT capability characterization) extends beyond what the source data alone establishes.
