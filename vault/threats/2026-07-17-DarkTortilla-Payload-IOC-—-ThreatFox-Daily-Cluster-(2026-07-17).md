---
title: DarkTortilla Payload IOC — ThreatFox Daily Cluster (2026-07-17)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-07-17
severity: medium
confidence: medium
flagged: true
cve: []
family: [DarkTortilla]
attack_techniques: [T1027]
actors: []
tags: [threat, threatfox, severity/medium]
---

# DarkTortilla Payload IOC — ThreatFox Daily Cluster (2026-07-17)

## What it is
This note tracks a single malware sample tied to [[families/DarkTortilla]] that ThreatFox reported on 2026-07-17, represented as three hashes (SHA256, SHA1, MD5) of the same payload file at 95% source confidence. DarkTortilla is publicly documented as a highly configurable .NET-based crypter/loader, frequently offered as crypting-as-a-service, that has been used to package and deliver a wide range of second-stage malware (commodity RATs and info-stealers). That background is well-established public knowledge about the family, not something this specific IOC record independently confirms. The source data itself carries no C2 infrastructure, delivery method, or behavioral detail beyond classifying the file as a "payload."

## Affected products / versions
Not applicable — this is a payload IOC, not a vulnerability advisory. DarkTortilla targets Windows endpoints generally; the source data does not name specific affected products or versions.

## ATT&CK mapping
- [[techniques/T1027]] — Obfuscated Files or Information: DarkTortilla's defining function as a crypter is to obfuscate/encrypt an embedded payload to evade detection. This mapping is drawn from established public reporting on the family rather than any behavioral detail present in this specific source record.

## Observed IOCs
| type | value | context |
|---|---|---|
| sha256 | 68c9207a1e4e703b897300fc6c21cf0472549b352d80a64259e21ed4fdfe63a4 | payload sample, first seen 2026-07-16 19:26:18 UTC |
| sha1 | 54f998f02bb83c71a0746cd38ca8203ed9a90a3a | payload sample, first seen 2026-07-16 19:26:18 UTC |
| md5 | 1f017ca7bcdae763c27483193017747a | payload sample, first seen 2026-07-16 19:26:18 UTC |

## Severity assessment
**Medium** — Per the rubric, ThreatFox family-day IOC clusters default to medium unless volume or an associated campaign justifies a higher rating. This cluster is a single sample (three hash formats of one file), which is not a volume signal, and the source data does not describe an associated large-scale campaign. It is not KEV-listed (no CVE involved), and DarkTortilla is a crypter/loader rather than a ransomware family itself, so neither automatic severity adjustment applies. Reputation data does corroborate that the file is genuinely malicious: VirusTotal shows 46 malicious detections out of 69 reporting engines (0 harmless) across all three hash values, consistent with a confirmed-bad sample rather than a benign or ambiguous file. That confirmation supports keeping the rating at medium rather than lowering it, but doesn't on its own justify raising it absent volume or campaign context.

## Confidence notes
This note carries two distinct confidence levels that don't fully align. The IOC values and family attribution come directly from ThreatFox at 95% source confidence, and VirusTotal independently corroborates the file is malicious — that part is well-supported. However, the characterization of DarkTortilla as a crypting-as-a-service loader used to deliver other malware families, and the resulting T1027 mapping, come from general public knowledge of the family rather than any behavioral detail in this specific source record, which contains only hash values and a threat_type of "payload." Confidence is set to medium and the note is flagged because a substantive claim (the crypter/loader characterization and technique mapping) extends beyond what the source data alone establishes.
