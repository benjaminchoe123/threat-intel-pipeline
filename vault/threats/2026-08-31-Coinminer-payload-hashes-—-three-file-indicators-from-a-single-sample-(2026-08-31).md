---
title: Coinminer payload hashes — three file indicators from a single sample (2026-08-31)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-08-31
severity: medium
confidence: medium
flagged: true
cve: []
family: [Coinminer]
attack_techniques: []
actors: []
tags: [threat, threatfox, severity/medium]
---

# Coinminer payload hashes — three file indicators from a single sample (2026-08-31)

## What it is
ThreatFox published three file hashes tagged as [[families/Coinminer]] payloads on 2026-08-31. A coinminer is software that quietly uses a victim machine's processor or graphics card to mine cryptocurrency for someone else — it steals computing power and electricity rather than data. The three hashes (SHA-1, MD5, SHA-256) all share the same first-seen timestamp and almost certainly describe a single file rather than three separate samples. VirusTotal detects the file with 42 of 70 engines, so it is confidently malicious, but the source provides no delivery method, infrastructure, or campaign context.

## Affected products / versions
Unknown — not stated in source. The source records file hashes only and does not name a target platform, application, or version.

## ATT&CK mapping
None supportable from the source. The only behavior implied is the "Coinminer" label itself, which is a generic classification rather than an observed technique. Mapping to `T1496` (Resource Hijacking) would be pattern-matching on the family name alone with no described execution, persistence, or delivery behavior in the source data, so it is omitted per the low-confidence rule.

## Observed IOCs

| type | value | context |
|---|---|---|
| sha256 | `916cf18c98363cf3419b4d51e9635dd1c610adb3b6d6264aac3f52a02b77541a` | Payload, confidence 95, first seen 2026-08-30 06:33:58 UTC. VT: 42 malicious / 0 suspicious / 0 harmless / 28 undetected. |
| sha1 | `5d1307ffad96536894481fead93401448cc6adac` | Payload, confidence 95, first seen 2026-08-30 06:33:59 UTC. VT: 42 malicious / 0 suspicious / 0 harmless / 28 undetected. |
| md5 | `99ad52820bd7ae090c578610e367fcdb` | Payload, confidence 95, first seen 2026-08-30 06:33:59 UTC. VT: 42 malicious / 0 suspicious / 0 harmless / 28 undetected. |

No reference URL was supplied for any indicator.

## Severity assessment
**medium** — This is an IOC-cluster note from a ThreatFox family-day aggregate, which the rubric defaults to medium. Neither of the two conditions that would raise it to high is met: the volume is three hashes describing what appears to be one file, and the source names no campaign, actor, or associated tooling. Coinminers are routine commodity malware whose primary impact is resource theft and degraded performance rather than data loss or lateral movement, and no ransomware association is present that would raise the rating a step. The 42/70 VirusTotal detection rate confirms the file is malicious and widely recognized by defenders, which supports the note's accuracy but does not by itself indicate a large-scale active campaign. There is no CVE, no exploitation-in-the-wild claim, and no KEV listing to floor the severity higher.

## Confidence notes
Set to medium and flagged. What is in the source: the three hash values, their types, the `payload` threat type, ThreatFox's 95 confidence level, and the first-seen timestamps. What is inference: that the three hashes represent a single file rather than three distinct samples — this is strongly suggested by the near-identical timestamps (58–59 seconds past the same minute) and the fact that ThreatFox commonly submits multiple hash types per sample, but the source does not state it. Also inferred is the general description of coinminer behavior (CPU/GPU theft), which comes from well-established public knowledge about the family classification, not from this source record. The ATT&CK list is deliberately empty for the reason given above. No delivery vector, C2 infrastructure, targeting, or victimology is available, so this note supports detection by hash only and not hunting or attribution.
