---
title: CrossRAT — 3 new IOCs (ThreatFox, 2026-07-20)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-07-20
severity: medium
confidence: medium
flagged: false
cve: []
family: [CrossRAT]
attack_techniques: []
actors: []
tags: [threat, threatfox, severity/medium]
---

# CrossRAT — 3 new IOCs (ThreatFox, 2026-07-20)

## What it is
ThreatFox published three file hashes on 2026-07-20 tagged as [[families/CrossRAT]] payloads. CrossRAT is a remote access trojan written in Java, publicly documented since 2018 as a cross-platform implant (Windows, macOS, Linux) that gives an attacker file access and control of an infected machine; public reporting at the time attributed its use to the [[actors/Dark Caracal]] group, though this sample carries no attribution in the source. The three hashes (SHA-256, SHA-1, MD5) share an identical first-seen timestamp and are very likely the same file, so this cluster represents one newly catalogued sample rather than a broad campaign.

## Affected products / versions
Not applicable — this is an IOC cluster for a malware payload, not a product vulnerability.

## ATT&CK mapping
None supportable from the source data. ThreatFox provides only file hashes with a family label and no behavioral detail; mapping techniques from the family name alone would be pattern-matching, so the list is left empty.

## Observed IOCs
| type | value | context |
|---|---|---|
| sha256_hash | 2d1a5a0c9b43b6dbff32bd3b66d1a96c0d36773f5b7b546fcb9da93580f9246a | CrossRAT payload, first seen 2026-07-20 11:22:50 UTC, ThreatFox confidence 95 |
| sha1_hash | 50d5e712edfc416e508aaf221110d6b4a3df93e2 | CrossRAT payload, same first-seen timestamp — likely the same file |
| md5_hash | 8465b5392ea382ceec662c25ea7acc34 | CrossRAT payload, same first-seen timestamp — likely the same file |

## Severity assessment
**medium** — IOC-cluster notes from ThreatFox default to medium under the rubric, and nothing here justifies raising it: the volume is minimal (three hashes, almost certainly one sample), the source describes no active large-scale campaign, and CrossRAT is not ransomware-associated, so no one-step raise applies. There is no KEV listing to floor severity at high. VirusTotal corroborates that the file is genuinely malicious (53 engines flag it, none rate it harmless), which supports treating the hashes as actionable blocklist/hunt material, but a single confirmed RAT sample without campaign context remains routine commodity-malware distribution.

## Confidence notes
The IOC values, family label, and timestamps come directly from ThreatFox (reporter confidence 95), and VirusTotal's 53-engine malicious verdict independently confirms the file is malware. Two things are not from the source: the description of CrossRAT's capabilities and its historical Dark Caracal association come from well-established public reporting on the family, and the claim that the three hashes are one file is an inference from their identical first-seen timestamp (ThreatFox does not state it). No ATT&CK techniques or actors are asserted in the frontmatter because the source contains no behavioral or attribution data for this specific sample.
