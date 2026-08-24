---
title: Ghost RAT payload hashes — ThreatFox daily IOC cluster (2026-07-20)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-07-20
severity: medium
confidence: medium
flagged: false
cve: []
family: [Ghost RAT]
attack_techniques: []
actors: []
tags: [threat, threatfox, severity/medium]
---

# Ghost RAT payload hashes — ThreatFox daily IOC cluster (2026-07-20)

## What it is
ThreatFox published three file hashes tagged as [[families/Ghost RAT]] payloads on 2026-07-20. Ghost RAT (commonly written Gh0st RAT) is a long-established remote access trojan whose source code has been public for years; it lets an attacker fully control an infected Windows machine — viewing the screen, logging keystrokes, and stealing files. The three hashes (SHA-256, SHA-1, and MD5, all first seen at the same timestamp) very likely identify a single malware sample rather than three distinct files.

## Affected products / versions
Not applicable — this is an IOC cluster, not a vulnerability in a specific product.

## ATT&CK mapping
None supportable from the source data. ThreatFox provides only the family tag and hashes with no described behavior, so no technique mapping is defensible here (see Confidence notes).

## Observed IOCs
| type | value | context |
|------|-------|---------|
| sha256_hash | 3fc95667b98c637ba785b67dff1bd15ff7a21f082d25894c3a78ec1b6206fcd7 | Ghost RAT payload, first seen 2026-07-20 11:23:17 UTC, ThreatFox confidence 95 |
| sha1_hash | e17f76e0b4c47a5f54ca51b105be0dd29df50c7c | Ghost RAT payload, same first-seen timestamp — likely the same file as the SHA-256 above |
| md5_hash | eff8675fac22c49107a2a42d3c735f10 | Ghost RAT payload, same first-seen timestamp — likely the same file as the SHA-256 above |

## Severity assessment
**medium** — Under the rubric, IOC-cluster notes from ThreatFox default to medium, and nothing here justifies raising it: the volume is minimal (three hashes, apparently one sample), the source ties it to no active large-scale campaign, and [[families/Ghost RAT]] is commodity RAT tooling rather than ransomware, so no one-step severity increase applies. VirusTotal confirms the sample is malicious (7 engine detections, zero harmless verdicts), but the low detection count (7 of 70 engines) suggests a fresh or repacked build, which is worth watching but does not by itself indicate widespread exploitation. This fits the "routine commodity-malware distribution" tier of the rubric.

## Confidence notes
The IOC values themselves come directly from ThreatFox (reported at confidence 95) and are corroborated as malicious by VirusTotal, so the indicators are solid. Confidence is medium rather than high because the Ghost RAT family attribution rests solely on the ThreatFox tag — the source describes no behavior, delivery method, or campaign context, and the low VirusTotal detection rate (7/70) means engine consensus on the family is thin. The observation that all three hashes represent one file is an inference from the identical first-seen timestamps, not stated in the source. No ATT&CK techniques are listed because mapping them would rely on the family name alone, which the low-confidence rule prohibits.
