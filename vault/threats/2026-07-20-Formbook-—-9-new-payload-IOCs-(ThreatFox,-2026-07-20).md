---
title: Formbook — 9 new payload IOCs (ThreatFox, 2026-07-20)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-07-20
severity: medium
confidence: medium
flagged: false
cve: []
family: [Formbook]
attack_techniques: [T1056.001, T1555, T1055]
actors: []
tags: [threat, threatfox, severity/medium]
---

# Formbook — 9 new payload IOCs (ThreatFox, 2026-07-20)

## What it is
ThreatFox reported 9 new file hashes on 2026-07-20 tied to [[families/Formbook]], a commodity information stealer sold as malware-as-a-service since 2016. Formbook harvests credentials from browsers and email clients, logs keystrokes, and grabs data submitted in web forms, then sends it to attacker-controlled servers. These hashes identify fresh payload samples circulating in ongoing distribution — most commonly via malicious email attachments — and are useful for blocking and retro-hunting in endpoint and mail telemetry.

## Affected products / versions
Not applicable — this is an IOC cluster for malware payload samples, not a product vulnerability.

## ATT&CK mapping
- [[techniques/T1056.001]] — Input Capture: Keylogging: Formbook's core capability is capturing keystrokes to steal credentials and other typed data.
- [[techniques/T1555]] — Credentials from Password Stores: Formbook extracts saved credentials from browsers and email clients.
- [[techniques/T1055]] — Process Injection: Formbook routinely injects into legitimate Windows processes to evade detection.

These mappings come from well-documented Formbook behavior, not from the source data — see Confidence notes.

## Observed IOCs

| type | value | context |
|------|-------|---------|
| md5_hash | aac21459dc203d21c539a72d54221102 | Formbook payload, first seen 2026-07-20 11:23:14 UTC |
| sha256_hash | 78e53037a3b94c1a14f4c8283f27b1b9b6a0601515fe6b4cdc28ac8fce9b938f | Formbook payload, first seen 2026-07-20 11:23:13 UTC |
| sha1_hash | 61a27756cba4c8be0a6465912de786b90f6f8de1 | Formbook payload, first seen 2026-07-20 11:23:13 UTC |
| sha256_hash | d3adedb75d5f43ee0a1400fa5be76e4f734ec031d40b426a390ec5f453a40859 | Formbook payload, first seen 2026-07-20 11:22:47 UTC |
| sha1_hash | 6f1cc02617b24127df7fb482c2e1c9496c0aafbc | Formbook payload, first seen 2026-07-20 11:22:47 UTC |
| md5_hash | 0c9381cfd85e2d1aad8ccbe8bec861ca | Formbook payload, first seen 2026-07-20 11:22:47 UTC |
| sha1_hash | ea88765037a10234f4558c076d3bb1805fe402f6 | Formbook payload, first seen 2026-07-20 11:22:44 UTC |
| md5_hash | a3f6cbc6b8366c4378504eedbb2408d1 | Formbook payload, first seen 2026-07-20 11:22:44 UTC |
| sha256_hash | 865884c27b7ee53c1744c183ca07ce310b4485dfa085fe3ed3c658e38f7d99f2 | Formbook payload, first seen 2026-07-20 11:22:43 UTC |

## Severity assessment
**medium** — Per the rubric, IOC-cluster notes from ThreatFox family-day aggregates default to medium, and nothing here justifies raising it. This is routine commodity-malware distribution: 9 payload hashes in a single day is ordinary volume for Formbook, and the source names no associated campaign, target set, or delivery infrastructure. Formbook is an infostealer, not a ransomware-associated family, so no severity step-up applies. The samples are confirmed malicious — VirusTotal shows 38–48 engine detections on the sampled hashes with zero harmless verdicts — but that confirms the classification rather than indicating unusual scale or impact.

## Confidence notes
The IOC values, family attribution, and timestamps come directly from the ThreatFox source data, and VirusTotal detections (38–48 malicious engines across four sampled hashes) independently corroborate that these are malicious Formbook payloads. Confidence is medium rather than high because the ATT&CK mappings are not derived from behavior described in the source — the source contains only hashes — but from well-established public reporting on the Formbook family's standard capabilities. The description of what Formbook does is likewise family-level knowledge, not sample-specific analysis; no delivery vector or campaign details for these specific samples are in the source.
