---
title: Ghost RAT Payload IOC — ThreatFox Daily Cluster (2026-07-17)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-07-17
severity: medium
confidence: medium
flagged: true
cve: []
family: [Ghost RAT]
attack_techniques: [T1219]
actors: []
tags: [threat, threatfox, severity/medium]
---

# Ghost RAT Payload IOC — ThreatFox Daily Cluster (2026-07-17)

## What it is
ThreatFox published a payload sample attributed to [[families/Ghost RAT]], a remote access trojan (RAT) family that has circulated for over a decade and gives an attacker interactive control over an infected Windows host — remote shell, file transfer, keylogging, and similar capabilities. The three indicators below (MD5, SHA1, SHA256) appear to represent hash values for the same payload file, submitted within the same minute on 2026-07-16. The source record contains no delivery mechanism, campaign name, or victim/targeting information.

## Affected products / versions
Not applicable — this is a payload IOC record, not a software vulnerability.

## ATT&CK mapping
- [[techniques/T1219]] — Remote Access Software: Ghost RAT's defining behavior is providing an attacker persistent, interactive remote control of the host. This mapping is drawn from well-established public knowledge of the family, not from any behavioral detail in this source record — see Confidence notes.

## Observed IOCs

| type | value | context |
|---|---|---|
| sha1_hash | 974e94efa9515e53d57b16f538c37bb9a81a39ee | payload, first seen 2026-07-16 19:26:26 UTC; VirusTotal: 12/69 engines malicious |
| md5_hash | 3166ae39b46472d2ee53a880eb8248e0 | payload, first seen 2026-07-16 19:26:26 UTC; VirusTotal: 12/69 engines malicious |
| sha256_hash | 0e8553970999b60c3a0a2637e0c282ca52b33d3e3ae88c99b6fa426bddc0075d | payload, first seen 2026-07-16 19:26:25 UTC; VirusTotal: 12/69 engines malicious |

## Severity assessment
**Medium** — This is a ThreatFox family-day IOC cluster, which defaults to medium per the rubric unless volume or an associated campaign justifies escalation. The record is not KEV-listed, carries no stated ransomware association, and provides no evidence of large-scale or targeted distribution — it is a single payload sample reported with high per-IOC confidence (95) from ThreatFox. VirusTotal shows a consistent malicious verdict (12 engines) across all three hash representations, supporting that this is genuine, actively-detected malware rather than a false positive, but the absence of scale or campaign data keeps this at commodity-RAT distribution rather than high.

## Confidence notes
Confidence is medium and this note is flagged because one substantive claim — the ATT&CK mapping to T1219 — is inferred from well-known public characteristics of the Ghost RAT family rather than from any behavior described in the source data. The source itself contains only hash values, a threat-type label ("payload"), and timestamps; it does not describe delivery, C2 communication, or observed capability. Treat the ATT&CK mapping as reasonable but not source-confirmed.
