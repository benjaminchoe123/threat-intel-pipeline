---
title: Agent Tesla — 12 new IOCs (ThreatFox, 2026-07-20)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-07-20
severity: medium
confidence: medium
flagged: false
cve: []
family: [Agent Tesla]
attack_techniques: [T1056.001, T1555.003, T1071.003]
actors: []
tags: [threat, threatfox, severity/medium]
---

# Agent Tesla — 12 new IOCs (ThreatFox, 2026-07-20)

## What it is
ThreatFox published 12 new indicators on 2026-07-20 tied to [[families/Agent Tesla]], a long-running commodity infostealer sold to many different criminal operators. It steals saved passwords, records keystrokes, and sends the stolen data back to the attacker, typically arriving via malicious email attachments. Today's batch is file hashes for four distinct payload samples (each reported as SHA-256, SHA-1, and MD5), useful for blocking and retroactive hunting in endpoint telemetry.

## Affected products / versions
Not applicable — this is an IOC cluster for malware payload samples, not a product vulnerability.

## ATT&CK mapping
- [[techniques/T1056.001]] — Input Capture: Keylogging: Agent Tesla's core, well-documented capability is capturing keystrokes on infected hosts.
- [[techniques/T1555.003]] — Credentials from Web Browsers: the family routinely harvests saved credentials from browsers and mail/FTP clients.
- [[techniques/T1071.003]] — Application Layer Protocol: Mail Protocols: Agent Tesla commonly exfiltrates stolen data over SMTP to attacker-controlled mailboxes.

## Observed IOCs
| type | value | context |
|---|---|---|
| sha256_hash | 58328b7f4fecb0407da1947937b41162e23a61559d6f49526ec1683febad6ddc | payload sample, first seen 2026-07-20 11:23:09 UTC; VT 24/43 malicious |
| sha1_hash | 1c89e143465d44f7d3fa6561436624b6990027fb | same sample (SHA-1), first seen 2026-07-20 11:23:09 UTC |
| md5_hash | 10cc531b5f4765f53cd3a58a2c23ffcf | same sample (MD5), first seen 2026-07-20 11:23:09 UTC |
| sha256_hash | 2112d749000ec32a1eeb719eb1e0daee69cda7946eab3049f5d2fd83bac566c2 | payload sample, first seen 2026-07-20 11:23:08 UTC; VT 45/69 malicious |
| sha1_hash | 22d0daad3abfb17c90862ac3fd80746738c9074e | same sample (SHA-1), first seen 2026-07-20 11:23:08 UTC |
| md5_hash | d8d19575c1de6c091ebf0624596478fa | same sample (MD5), first seen 2026-07-20 11:23:08 UTC |
| sha256_hash | 940f0d74f64672c50d4b6ed704aefa743d81b7cdfbeb6666a00f690f80b7b001 | payload sample, first seen 2026-07-20 11:22:40 UTC |
| sha1_hash | a302b2902da6ebf1c6f9b79158320bb4111d75a0 | payload sample hash, first seen 2026-07-20 11:22:41 UTC |
| md5_hash | 791d27fd45d5ac5f25235b46547129ad | payload sample hash, first seen 2026-07-20 11:22:41 UTC |
| sha256_hash | e6290924b6e7a434776239ae19e79b02e88c3a6bef1b0e1d61041cc4176dec6e | payload sample, first seen 2026-07-20 11:22:39 UTC |
| sha1_hash | ea9efc587962f4a1286aa26d274354039472d436 | payload sample hash, first seen 2026-07-20 11:22:39 UTC |
| md5_hash | a757a8b09d99acc2835fd0d26541e46c | payload sample hash, first seen 2026-07-20 11:22:39 UTC |

## Severity assessment
**medium** — Per the rubric, IOC-cluster notes from ThreatFox daily aggregates default to medium unless volume or an associated campaign justifies more. Twelve hashes covering roughly four payload samples is routine daily volume for [[families/Agent Tesla]], a commodity infostealer distributed continuously at scale; nothing in the source ties these samples to a specific large-scale campaign. Agent Tesla is not ransomware-associated, so no one-step upgrade applies. The threat is real and VirusTotal confirms the sampled hashes as widely detected (24–45 engines malicious), but this is routine commodity-malware distribution, which the rubric places at medium.

## Confidence notes
The IOC values, family attribution, and timestamps come directly from the ThreatFox source data, and VirusTotal independently confirms the sampled hashes as malicious. The ATT&CK mappings, however, are based on well-established public reporting about the Agent Tesla family generally — the source contains only hashes and describes no behavior for these specific samples, so confidence is capped at medium. The grouping of hashes into "same sample" sets is inferred from identical first-seen timestamps (the source does not explicitly link SHA-256/SHA-1/MD5 triplets). No C2, delivery, or victim data was present in the source.
