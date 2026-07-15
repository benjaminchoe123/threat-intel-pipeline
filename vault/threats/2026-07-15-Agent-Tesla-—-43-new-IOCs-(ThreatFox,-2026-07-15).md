---
title: Agent Tesla — 43 new IOCs (ThreatFox, 2026-07-15)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-07-15
severity: medium
confidence: medium
flagged: false
cve: []
family: [Agent Tesla]
attack_techniques: [T1071, T1056.001, T1555.003]
actors: []
tags: [threat, threatfox, severity/medium]
---

# Agent Tesla — 43 new IOCs (ThreatFox, 2026-07-15)

## What it is
ThreatFox reported 43 new indicators tied to [[families/Agent Tesla]], a long-running commodity information stealer sold on underground markets. It records keystrokes and steals saved passwords from browsers and email clients, then sends them back to the attacker. This batch is one command-and-control domain plus 42 payload file hashes, consistent with routine ongoing distribution of the malware rather than a new campaign.

## Affected products / versions
Not applicable — this is an IOC cluster for a malware family, not a product vulnerability. [[families/Agent Tesla]] targets Windows systems.

## ATT&CK mapping
- [[techniques/T1071]] — Application Layer Protocol: the source lists `ftp.fundacionpiaz.org` as active botnet C2 infrastructure for this family.
- [[techniques/T1056.001]] — Input Capture: Keylogging: keystroke logging is core, well-documented [[families/Agent Tesla]] behavior (family knowledge, not shown in this source data).
- [[techniques/T1555.003]] — Credentials from Web Browsers: harvesting saved browser credentials is core, well-documented [[families/Agent Tesla]] behavior (family knowledge, not shown in this source data).

## Observed IOCs

| type | value | context |
|---|---|---|
| domain | ftp.fundacionpiaz.org | Botnet C2 (ThreatFox confidence 100; linked to a MalwareBazaar sample) |
| sha1 | 3c679b739501a308372dffb6485de4ae9c14293b | Payload hash |
| md5 | 132fd7e557ae7b95f7dc8c2b5bbefe06 | Payload hash |
| sha256 | 8dbd16903437126bd14983912aac07748f95289da274c04f5f4a6610e77bfd9c | Payload hash |
| sha256 | bc6d86cef1b7404823c1d830387b2c9b1289c453620482fc1749dd5d2ade3897 | Payload hash |
| sha1 | b9308e6c91b64f4695a5418276a25f35e6eb18ae | Payload hash |
| md5 | 183573ffe3b0c5f9188c5fab6b80ebec | Payload hash |
| sha256 | c5b0a5ab88c4530029bc900d9f3a3a3e7868d5cd3adde5a479a302fed2d50fb2 | Payload hash |
| sha1 | 248d7c09262684327d785410a5aea70158cf5147 | Payload hash |
| md5 | 30c502ded0262fcef7266948147d963d | Payload hash |
| sha1 | dd6d0514ba78dbf7e39288b14a9fa36338ca76d3 | Payload hash |
| md5 | 70ccc55374a58a7513304ffafa37db6e | Payload hash |
| sha1 | 7c61077ca3c1d12c73e308b2a674212bab4bf88b | Payload hash |
| md5 | 578a549be9926fbd8016a8ff8ec0636e | Payload hash |
| sha256 | fe3e2114d24a0409a7b58e97a67c9da775fef6bc736e26f5a3ddaab131b090a3 | Payload hash |
| sha1 | e96244a68e280ef833f34ee984557ac35deb2c57 | Payload hash |
| md5 | 8951ce27300748d7b3d471020fbbd830 | Payload hash |
| sha256 | 284ad50e9107b510ea42440c143b96f88fc30b524f325e4c450f659871438475 | Payload hash |
| sha1 | 65a8ef55ec58fefe4b376547e0779f003b05bab5 | Payload hash |
| md5 | 4df01b918569068a3a0199826627abde | Payload hash |
| sha256 | e3a7b527e98ba28056ccaf3c3504d067714782de35c5f5141781f12cb894c4b0 | Payload hash |
| sha1 | 828547dae1fcb05f9e12cdec3faa9b8914eec7ff | Payload hash |
| md5 | 013081a63b3561182855875975b849ea | Payload hash |
| sha256 | e51673c5981d94544b0392939ce7c0ac0f31bad427b1ea6ea998634b8e443b3e | Payload hash |
| md5 | a4ba482014b7881e331029d59c1fd739 | Payload hash |
| sha256 | ba368193363e2f907a667c48ebb1335aab4dcffb38a6843687a3a46bc9ca0b0d | Payload hash |
| md5 | 89a42088178e5c5778bcef4b02930b14 | Payload hash |
| sha256 | 4f78fc5a1fff341c00583c7276902f0efb6a9edefe1bbd327d72fa1cc7311eee | Payload hash |
| sha1 | 87d1fe176708d762d7c4218a71ff2ba8e0098c63 | Payload hash |
| md5 | 83aaec9b27ca20a5f1cdd75aa3c89d9a | Payload hash |
| sha256 | 0de09d55351a5e10c4f51dd12b0edb385eb56da86d54d80276915116a0c847ad | Payload hash |
| sha1 | 2b150301ee3c2b37c551fefb4bf2a291db3660ac | Payload hash |
| md5 | a985c254ed2d791688736f83ee2befde | Payload hash |
| sha256 | 97b6c601828796cbb4b7f7d7dba3789a792816fdca70201e3965dc57694882a4 | Payload hash |
| sha1 | aad5448e55ecb42184fc171c6128d809a8396596 | Payload hash |
| md5 | a85f8ef34cc5ab90e0aa6c9b1a5b289d | Payload hash |
| sha256 | 6e00f52072b251d58ce01eecd95aa6022db7ba161e7d68d2c224091392f6c832 | Payload hash |
| sha1 | 397819924ee78628c50f09b86a88b10ce6eb4299 | Payload hash |
| md5 | 73d3a30675edff0224cfaeef1b578b66 | Payload hash |
| sha256 | 56e83469b37785a3ff4a82395e014c95da9643b58733d3a085944821dd1fd653 | Payload hash |
| sha1 | ae187e52be3f84d92e9994c62de1edab36c339b4 | Payload hash |
| sha256 | 8365a58fe73a021c914e57868087df4299d61dfdfd34e00cc89e496aa18c0572 | Payload hash |
| sha1 | 125ce3384144e4475e652027623b0aa5d6da081b | Payload hash |

## Severity assessment
**medium** — Per the rubric, IOC-cluster notes from ThreatFox family-day aggregates default to medium unless volume or an associated campaign justifies high. [[families/Agent Tesla]] is commodity malware and this batch reflects routine distribution: 43 IOCs, but most are overlapping hash formats (SHA256/SHA1/MD5 of what appear to be the same samples, given identical first-seen timestamps), so the effective sample count is much smaller than the raw count suggests. Only one active C2 domain is reported. No CVE exploitation, no ransomware association, and no named campaign appears in the source, so no context adjustment raises the rating.

## Confidence notes
The IOC values, family attribution, and C2 designation come directly from ThreatFox source data and are high-confidence (ThreatFox confidence 95–100). Confidence is set to medium because the ATT&CK mappings for keylogging (T1056.001) and browser credential theft (T1555.003) rest on well-established public knowledge of the [[families/Agent Tesla]] family, not on behavior described in this source — the source contains only hashes and one C2 domain. The `ftp.` hostname of the C2 domain is consistent with Agent Tesla's documented FTP-based exfiltration, but the source does not confirm the protocol, so no exfiltration technique was mapped. The observation that hash-format overlap reduces the effective sample count is analyst inference from identical timestamps, not stated by the source.
