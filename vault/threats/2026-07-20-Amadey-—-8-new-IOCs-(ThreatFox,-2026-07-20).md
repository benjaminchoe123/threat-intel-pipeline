---
title: Amadey — 8 new IOCs (ThreatFox, 2026-07-20)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-07-20
severity: medium
confidence: high
flagged: false
cve: []
family: [Amadey]
attack_techniques: [T1071.001]
actors: []
tags: [threat, threatfox, severity/medium]
---

# Amadey — 8 new IOCs (ThreatFox, 2026-07-20)

## What it is
ThreatFox published 8 new indicators tied to [[families/Amadey]] on 2026-07-20: six file hashes for malware payloads and two command-and-control (C2) URLs. Amadey is a long-running, commercially sold botnet loader — once on a machine it reports in to its C2 server and downloads additional malware chosen by whoever is renting it. These indicators give defenders fresh file hashes to block or hunt for and two live C2 addresses to watch for in network traffic.

## Affected products / versions
Not applicable — this is an IOC cluster, not a vulnerability in a specific product. Amadey targets Windows systems generally.

## ATT&CK mapping
- [[techniques/T1071.001]] — Application Layer Protocol: Web Protocols: both C2 indicators are plain-HTTP URLs ending in `.php` endpoints, labeled `botnet_cc` in the source — the botnet communicates with its controllers over HTTP.

## Observed IOCs

| type | value | context |
|------|-------|---------|
| sha256_hash | e85149704da6ee8f9bc1c55304c560d1a792180489d4859a64cf0a4e056ccf52 | payload; first seen 2026-07-20 01:15:45 UTC |
| sha1_hash | 16646bfd7f6554cd170fb373ce813c24f37e829e | payload; first seen 2026-07-20 01:15:45 UTC |
| md5_hash | f8e68cddf13a94d821a4b265172a0e32 | payload; first seen 2026-07-20 01:15:45 UTC |
| md5_hash | 5d11d7b9b175695c197014bc6aa2fbdb | payload; first seen 2026-07-20 01:15:44 UTC |
| sha256_hash | a86c023a02f1454738b39f753f50777c238b4ea296ffc76cd41c3059f216be10 | payload; first seen 2026-07-20 01:15:43 UTC |
| sha1_hash | c25b20a5f15a0f69e0343b539bb4408a4e3739db | payload; first seen 2026-07-20 01:15:43 UTC |
| url | http://192.162.199.186/aB7xTy2N/mAjOR.php | botnet C2; first seen 2026-07-19 23:45:09 UTC |
| url | http://196.251.107.186/qK3mRv9L/pLdWr.php | botnet C2; first seen 2026-07-19 23:45:06 UTC |

## Severity assessment
**medium** — This is a ThreatFox family-day IOC aggregate, which the rubric defaults to medium. The volume (8 indicators, two C2 servers) is routine commodity-malware distribution, not an unusually large campaign that would justify raising it to high. [[families/Amadey]] is a loader rather than a ransomware family itself, so the ransomware-association bump does not apply, though its role as a delivery vector for follow-on payloads is why these IOCs are still worth acting on. VirusTotal strongly corroborates the payloads (53 of 68 engines flag the primary sample as malicious), confirming these are real, actively detected malware — but confirmation of maliciousness doesn't change the scope factors that keep this at medium.

## Confidence notes
The source data fully supports the above: all IOCs come directly from ThreatFox (95–100% source confidence), VirusTotal independently confirms the sampled hashes as widely detected malware, and the single ATT&CK mapping is drawn from the source's own `botnet_cc` HTTP URL indicators rather than family-name pattern-matching. The one-line characterization of Amadey as a botnet loader is well-established public knowledge about the family.
