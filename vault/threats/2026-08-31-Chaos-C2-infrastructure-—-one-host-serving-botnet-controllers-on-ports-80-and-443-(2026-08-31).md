---
title: Chaos C2 infrastructure — one host serving botnet controllers on ports 80 and 443 (2026-08-31)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-08-31
severity: medium
confidence: medium
flagged: true
cve: []
family: [Chaos]
attack_techniques: [T1071.001]
actors: []
tags: [threat, threatfox, severity/medium]
---

# Chaos C2 infrastructure — one host serving botnet controllers on ports 80 and 443 (2026-08-31)

## What it is
ThreatFox reported two command-and-control (C2) indicators for malware tracked as [[families/Chaos]] on 2026-08-31. Both point at the same server — 144.31.106.168 — listening on port 443 and port 80, the two ports normal web traffic uses. Infected machines contact this server to receive instructions, so any connection from inside the network to that address is a strong sign of a compromised host. The operator's use of standard web ports is a deliberate blending tactic: this traffic looks like ordinary browsing in a firewall log.

## Affected products / versions
Unknown — not stated in source. The report describes attacker-controlled infrastructure, not a vulnerable product.

## ATT&CK mapping
- [[techniques/T1071.001]] — Application Layer Protocol: Web Protocols: the C2 endpoints are on TCP/80 and TCP/443, the standard HTTP and HTTPS ports, indicating C2 traffic shaped to blend with normal web browsing. Inferred from the port numbers, not from observed protocol data — see Confidence notes.

## Observed IOCs
| type | value | context |
| --- | --- | --- |
| ip:port | 144.31.106.168:443 | Botnet C2, ThreatFox confidence 75, first seen 2026-08-30 19:43:36 UTC |
| ip:port | 144.31.106.168:80 | Botnet C2, ThreatFox confidence 75, first seen 2026-08-30 19:43:36 UTC |
| ip | 144.31.106.168 | Host behind both indicators. VirusTotal: 4 malicious / 2 suspicious / 49 harmless / 36 undetected. AbuseIPDB: 0% abuse confidence, 0 reports in 90 days |

## Severity assessment
**medium** — This is an IOC-cluster note, which the rubric defaults to medium, and nothing in the source data justifies raising it. The volume is at the low end: two indicators resolving to a single host, one first-seen timestamp, no campaign reference, no victim or targeting detail. Reputation corroboration is thin — VirusTotal shows only 4 malicious and 2 suspicious verdicts against 49 harmless, and AbuseIPDB has no reports at all in 90 days, which is consistent with fresh C2 infrastructure that has not yet been widely flagged but is not itself independent confirmation of large-scale activity. ThreatFox's own confidence is 75, not maximal. No CVE, no exploitation-in-the-wild claim, and no KEV listing applies, so neither the KEV floor nor the ransomware step-up is in play. The rating would rise to high if this host were tied to a broader campaign or if the Chaos attribution were confirmed as the ransomware-associated family rather than the botnet.

## Confidence notes
Medium, and flagged. Two things are uncertain. First, the family label: "Chaos" is used publicly for more than one distinct threat — a Go-based cross-platform DDoS/cryptomining botnet and an unrelated ransomware builder family — and the source data contains only the bare string "Chaos" with no sample hash, payload detail, or reference URL to disambiguate. The `threat_type` of `botnet_cc` is the only evidence available and points toward the botnet reading, but that is inference, not source fact; the severity here deliberately does not apply the ransomware step-up because the association is not established. Second, the ATT&CK mapping is derived from the port numbers alone. Ports 80 and 443 conventionally carry HTTP and HTTPS, but the source provides no protocol capture, so a non-web protocol on those ports cannot be ruled out. The IOC values, ports, threat type, confidence level, and first-seen timestamp are directly from the source; everything else in this note is labelled inference.
