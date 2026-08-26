---
title: DCRat C2 infrastructure — 1 IP:port indicator (2026-08-25)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-08-25
severity: medium
confidence: medium
flagged: true
cve: []
family: [DCRat]
attack_techniques: [T1071.001]
actors: []
tags: [threat, threatfox, severity/medium]
---

# DCRat C2 infrastructure — 1 IP:port indicator (2026-08-25)

## What it is
ThreatFox published a single indicator on 2026-08-25 pointing at a command-and-control (C2) server for [[families/DCRat]], a commodity remote access trojan sold cheaply on underground forums and used by many unrelated operators. A C2 server is the machine an already-infected computer calls home to for instructions, so any traffic from inside the network to this address suggests a host is already compromised. The indicator is a single IP address and port, not a vulnerability — it is useful for blocking and for hunting through outbound connection logs. Reporter confidence is 75%, which is moderate rather than definitive.

## Affected products / versions
Not applicable — this is an IOC cluster, not a product vulnerability.

## ATT&CK mapping
- [[techniques/T1071.001]] — Application Layer Protocol: Web Protocols: the source classifies the indicator as `botnet_cc`, meaning an infected host initiates outbound C2 traffic to this address. The specific protocol on port 7777 is not stated in the source, so this mapping rests on the general C2 behavior implied by the `botnet_cc` threat type rather than on observed traffic.

## Observed IOCs
| type | value | context |
|---|---|---|
| ip:port | `69.167.11.198:7777` | DCRat botnet C2, first seen 2026-08-25 09:41:58 UTC, ThreatFox confidence 75%, no reference URL provided |

## Severity assessment
**medium** — Per the rubric, IOC-cluster notes default to medium unless volume or an associated campaign justifies raising them. Neither applies here: this is a single indicator with no linked campaign, no reference URL, and no reported victim scope. DCRat is routine commodity malware distributed broadly rather than a targeted, large-scale campaign, which fits the "routine commodity-malware distribution" band. Reputation data does not push the rating up — VirusTotal shows only 2 malicious and 1 suspicious verdict against 52 harmless, and AbuseIPDB has 0 reports at 0% abuse confidence over 90 days. That thin corroboration is consistent with a freshly stood-up or shared-hosting C2, but it gives no evidence of scale. No CVE, no exploitation, and no wormable or unauthenticated-RCE factor is in play.

## Confidence notes
Flagged. The IP:port, threat type, family attribution, first-seen timestamp, and 75% reporter confidence all come directly from the source. Two things are inference beyond it. First, the ATT&CK mapping: `botnet_cc` establishes that C2 communication occurs, but the source does not describe the protocol, so T1071.001 (web protocols) is partly a pattern-match on DCRat's commonly reported HTTP-based C2 rather than on anything observed in this submission — treat it as indicative, not confirmed. Second, the reputation picture is weak: a 2/52 malicious-to-harmless split on VirusTotal and zero AbuseIPDB reports mean the maliciousness of this specific host is corroborated only by the single ThreatFox submission at 75% confidence. If this IP belongs to shared hosting, blocking it outright could affect unrelated services — verify against your own egress logs before enforcing a block.
