---
title: DCRat botnet C2 — 1 new IOC (ThreatFox, 2026-07-20)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-07-20
severity: medium
confidence: medium
flagged: false
cve: []
family: [DCRat]
attack_techniques: [T1571, T1219]
actors: []
tags: [threat, threatfox, severity/medium]
---

# DCRat botnet C2 — 1 new IOC (ThreatFox, 2026-07-20)

## What it is
ThreatFox reported one new command-and-control server tied to [[families/DCRat]] (DarkCrystal RAT), a cheap, commercially sold remote access trojan that lets an attacker fully control an infected Windows computer — stealing passwords, logging keystrokes, and downloading further malware. Infected machines in a network would connect out to this server to receive the attacker's commands. Blocking or alerting on this address helps catch existing infections before data is stolen.

## Affected products / versions
Not applicable — this is an IOC cluster note for C2 infrastructure, not a product vulnerability.

## ATT&CK mapping
- [[techniques/T1571]] — Non-Standard Port: the C2 listener runs on port 8624, a non-standard port not associated with any common service.
- [[techniques/T1219]] — Remote Access Tools: [[families/DCRat]] is a commercially distributed remote access trojan; the reported infrastructure is its command channel.

## Observed IOCs
| type | value | context |
|------|-------|---------|
| ip:port | 209.160.115.136:8624 | [[families/DCRat]] botnet C2, first seen 2026-07-19 19:44:19 UTC (ThreatFox confidence 75) |

## Severity assessment
**medium** — Per the rubric, ThreatFox family-day IOC-cluster notes default to medium, and nothing here justifies raising it: this is a single C2 indicator, not a large-scale campaign, and DCRat is commodity malware rather than a ransomware-associated family (no severity step-up applies). Volume is minimal (one IOC). Reputation data offers only moderate corroboration — VirusTotal shows 3 malicious and 2 suspicious engine verdicts against 52 harmless, and AbuseIPDB has zero abuse reports in 90 days, consistent with fresh, not-yet-widely-reported infrastructure. Routine commodity-malware C2 distribution fits the medium tier.

## Confidence notes
Medium. The source directly supports the IOC, its botnet_cc classification, and the DCRat family attribution (ThreatFox confidence 75, not certainty). The T1571 mapping is directly observable from the non-standard port in the IOC; the T1219 mapping rests on well-established public knowledge of what DCRat is, not on behavior described in this source. Independent corroboration is thin: only 3 of ~91 VirusTotal engines flag the IP and AbuseIPDB has no reports, so the indicator is plausible but not strongly cross-validated. The general description of DCRat's capabilities is public knowledge about the family, not derived from this source.
