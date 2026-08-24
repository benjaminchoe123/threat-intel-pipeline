---
title: Agent Tesla FTP C2 Infrastructure — ThreatFox Daily IOC Cluster (2026-08-04)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-08-04
severity: medium
confidence: medium
flagged: true
cve: []
family: [Agent Tesla]
attack_techniques: [T1071.002]
actors: []
tags: [threat, threatfox, severity/medium]
---

# Agent Tesla FTP C2 Infrastructure — ThreatFox Daily IOC Cluster (2026-08-04)

## What it is
ThreatFox published five new command-and-control domains tied to [[families/Agent Tesla]] on 2026-08-04. Agent Tesla is a long-running commodity information stealer sold to low-skill operators; it harvests saved browser passwords, email credentials, and keystrokes from infected Windows machines and sends them back to the operator. Every domain in this batch uses an `ftp.` hostname and is classified by the source as botnet C2, which matches how this family is normally configured to ship stolen data out. Practical impact for a defender: any host resolving these names is very likely already compromised and leaking credentials.

## Affected products / versions
Not applicable — this is an IOC cluster, not a product vulnerability. Agent Tesla targets Windows endpoints.

## ATT&CK mapping
- [[techniques/T1071.002]] — Application Layer Protocol: File Transfer Protocols: all five indicators are `ftp.*` hostnames that the source labels as botnet C2, indicating the operator is using FTP as the channel for command-and-control and data egress rather than HTTP.

## Observed IOCs

| type | value | context |
| --- | --- | --- |
| domain | ftp.gebzekamlok.com | botnet_cc, confidence 100, first seen 2026-08-04 12:53:25 UTC · VT 6 malicious / 1 suspicious |
| domain | ftp.darlenemarino.cyou | botnet_cc, confidence 100, first seen 2026-08-04 09:17:10 UTC · VT 5 malicious / 3 suspicious |
| domain | ftp.melrz.com | botnet_cc, confidence 100, first seen 2026-08-04 09:14:59 UTC · VT 14 malicious / 1 suspicious |
| domain | ftp.lodenrandmarines.com | botnet_cc, confidence 100, first seen 2026-08-04 09:14:00 UTC · VT 14 malicious / 1 suspicious |
| domain | ftp.raxclopent.info | botnet_cc, confidence 100, first seen 2026-08-04 09:08:27 UTC · no VT data in this lookup |

Each indicator is backed by a MalwareBazaar sample reference (see source links in the ThreatFox entries).

## Severity assessment
**medium** — This is a routine commodity-malware distribution cluster, which the rubric places at medium by default for URLhaus/ThreatFox family-day aggregates. Volume is low (five indicators in one day) and there is nothing in the source pointing to a named campaign, a specific targeted sector, or an escalation that would justify raising it to high. Agent Tesla is not a ransomware-associated family, so the ransomware step-up does not apply, and no CVE or KEV listing is involved, so the KEV floor does not apply either. Working against a lower rating: ThreatFox assigns all five a confidence level of 100, and VirusTotal independently flags four of the four checked domains as malicious by multiple engines, so these are real live C2 endpoints rather than speculative indicators. The credential-theft impact on any single infected host is serious, but the scope and scale here are ordinary for this family.

## Confidence notes
Directly supported by the source: the five domain values, their `botnet_cc` threat type, ThreatFox confidence of 100, first-seen timestamps, and the sample references. Supported by reputation data: multi-engine malicious verdicts for four of the five domains — `ftp.raxclopent.info` was not returned in the lookup, which is common for fresh indicators and does not imply it is benign.

Flagged because part of the note is inference rather than source-stated fact. The source does not describe any observed behavior — it provides indicators and a classification only. The [[techniques/T1071.002]] mapping is inferred from the `ftp.` hostname pattern combined with the botnet C2 label and well-known [[families/Agent Tesla]] tradecraft; no packet capture or sandbox detail confirming FTP C2 for *these specific* domains appears in the source. Likewise, the description of what Agent Tesla steals (browser credentials, keystrokes) is established public knowledge about the family, not something this cluster demonstrates. No additional techniques (keylogging, defense evasion, initial access) were mapped because the source shows nothing about delivery or on-host behavior, and mapping them would be pattern-matching on the family name alone. No actors are listed — Agent Tesla is sold broadly and attribution of these domains to a specific operator is not supportable from this data.
