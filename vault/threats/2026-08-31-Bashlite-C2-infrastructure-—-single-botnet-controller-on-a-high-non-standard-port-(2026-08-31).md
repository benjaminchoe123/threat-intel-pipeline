---
title: Bashlite C2 infrastructure — single botnet controller on a high non-standard port (2026-08-31)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-08-31
severity: medium
confidence: medium
flagged: true
cve: []
family: [Bashlite]
attack_techniques: [T1571]
actors: []
tags: [threat, threatfox, severity/medium]
---

# Bashlite C2 infrastructure — single botnet controller on a high non-standard port (2026-08-31)

## What it is
ThreatFox reported one command-and-control endpoint for [[families/Bashlite]] on 2026-08-31, first seen the previous day. Bashlite (also tracked as Gafgyt) is a long-running family that infects Linux-based IoT devices — routers, cameras, DVRs — typically via weak or default credentials, and uses them to run distributed denial-of-service attacks. Practically, this note is a blocklist entry: any device on your network talking to this address and port is likely already compromised and taking orders from someone else.

## Affected products / versions
- Unknown — not stated in source. The source data identifies a controller address only, not the victim devices or firmware versions it controls.

## ATT&CK mapping
- [[techniques/T1571]] — Non-Standard Port: the controller is reachable on TCP/65481, a high port outside the ranges normally used by the protocols it would otherwise imitate, which is consistent with C2 traffic placed to avoid casual port-based inspection.

## Observed IOCs
| type | value | context |
| --- | --- | --- |
| ip:port | 64.89.160.222:65481 | Bashlite botnet C2, ThreatFox confidence 100, first seen 2026-08-30 10:43:05 UTC |

## Severity assessment
**medium** — This is an IOC-cluster note, which the rubric defaults to medium, and nothing here justifies raising it. The volume is a single indicator on a single host, not a broad campaign, and the source ties it to no named operation or actor. Bashlite is commodity DDoS malware rather than a ransomware-associated family, so no one-step increase applies. There is no CVE, no KEV listing, and no exploitation-in-the-wild claim about a specific product to floor the rating higher. The impact of a Bashlite infection is real but bounded — the device becomes DDoS capacity for someone else, and the primary risk to an owning organization is outbound abuse and bandwidth loss rather than data theft.

## Confidence notes
Two things are inference beyond the source, which is why this is flagged.

First, the ATT&CK mapping. The source describes no protocol, no beacon behavior, and no on-host activity — only an address, a port, and the label `botnet_cc`. T1571 is drawn from the port number itself, which is defensible but thin; no DDoS technique is mapped, because the source data does not observe one and mapping it on the strength of the family name alone would be exactly the guess these instructions prohibit.

Second, the reputation data does not cleanly corroborate the C2 designation. ThreatFox rates its own entry at confidence 100, but VirusTotal shows only 8 malicious and 2 suspicious verdicts against 47 harmless, and AbuseIPDB puts abuse confidence at 11% despite 74 reports in 90 days. That spread is what a shared or mixed-use host looks like — a compromised server or a hosting IP with one malicious service on a high port — as much as it looks like dedicated infrastructure. Block the IP:port pair rather than the bare address, and treat a hit as a signal to inspect the internal device, not as proof the whole host is hostile.

The family attribution comes from ThreatFox's label with `reference: null` — no sample, sandbox run, or write-up was supplied to check it against. The description of Bashlite's IoT targeting and DDoS purpose is well-established public knowledge about the family, not something the source data establishes for this specific indicator.
