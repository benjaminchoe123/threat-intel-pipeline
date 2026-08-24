---
title: BianLian botnet C2 IOC — ThreatFox Daily Cluster (2026-07-20)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-07-20
severity: medium
confidence: medium
flagged: true
cve: []
family: [BianLian]
attack_techniques: [T1071]
actors: []
tags: [threat, threatfox, severity/medium]
---

# BianLian botnet C2 IOC — ThreatFox Daily Cluster (2026-07-20)

## What it is
ThreatFox reported one new command-and-control (C2) server attributed to the [[families/BianLian]] malware family on 2026-07-20. A C2 server is infrastructure that infected devices contact to receive instructions and hand over stolen data. The name BianLian is used for two distinct threats — an Android banking trojan and a separate ransomware/extortion group — and the source data does not say which one this server belongs to. Either way, an active C2 endpoint is infrastructure worth blocking and hunting for in outbound traffic.

## Affected products / versions
Not applicable — this is an IOC cluster note for C2 infrastructure, not a vulnerability in a product.

## ATT&CK mapping
- [[techniques/T1071]] — Application Layer Protocol: the source classifies this indicator as botnet C2 (`botnet_cc`); port 8443 is a common alternate HTTPS port, consistent with C2 traffic blended into web protocols. The specific protocol is not confirmed in the source.

## Observed IOCs
| type | value | context |
|------|-------|---------|
| ip:port | 154.83.186.39:8443 | [[families/BianLian]] C2 server (`botnet_cc`), first seen 2026-07-20 09:43:39 UTC, ThreatFox reporter confidence 75 |

## Severity assessment
**medium** — This is a ThreatFox family-day IOC cluster, which the rubric defaults to medium, and at a single indicator the volume does not justify raising it. The ransomware-association step-up would push this to high if the indicator belongs to the BianLian ransomware group, but ThreatFox's BianLian family label frequently denotes the Android banking trojan, and the source provides no reference resolving the ambiguity — so the step-up is not applied. Reputation corroboration is weak: VirusTotal shows only 2 of 91 engines flagging the IP as malicious, and AbuseIPDB has zero reports in 90 days, which is consistent with fresh infrastructure but does not indicate a large-scale active campaign. No evidence of an associated campaign is present in the source.

## Confidence notes
The IOC value, type, threat classification, and first-seen timestamp come directly from the source and are reliable as reported (ThreatFox reporter confidence 75, no external reference attached). Two things are inference beyond the source: (1) which BianLian this is — the Android banking trojan and the ransomware group share the name, and the source does not distinguish them, which is why the ransomware severity step-up was not applied; (2) the T1071 mapping rests on the `botnet_cc` classification and the 8443 port choice, not on observed protocol behavior. Reputation data only weakly corroborates the indicator (2 VT detections, no AbuseIPDB reports). Flagged for these reasons; confidence is medium.
