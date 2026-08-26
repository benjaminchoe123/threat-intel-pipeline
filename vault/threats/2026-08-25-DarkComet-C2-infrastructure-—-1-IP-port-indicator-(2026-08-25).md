---
title: DarkComet C2 infrastructure — 1 IP:port indicator (2026-08-25)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-08-25
severity: medium
confidence: low
flagged: true
cve: []
family: [DarkComet]
attack_techniques: [T1071, T1571]
actors: []
tags: [threat, threatfox, severity/medium]
---

# DarkComet C2 infrastructure — 1 IP:port indicator (2026-08-25)

## What it is
ThreatFox published a single command-and-control (C2) indicator attributed to [[families/DarkComet]], an old and widely available remote access trojan. The indicator is an IP address and port that infected machines are believed to contact to receive commands from an operator. In practical terms: if a computer on the network connects to this address, that machine is likely running remote-control malware and someone else has hands-on access to it. This is one address reported on one day, not evidence of a broad campaign.

## Affected products / versions
Not applicable — this is an infrastructure indicator, not a product vulnerability.

## ATT&CK mapping
- [[techniques/T1071]] — Application Layer Protocol: the source classifies the indicator as `botnet_cc`, i.e. an endpoint used for command-and-control traffic between an implant and its operator.
- [[techniques/T1571]] — Non-Standard Port: the C2 endpoint is on TCP/1604, not a common service port, which is consistent with C2 traffic on a non-standard port.

## Observed IOCs

| type | value | context |
|---|---|---|
| ip:port | 132.243.172.182:1604 | ThreatFox `botnet_cc` for [[families/DarkComet]]; confidence 75; first seen 2026-08-25 15:00:38 UTC; no reference URL provided |

## Severity assessment
**medium** — Per the rubric, ThreatFox family-day IOC aggregates default to medium, and nothing here justifies raising that. Volume is minimal (a single indicator), there is no associated named campaign in the source, and [[families/DarkComet]] is commodity malware with no ransomware association that would push the rating up a step. There is no CVE, no exploitation of a product vulnerability, and no evidence of scale. External reputation does not corroborate the report: VirusTotal returns 0 malicious / 1 suspicious against 54 harmless verdicts for the IP, and AbuseIPDB shows 0% abuse confidence with no reports in 90 days. That absence of corroboration argues against rating this higher, though a genuinely fresh C2 endpoint would also be expected to look clean. Blocking the endpoint is cheap; treating it as a major event is not warranted.

## Confidence notes
Low. The only evidence that this address is a [[families/DarkComet]] C2 is the ThreatFox submission itself, which carries a confidence level of 75 and includes no reference URL, no sample hash, and no analysis to trace back to. Independent reputation data does not support the classification — both VirusTotal and AbuseIPDB are effectively clean for this IP, which is common for new infrastructure but leaves the attribution unverified. The IP is also in a `132.243.0.0` range that may be shared or reassigned hosting, so the possibility of a false positive or stale ownership cannot be ruled out from the source data. Both ATT&CK mappings derive from the source's own `botnet_cc` classification and the observed port rather than from any described behavior, so they inherit the same uncertainty; nothing about the malware's on-host behavior (persistence, keylogging, credential theft) is asserted here because the source contains no evidence of it. Flagged for analyst review before this indicator is used to drive anything beyond a low-cost block or a detection watchlist entry.
