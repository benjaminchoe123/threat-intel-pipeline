---
title: Chaos Botnet C2 IOC — ThreatFox Daily Cluster (2026-07-20)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-07-20
severity: medium
confidence: medium
flagged: false
cve: []
family: [Chaos]
attack_techniques: []
actors: []
tags: [threat, threatfox, severity/medium]
---

# Chaos Botnet C2 IOC — ThreatFox Daily Cluster (2026-07-20)

## What it is

ThreatFox reported one new command-and-control (C2) server tied to [[families/Chaos]], a Go-based botnet malware known publicly for infecting a wide range of Windows and Linux systems — including routers and other small networked devices — and using them for DDoS attacks and cryptomining. A C2 server is the machine infected devices call back to for instructions. Blocking or alerting on this address helps catch infected hosts on a network before they are put to work by the botnet operator.

## Affected products / versions

Not applicable — this is an IOC cluster note, not a vulnerability. Chaos malware is publicly known to target multiple architectures across Windows and Linux, but the source data does not state targeting details for this infrastructure.

## ATT&CK mapping

None supportable from the source data. The `botnet_cc` threat type establishes that this is C2 infrastructure, but the source does not describe the protocol or behavior, so no specific technique ID can be defensibly assigned. See Confidence notes.

## Observed IOCs

| type | value | context |
|------|-------|---------|
| ip:port | 89.223.24.227:52709 | Chaos botnet C2 server, first seen 2026-07-19 19:45:39 UTC (ThreatFox confidence 75) |

## Severity assessment

**medium** — Per the rubric, ThreatFox family-day IOC cluster notes default to medium unless volume or an associated campaign justifies raising it. This cluster contains a single IOC with no campaign context, so nothing supports an upward adjustment. The Chaos botnet name overlaps with the Chaos ransomware builder, but this indicator is typed `botnet_cc` (DDoS/cryptomining botnet infrastructure), so the ransomware-association step-up does not apply. Reputation signals are mixed rather than alarming: VirusTotal shows only 2 malicious and 2 suspicious verdicts against 51 harmless, and AbuseIPDB has zero abuse reports in 90 days — consistent with fresh, low-volume C2 infrastructure rather than a large-scale active campaign.

## Confidence notes

Confidence is medium. The IOC value, type, threat type, and first-seen timestamp come directly from ThreatFox, which itself rates this indicator at 75% confidence. Corroboration is weak: only 2 of 91 VirusTotal engines flag the IP as malicious and AbuseIPDB shows no abuse reports, so third-party validation of the C2 attribution is thin (though normal for an indicator first seen the previous day). The family attribution to Chaos is ThreatFox's tag, not independently verified here; the background description of Chaos as a Go-based DDoS/cryptomining botnet is well-established public knowledge about the family, not derived from this source. The ATT&CK list is left empty because the source describes no behavior beyond the `botnet_cc` label.
