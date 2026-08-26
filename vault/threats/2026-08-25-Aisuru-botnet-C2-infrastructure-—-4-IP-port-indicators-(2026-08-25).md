---
title: Aisuru botnet C2 infrastructure — 4 IP:port indicators (2026-08-25)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-08-25
severity: medium
confidence: medium
flagged: true
cve: []
family: [Aisuru]
attack_techniques: [T1071, T1498]
actors: []
tags: [threat, threatfox, severity/medium]
---

# Aisuru botnet C2 infrastructure — 4 IP:port indicators (2026-08-25)

## What it is
ThreatFox published four command-and-control (C2) servers tied to the [[families/Aisuru]] botnet on 2026-08-25. A C2 server is the machine infected devices phone home to for instructions, so blocking these addresses cuts the operator's control over any device on our network that is already compromised. All four indicators were submitted with a 100% confidence level by the reporting party. Publicly, Aisuru is described as a Mirai-derived botnet that infects internet-exposed IoT devices (routers, DVRs, cameras) and uses them for large-scale denial-of-service attacks — that characterization comes from open reporting, not from this feed entry.

## Affected products / versions
Unknown — not stated in source. The source provides C2 infrastructure only, with no indication of which device models or firmware versions the botnet recruits.

## ATT&CK mapping
- [[techniques/T1071]] — Application Layer Protocol: ThreatFox classifies all four indicators as `botnet_cc`, meaning infected hosts initiate outbound C2 sessions to these IP:port pairs. Ports 8080 (twice), 9035, and 34567 are high/alternate service ports consistent with an application-layer C2 channel, though the exact protocol is not stated in the source.
- [[techniques/T1498]] — Network Denial of Service: mapped from public reporting on [[families/Aisuru]] as a DDoS botnet, **not** from anything in this source data. See Confidence notes.

## Observed IOCs

| type | value | context |
| --- | --- | --- |
| ip:port | 46.101.146.87:8080 | Aisuru botnet C2, first seen 2026-08-25 16:29:38 UTC, confidence 100. VT: 6 malicious / 2 suspicious; AbuseIPDB 3% (1 report/90d) |
| ip:port | 159.89.24.55:9035 | Aisuru botnet C2, first seen 2026-08-25 06:48:59 UTC, confidence 100. VT: 4 malicious / 3 suspicious; AbuseIPDB 0% (1 report/90d) |
| ip:port | 168.144.188.31:8080 | Aisuru botnet C2, first seen 2026-08-25 06:48:58 UTC, confidence 100. VT: 3 malicious / 2 suspicious; AbuseIPDB 0% (0 reports/90d) |
| ip:port | 64.227.187.82:34567 | Aisuru botnet C2, first seen 2026-08-25 06:48:56 UTC, confidence 100. VT: 4 malicious / 2 suspicious; AbuseIPDB 2% (1 report/90d) |

No references, hashes, or payload URLs were included with any of the four submissions.

## Severity assessment
**medium** — This is an IOC-cluster note from a ThreatFox family-day aggregate, which the rubric defaults to medium unless volume or a named campaign justifies raising it. Volume is low: four indicators in a single day is routine commodity-botnet infrastructure churn, not a surge. No CVE, exploitation activity, or targeting of our environment is described, so none of the critical/high factors (active exploitation, wormable, unauthenticated RCE in widely deployed software) apply. Reputation data argues against escalation as well — VirusTotal shows only 3–6 malicious engines per address against ~50 harmless verdicts, and AbuseIPDB abuse confidence is 0–3% with at most one report in 90 days, consistent with freshly stood-up hosting rather than long-abused infrastructure. [[families/Aisuru]] is not a ransomware-associated family, so the ransomware one-step raise does not apply. The practical risk is to internet-exposed IoT/edge devices, which is a real but bounded exposure for most enterprise networks.

## Confidence notes
Confidence is medium and this note is flagged. What the source directly supports: the four IP:port values, their `botnet_cc` threat type, their first-seen timestamps, the 100% submitter confidence, and the family label "Aisuru". Everything else is inference. Specifically: the description of Aisuru as a Mirai-derived IoT botnet used for DDoS, and the [[techniques/T1498]] mapping that follows from it, are pattern-matched from the family name against public reporting — the source data contains no payload, no victim device information, and no observed attack behavior to confirm it. The [[techniques/T1071]] mapping is better supported (the `botnet_cc` classification implies an outbound C2 channel) but the specific application-layer protocol on ports 8080/9035/34567 is not stated and was not verified. Note also the tension between the submitter's 100% confidence and the weak third-party reputation signals; the most likely explanation is that these are recently provisioned hosts that scanners have not yet caught up with, but that is an assumption, not a finding.
