---
title: Cobalt Strike C2 Infrastructure — ThreatFox Daily IOC Cluster (2026-07-17)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-07-17
severity: high
confidence: medium
flagged: true
cve: []
family: [Cobalt Strike]
attack_techniques: [T1071]
actors: []
tags: [threat, threatfox, severity/high]
---

# Cobalt Strike C2 Infrastructure — ThreatFox Daily IOC Cluster (2026-07-17)

## What it is
ThreatFox reported six active command-and-control (C2) endpoints for [[families/Cobalt Strike]] on 2026-07-17. [[families/Cobalt Strike]] is a commercial adversary-simulation ("red team") platform that is also one of the most widely abused post-exploitation frameworks in criminal and state-linked intrusions; attackers use it to maintain remote control of compromised hosts after initial access. One IP, 114.134.187.38, appears twice on two different ports, suggesting a single host running multiple listener configurations.

## Affected products / versions
Not applicable — this is an IOC cluster describing attacker infrastructure, not a product vulnerability.

## ATT&CK mapping
- [[techniques/T1071]] — Application Layer Protocol: Cobalt Strike beacons check in to operator-controlled listeners over these IP:port endpoints; the source data confirms the endpoints are flagged as botnet C2 but does not specify the wire protocol in use.

## Observed IOCs

| type | value | context |
|---|---|---|
| ip:port | 114.134.187.38:8082 | botnet_cc, ThreatFox confidence 100, first seen 2026-07-17 16:05 UTC |
| ip:port | 47.106.110.47:80 | botnet_cc, ThreatFox confidence 75, first seen 2026-07-17 15:47 UTC |
| ip:port | 114.134.187.38:111 | botnet_cc, ThreatFox confidence 100, first seen 2026-07-17 15:05 UTC |
| ip:port | 198.46.175.153:9090 | botnet_cc, ThreatFox confidence 100, first seen 2026-07-17 07:30 UTC |
| ip:port | 8.141.121.30:9999 | botnet_cc, ThreatFox confidence 100, first seen 2026-07-17 07:30 UTC |
| ip:port | 103.43.18.230:80 | botnet_cc, ThreatFox confidence 100, first seen 2026-07-17 07:30 UTC |

## Severity assessment
**high** — Per the rubric, IOC-cluster notes default to medium, but Cobalt Strike is well-established in public reporting as the C2 tool most frequently used by ransomware operators between initial access and ransomware deployment, which applies the rubric's "ransomware-associated family raises severity one step" adjustment. Corroboration is uneven across the cluster: 114.134.187.38 has strong support (ThreatFox confidence 100, VirusTotal 20/91 engines malicious) but weak AbuseIPDB history (9% confidence, 3 reports), while the other five endpoints show only 1-4 VirusTotal malicious detections and 0% AbuseIPDB confidence despite 100% ThreatFox confidence — consistent with freshly stood-up infrastructure rather than long-lived, well-reported C2. No volume or campaign attribution is stated in the source to independently justify "high" on scale alone.

## Confidence notes
The severity bump from the medium default to high rests on Cobalt Strike's general association with ransomware precursor activity, which is well-established public knowledge but is not stated in this source data — that inference, combined with the low corroboration on most of the individual IOCs (near-zero AbuseIPDB history, low VirusTotal detection counts for 5 of 6 endpoints), is why confidence is set to medium and the note is flagged. The ATT&CK mapping to T1071 is derived from Cobalt Strike's known C2 behavior rather than any protocol detail present in the source, and no more specific sub-technique (e.g., T1071.001) is claimed since the source does not confirm the protocol used on each port.
