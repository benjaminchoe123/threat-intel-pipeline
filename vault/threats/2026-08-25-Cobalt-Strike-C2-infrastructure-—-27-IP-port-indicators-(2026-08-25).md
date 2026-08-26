---
title: Cobalt Strike C2 infrastructure — 27 IP:port indicators (2026-08-25)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-08-25
severity: high
confidence: medium
flagged: true
cve: []
family: [Cobalt Strike]
attack_techniques: [T1071.001, T1573.002, T1583.003]
actors: []
tags: [threat, threatfox, severity/high]
---

# Cobalt Strike C2 infrastructure — 27 IP:port indicators (2026-08-25)

## What it is
ThreatFox published 27 command-and-control indicators for [[families/Cobalt Strike]] first seen on 24–25 August 2026. Cobalt Strike is a commercial red-team tool whose cracked versions are one of the most widely abused intrusion frameworks in the world — attackers install its "Beacon" implant on a compromised machine and use it to run commands, steal credentials, and move to other systems, frequently as the staging step before ransomware is deployed. Each indicator is a server address and port that a Beacon implant calls home to, so any internal host connecting to one of these addresses should be treated as compromised. The indicators span 12 distinct IP addresses, most of them exposing several ports on the same host.

## Affected products / versions
Not applicable — this is a C2 infrastructure indicator cluster, not a product vulnerability. Any Windows, Linux, or macOS host reachable by an operator can run a Beacon payload.

## ATT&CK mapping
- [[techniques/T1071.001]] — Application Layer Protocol: Web Protocols: 13 of the 27 indicators use plain HTTP ports (80, 81, 8000, 8080, 8082), consistent with Beacon HTTP C2 channels blending into normal web traffic.
- [[techniques/T1573.002]] — Encrypted Channel: Asymmetric Cryptography: 9 indicators use TLS-typical or TLS-alternate ports (443, 2083, 4433, 7791, 10443), consistent with Beacon HTTPS C2 over an encrypted channel.
- [[techniques/T1583.003]] — Acquire Infrastructure: Virtual Private Server: the operators are running listeners on dedicated internet-facing hosts across multiple providers, which ThreatFox classifies as `botnet_cc` infrastructure rather than compromised victim endpoints.

## Observed IOCs

| type | value | context |
|---|---|---|
| ip:port | 38.147.185.54:10443 | botnet_cc, ThreatFox confidence 75, first seen 2026-08-25 15:16 UTC |
| ip:port | 177.3.89.54:22 | botnet_cc, confidence 100, first seen 2026-08-25 15:05 UTC |
| ip:port | 177.3.89.54:8080 | botnet_cc, confidence 100, first seen 2026-08-25 15:05 UTC |
| ip:port | 177.3.89.54:80 | botnet_cc, confidence 100, first seen 2026-08-25 14:05 UTC |
| ip:port | 177.3.89.54:443 | botnet_cc, confidence 100, first seen 2026-08-25 14:05 UTC |
| ip:port | 182.92.78.7:80 | botnet_cc, confidence 100, first seen 2026-08-25 13:05 UTC |
| ip:port | 182.92.78.7:443 | botnet_cc, confidence 100, first seen 2026-08-25 12:05 UTC |
| ip:port | 182.92.78.7:8080 | botnet_cc, confidence 100, first seen 2026-08-25 12:05 UTC |
| ip:port | 182.92.78.7:5555 | botnet_cc, confidence 100, first seen 2026-08-25 08:51 UTC |
| ip:port | 43.143.13.146:8080 | botnet_cc, confidence 100, first seen 2026-08-25 11:05 UTC |
| ip:port | 43.143.13.146:22 | botnet_cc, confidence 100, first seen 2026-08-25 10:05 UTC |
| ip:port | 43.143.13.146:8082 | botnet_cc, confidence 100, first seen 2026-08-25 10:05 UTC |
| ip:port | 43.143.13.146:80 | botnet_cc, confidence 100, first seen 2026-08-25 09:05 UTC |
| ip:port | 43.143.13.146:443 | botnet_cc, confidence 100, first seen 2026-08-25 09:05 UTC |
| ip:port | 149.88.66.234:7791 | botnet_cc, confidence 100, first seen 2026-08-25 09:05 UTC |
| ip:port | 121.4.38.18:443 | botnet_cc, confidence 100, first seen 2026-08-25 08:52 UTC |
| ip:port | 118.24.172.48:81 | botnet_cc, confidence 100, first seen 2026-08-25 08:51 UTC |
| ip:port | 47.96.123.205:8000 | botnet_cc, confidence 100, first seen 2026-08-25 08:51 UTC |
| ip:port | 91.92.240.88:443 | botnet_cc, confidence 100, first seen 2026-08-25 08:05 UTC |
| ip:port | 91.92.240.88:22 | botnet_cc, confidence 100, first seen 2026-08-25 07:05 UTC |
| ip:port | 91.92.240.88:8080 | botnet_cc, confidence 100, first seen 2026-08-25 07:05 UTC |
| ip:port | 91.92.240.88:80 | botnet_cc, confidence 100, first seen 2026-08-25 06:05 UTC |
| ip:port | 64.83.24.34:8080 | botnet_cc, confidence 100, first seen 2026-08-24 19:05 UTC |
| ip:port | 64.83.24.34:80 | botnet_cc, confidence 100, first seen 2026-08-24 19:05 UTC |
| ip:port | 64.83.24.34:443 | botnet_cc, confidence 100, first seen 2026-08-24 19:05 UTC |
| ip:port | 207.57.123.57:2083 | botnet_cc, confidence 75, first seen 2026-08-24 18:19 UTC |
| ip:port | 175.27.214.144:4433 | botnet_cc, confidence 75, first seen 2026-08-24 17:39 UTC |

## Severity assessment
**high** — IOC-cluster notes default to medium under the rubric, but two factors raise this one step. First, [[families/Cobalt Strike]] is routinely the hands-on-keyboard stage of ransomware intrusions, and the rubric raises a ransomware-associated family one step. Second, the volume and freshness support an active campaign rather than routine commodity distribution: 27 live listeners across 12 hosts, 24 of them carrying ThreatFox confidence 100, all first observed inside a 24-hour window. This is not critical: there is no CVE, no exploitation of a specific product, and nothing wormable — the indicators only matter to an organisation that already has a foothold problem or is about to. Reputation data argues mildly against a higher rating, since the four sampled IPs draw only 1–3 malicious VirusTotal verdicts each and zero AbuseIPDB reports in 90 days, which is typical for freshly stood-up C2 that scanners have not caught up with but does mean no independent corroboration yet.

## Confidence notes
Medium, and flagged. What the source actually contains is a list of IP:port pairs, a `botnet_cc` threat type, ThreatFox confidence scores, and timestamps — nothing about victims, delivery, targeting, or an operator. Everything beyond that is inference:

- The ATT&CK mappings are derived from the port profile plus well-established public knowledge of how Cobalt Strike Beacon communicates, not from any described behaviour in the source. The HTTP/HTTPS split ([[techniques/T1071.001]], [[techniques/T1573.002]]) is a reasonable read of ports 80/8080/8000/81 versus 443/4433/10443/2083/7791, but the source does not confirm the protocol on any port.
- The ransomware association that drove the severity step-up is family-level background knowledge, not evidence from this data. No ransomware family, intrusion, or campaign is named in the source.
- Three indicators are on port 22 (177.3.89.54, 43.143.13.146, 91.92.240.88). This is ambiguous: it may reflect Cobalt Strike's SSH beacon, or simply an SSH management service on the same team-server host that the collector fingerprinted alongside the real listener. It is not mapped to a technique for that reason, and port 22 hits alone are weak detection evidence.
- No actors are listed because the source names none, and cracked Cobalt Strike is shared across too many unrelated operators to attribute from infrastructure alone.
- The three confidence-75 indicators (38.147.185.54:10443, 207.57.123.57:2083, 175.27.214.144:4433) carry empty reference fields and should be treated as lower-grade than the rest. VirusTotal and AbuseIPDB were checked for only four of the twelve IPs; the remaining eight are unvalidated by any second source.
