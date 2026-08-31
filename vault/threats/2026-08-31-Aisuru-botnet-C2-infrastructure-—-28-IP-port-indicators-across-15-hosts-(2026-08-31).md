---
title: Aisuru botnet C2 infrastructure — 28 IP:port indicators across 15 hosts (2026-08-31)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-08-31
severity: medium
confidence: medium
flagged: true
cve: []
family: [Aisuru]
attack_techniques: [T1071, T1571, T1498]
actors: []
tags: [threat, threatfox, severity/medium]
---

# Aisuru botnet C2 infrastructure — 28 IP:port indicators across 15 hosts (2026-08-31)

## What it is
ThreatFox published 28 command-and-control (C2) indicators tied to the [[families/Aisuru]] botnet in its 2026-08-31 aggregate. A C2 server is the machine an infected device phones home to for instructions, so blocking these addresses cuts the operator's control over any device on our network that is already compromised. The 28 indicators resolve to only 15 distinct IP addresses — several hosts run the C2 service on three or four ports at once — and every submission carries a 100% confidence level from the reporting party. Publicly, [[families/Aisuru]] is described as a Mirai-derived botnet that recruits internet-exposed IoT devices (routers, DVRs, cameras) for large-scale denial-of-service attacks; that characterization comes from open reporting, not from this feed entry.

This cluster is a continuation of, not a first sighting of, this infrastructure: `159.89.24.55` appeared in the [[2026-08-25-Aisuru-botnet-C2-infrastructure-—-4-IP-port-indicators-(2026-08-25)]] cluster on port 9035 and appears here on the adjacent port 9034.

## Affected products / versions
Unknown — not stated in source. The feed provides C2 infrastructure only, with no payload, no victim telemetry, and no indication of which device models or firmware versions the botnet recruits.

## ATT&CK mapping
- [[techniques/T1071]] — Application Layer Protocol: ThreatFox classifies all 28 indicators as `botnet_cc`, meaning infected hosts initiate outbound sessions to these IP:port pairs. The heavy reuse of 8080, 8443, and 8001 across the set is consistent with an HTTP/TLS-style application-layer channel, though the source never states the protocol.
- [[techniques/T1571]] — Non-Standard Port: the C2 listeners sit on 8001 (8 hosts), 8443 (7), 8080 (5), 9034 (5), 34567 (2), and 9035 (1). Aside from 8080/8443, none of these are registered service ports for their likely protocol, and 34567 is conventionally a DVR/NVR management port rather than a server-side C2 port. This mapping rests on the port numbers in the source data itself.
- [[techniques/T1498]] — Network Denial of Service: mapped from public reporting on [[families/Aisuru]] as a DDoS botnet, **not** from anything in this source data. See Confidence notes.

## Observed IOCs

| type | value | context |
| --- | --- | --- |
| ip:port | 167.99.194.254:9034 | Aisuru botnet C2, first seen 2026-08-31 03:49:28 UTC, confidence 100. VT: 3 malicious / 3 suspicious / 52 harmless; AbuseIPDB 28% (4 reports/90d) |
| ip:port | 174.138.30.59:8080 | Aisuru botnet C2, first seen 2026-08-30 23:52:46 UTC, confidence 100. VT: 4 malicious / 1 suspicious / 50 harmless; AbuseIPDB 0% (0 reports/90d) |
| ip:port | 167.99.128.245:8080 | Aisuru botnet C2, first seen 2026-08-30 19:52:17 UTC, confidence 100. VT: 4 malicious / 1 suspicious / 52 harmless; AbuseIPDB 0% (0 reports/90d) |
| ip:port | 104.248.41.207:34567 | Aisuru botnet C2, first seen 2026-08-30 18:55:36 UTC, confidence 100. VT: 6 malicious / 2 suspicious / 52 harmless; AbuseIPDB 0% (0 reports/90d) |
| ip:port | 167.99.128.245:8443 | Aisuru botnet C2, first seen 2026-08-30 17:39:56 UTC, confidence 100 |
| ip:port | 159.89.24.55:9034 | Aisuru botnet C2, first seen 2026-08-30 17:39:55 UTC, confidence 100. Same host seen on port 9035 in the 2026-08-25 cluster |
| ip:port | 46.101.179.59:9034 | Aisuru botnet C2, first seen 2026-08-30 11:55:39 UTC, confidence 100 |
| ip:port | 45.55.191.196:8080 | Aisuru botnet C2, first seen 2026-08-30 10:43:05 UTC, confidence 100 |
| ip:port | 152.42.255.118:8080 | Aisuru botnet C2, first seen 2026-08-30 08:16:51 UTC, confidence 100 |
| ip:port | 134.122.124.236:8001 | Aisuru botnet C2, first seen 2026-08-30 07:09:40 UTC, confidence 100 |
| ip:port | 45.55.191.196:8001 | Aisuru botnet C2, first seen 2026-08-30 07:09:39 UTC, confidence 100 |
| ip:port | 152.42.255.118:8001 | Aisuru botnet C2, first seen 2026-08-30 07:09:39 UTC, confidence 100 |
| ip:port | 167.99.128.245:8001 | Aisuru botnet C2, first seen 2026-08-30 07:09:38 UTC, confidence 100 |
| ip:port | 67.205.132.147:8001 | Aisuru botnet C2, first seen 2026-08-30 07:09:38 UTC, confidence 100 |
| ip:port | 174.138.30.59:8001 | Aisuru botnet C2, first seen 2026-08-30 07:09:37 UTC, confidence 100 |
| ip:port | 165.22.191.159:8001 | Aisuru botnet C2, first seen 2026-08-30 07:09:36 UTC, confidence 100 |
| ip:port | 104.248.27.128:8001 | Aisuru botnet C2, first seen 2026-08-30 07:09:35 UTC, confidence 100 |
| ip:port | 165.22.122.89:9034 | Aisuru botnet C2, first seen 2026-08-30 07:09:35 UTC, confidence 100 |
| ip:port | 165.22.191.159:8443 | Aisuru botnet C2, first seen 2026-08-30 07:09:28 UTC, confidence 100 |
| ip:port | 104.248.247.126:9034 | Aisuru botnet C2, first seen 2026-08-30 07:09:28 UTC, confidence 100 |
| ip:port | 174.138.30.59:8443 | Aisuru botnet C2, first seen 2026-08-30 07:09:27 UTC, confidence 100 |
| ip:port | 167.99.194.254:9035 | Aisuru botnet C2, first seen 2026-08-30 07:09:26 UTC, confidence 100 |
| ip:port | 104.248.27.128:8443 | Aisuru botnet C2, first seen 2026-08-30 07:09:26 UTC, confidence 100 |
| ip:port | 67.205.132.147:8443 | Aisuru botnet C2, first seen 2026-08-30 07:09:26 UTC, confidence 100 |
| ip:port | 134.122.124.236:8443 | Aisuru botnet C2, first seen 2026-08-30 07:09:25 UTC, confidence 100 |
| ip:port | 167.99.128.245:34567 | Aisuru botnet C2, first seen 2026-08-30 07:09:24 UTC, confidence 100 |
| ip:port | 152.42.255.118:8443 | Aisuru botnet C2, first seen 2026-08-30 07:09:21 UTC, confidence 100 |
| ip:port | 159.65.50.202:8080 | Aisuru botnet C2, first seen 2026-08-30 07:09:21 UTC, confidence 100 |

Reputation lookups were run against 4 of the 15 distinct addresses; the other 11 were not sampled and have no third-party verdict recorded here. No references, hashes, or payload URLs were included with any of the 28 submissions.

Two structural observations from the timestamps and addresses. First, 19 of the 28 indicators carry first-seen stamps inside a 19-second window (2026-08-30 07:09:21–07:09:40 UTC). Second, the 15 addresses fall into a narrow set of prefixes — 167.99/16, 104.248/16, 165.22/16, 159.89/16, 159.65/16, 152.42/16, 174.138/16, 134.122/16, 46.101/16, 45.55/16, 67.205/18 — all of which are, to public knowledge, allocated to a single large VPS provider. Only one indicator (`167.99.194.254:9034`) was first seen on the 2026-08-31 aggregation day itself; the remaining 27 are stamped 2026-08-30.

## Severity assessment
**medium** — The rubric defaults ThreatFox family-day IOC clusters to medium unless volume or an associated campaign justifies high, and neither factor holds up on inspection here. Volume looks like a sevenfold jump over the 4-indicator 2026-08-25 cluster, but 19 of the 28 indicators share a 19-second first-seen window, which is far more consistent with one bulk submission or a single scanning sweep than with 19 servers being provisioned in 19 seconds — so the apparent surge is at least partly a reporting artifact and cannot carry an escalation on its own. Deduplicated, the cluster is 15 hosts, not 28. None of the critical/high factors apply: there is no CVE, no described exploitation activity, no wormable or unauthenticated-RCE component in the source, and nothing indicating targeting of our environment. Reputation data argues against escalation too — the four sampled addresses show only 3–6 malicious engines against ~50 harmless verdicts, and AbuseIPDB abuse confidence is 0% on three of four (the fourth, `167.99.194.254`, at 28% with 4 reports, is the only address with meaningful independent corroboration). [[families/Aisuru]] is not ransomware-associated, so the one-step raise does not apply. The practical exposure is to internet-facing IoT and edge devices, which is real but bounded for most enterprise networks; the defensive value of this note is the blocklist, not the rating.

## Confidence notes
Confidence is medium and this note is flagged. What the source directly supports: the 28 IP:port values, their `botnet_cc` threat type, the first-seen timestamps, the 100% submitter confidence, and the family label "Aisuru" — the port and host tallies in this note are arithmetic on those values and nothing more.

Everything else is inference, specifically:

- The description of Aisuru as a Mirai-derived IoT botnet used for DDoS, and the [[techniques/T1498]] mapping that follows from it, are pattern-matched from the family name against public reporting. The source contains no payload, no victim device information, and no observed attack traffic to confirm it. Per the low-confidence rule, this alone caps confidence at medium.
- The claim that all 15 addresses sit in one VPS provider's ranges comes from public IP-allocation knowledge, not from the source data, and was not verified against WHOIS during enrichment. It is stated as an observation, not a finding, and no ATT&CK infrastructure-acquisition technique was mapped from it — that mapping would be inference stacked on inference.
- The reading of the 07:09 timestamp burst as a bulk submission rather than a real deployment burst is an interpretation. ThreatFox `first_seen` does not distinguish the two, and the severity rating above depends on that interpretation; if these were in fact 19 hosts stood up simultaneously, a case for high could be made.
- [[techniques/T1071]] and [[techniques/T1571]] are the better-supported mappings, since `botnet_cc` implies an outbound C2 channel and the port numbers are in the source. Even so, the actual application-layer protocol on 8001/8443/9034/9035/34567 is not stated and was not verified.
- Reputation coverage is partial: 4 of 15 addresses were sampled, so the note cannot characterize the reputation of the cluster as a whole. Low VirusTotal and AbuseIPDB scores do not clear an address — freshly provisioned cloud hosts routinely score clean — but the tension between the submitter's 100% confidence and near-zero independent reporting is unresolved.
