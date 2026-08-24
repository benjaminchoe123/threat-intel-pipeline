---
title: AdaptixC2 C2 Infrastructure — ThreatFox Daily IOC Cluster (2026-08-04)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-08-04
severity: high
confidence: medium
flagged: true
cve: []
family: [AdaptixC2]
attack_techniques: [T1071.001, T1571]
actors: []
tags: [threat, threatfox, severity/high]
---

# AdaptixC2 C2 Infrastructure — ThreatFox Daily IOC Cluster (2026-08-04)

## What it is
ThreatFox published seven new command-and-control indicators for [[families/AdaptixC2]] on 2026-08-04. AdaptixC2 is a post-exploitation and command-and-control framework — the software an intruder installs on a machine they have already broken into so they can keep control of it, run commands, and move deeper into the network. Each indicator is an IP address and port pair that a compromised machine would call home to. Outbound traffic from an internal host to any of these addresses should be treated as a probable active intrusion, not as routine malware noise.

## Affected products / versions
Not applicable — this is a C2 infrastructure indicator cluster, not a product vulnerability.

## ATT&CK mapping
- [[techniques/T1071.001]] — Application Layer Protocol: Web Protocols: four of the seven listeners sit on 80, 443, 8080, and 8443, the standard web ports used to blend C2 traffic in with normal browsing.
- [[techniques/T1571]] — Non-Standard Port: three listeners use 65432 and 4321, ports with no legitimate common service, which is a direct observation from the source data.

## Observed IOCs

| type | value | context |
|---|---|---|
| ip:port | 89.36.231.206:65432 | botnet_cc, ThreatFox confidence 75, first seen 2026-08-04 09:46 UTC; VT 3 malicious, AbuseIPDB 0% |
| ip:port | 45.139.226.224:4321 | botnet_cc, ThreatFox confidence 75, first seen 2026-08-04 09:45 UTC; VT 3 malicious, AbuseIPDB 0% |
| ip:port | 138.124.62.3:4321 | botnet_cc, ThreatFox confidence 75, first seen 2026-08-04 09:43 UTC; VT 2 malicious, AbuseIPDB 0% |
| ip:port | 89.124.104.192:8443 | botnet_cc, ThreatFox confidence 100, first seen 2026-08-04 02:05 UTC; VT 9 malicious / 4 suspicious, AbuseIPDB 100% (141 reports) |
| ip:port | 47.93.42.22:8080 | botnet_cc, ThreatFox confidence 100, first seen 2026-08-04 00:05 UTC; no reputation lookup in sample |
| ip:port | 47.93.42.22:443 | botnet_cc, ThreatFox confidence 100, first seen 2026-08-03 22:05 UTC; same host as above |
| ip:port | 47.93.42.22:80 | botnet_cc, ThreatFox confidence 100, first seen 2026-08-03 22:05 UTC; same host as above |

Note: 47.93.42.22 accounts for three of the seven indicators, listening on 80, 443, and 8080 — a single multi-port C2 host rather than three separate ones. Five distinct IPs are represented overall.

## Severity assessment
**high** — The rubric floors IOC-cluster notes at medium, and the volume here (7 indicators across 5 IPs, one of them a single multi-port host) is routine daily traffic that does not on its own justify a step up. The step to high comes from the ransomware-association adjustment: AdaptixC2 is publicly documented as a framework adopted by ransomware affiliates for hands-on-keyboard intrusion, so a live beacon to this infrastructure implies an operator already inside a network rather than commodity malware being sprayed at it. Corroboration is uneven but real: 89.124.104.192 carries 9 VirusTotal malicious verdicts and a 100% AbuseIPDB score across 141 reports in 90 days, which independently confirms at least one node as hostile. The other three sampled IPs show only 2–3 VirusTotal malicious verdicts and no AbuseIPDB reports, consistent with freshly stood-up infrastructure that detection vendors have not caught up to. Scope is limited to blocking and hunting for these five addresses, which is why this does not reach critical.

## Confidence notes
The IOC values, ports, threat type, timestamps, and ThreatFox confidence levels are taken directly from the source data and are not in doubt. Two things are inference beyond the source and drive the medium rating and the flag. First, the ransomware association that raised severity from medium to high comes from public reporting on AdaptixC2, not from anything in this feed record — none of the seven entries carries a reference URL, a campaign name, or a victim, so these specific IPs are not tied to a ransomware intrusion by evidence in hand. Second, the ATT&CK mappings are derived from the observed port numbers rather than from observed protocol behavior; the source states `botnet_cc` and a port, so T1071.001 and T1571 are reasonable but not confirmed by traffic analysis. No actor is named because the source supports none, and no encrypted-channel technique was mapped because port 443/8443 alone does not prove TLS was used. Reputation data was available for only four of the five distinct IPs — 47.93.42.22, the multi-port host, was not sampled.
