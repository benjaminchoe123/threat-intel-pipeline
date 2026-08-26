---
title: AsyncRAT C2 infrastructure — 3 IP:port indicators (2026-08-25)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-08-25
severity: medium
confidence: medium
flagged: false
cve: []
family: [AsyncRAT]
attack_techniques: [T1071, T1571, T1219]
actors: []
tags: [threat, threatfox, severity/medium]
---

# AsyncRAT C2 infrastructure — 3 IP:port indicators (2026-08-25)

## What it is
ThreatFox published three IP-and-port pairs on 2026-08-25 that act as command-and-control (C2) servers for [[families/AsyncRAT]], a widely used open-source remote access trojan. A C2 server is the machine an infected computer calls home to for instructions, so any internal host connecting to one of these addresses should be treated as compromised. AsyncRAT gives an operator remote control of the victim machine — file access, keystroke capture, screen viewing, and the ability to install further malware. This note is a daily indicator cluster, not a report on a specific intrusion: it tells defenders what to block and hunt for, not who was targeted.

## Affected products / versions
Not applicable — this is an IOC cluster describing attacker infrastructure, not a vulnerability in a product. AsyncRAT targets Windows endpoints generally.

## ATT&CK mapping
- [[techniques/T1071]] — Application Layer Protocol: all three indicators are classified by the source as `botnet_cc`, meaning infected hosts initiate outbound network sessions to these endpoints to receive commands.
- [[techniques/T1571]] — Non-Standard Port: two of the three C2 endpoints listen on 30700/tcp and 8808/tcp, unusual high ports that will not blend with normal web traffic; the third uses 443/tcp, which does blend.
- [[techniques/T1219]] — Remote Access Tools: [[families/AsyncRAT]] is by definition a remote access trojan providing interactive operator control of the victim host. This mapping comes from the family identification, not from behavior observed in this source data.

## Observed IOCs

| type | value | context |
| --- | --- | --- |
| ip:port | 80.190.77.86:30700 | AsyncRAT botnet C2, ThreatFox confidence 100%, first seen 2026-08-25 13:05:08 UTC. VirusTotal: 10 malicious / 1 suspicious. |
| ip:port | 50.116.42.10:8808 | AsyncRAT botnet C2, ThreatFox confidence 100%, first seen 2026-08-25 12:05:05 UTC. VirusTotal: 2 malicious / 1 suspicious. |
| ip:port | 160.25.140.133:443 | AsyncRAT botnet C2, ThreatFox confidence 50%, first seen 2026-08-25 06:48:53 UTC. VirusTotal: 2 malicious / 1 suspicious. |

## Severity assessment
**medium** — This is a routine ThreatFox family-day aggregate, which the rubric defaults to medium unless volume or a named campaign justifies raising it. Three indicators in one day is low volume, and the source supplies no campaign, victim, or targeting context and no reference links. AsyncRAT is commodity malware distributed at scale by many unrelated operators, which fits the "routine commodity-malware distribution" band rather than a large-scale coordinated campaign. Nothing here indicates ransomware association, so no upward adjustment applies. The impact on any single infected host is high — full remote control — but the exposure represented by this note is limited to blocking three C2 endpoints, one of which the source itself only rates 50% confident.

## Confidence notes
The IOC values, ports, timestamps, threat type, and family attribution are taken directly from the source; nothing in the table is inferred. Two points of uncertainty keep this at medium rather than high. First, `160.25.140.133:443` carries a ThreatFox confidence of only 50%, so it may be a false positive or shared infrastructure — treat a hit on it as a lead to investigate rather than proof of infection, and note that port 443 on a shared host is far more likely to be legitimate than the two high ports. Second, the T1219 mapping is derived from what AsyncRAT is as a family, not from behavior described in this source, and T1071/T1571 are derived from the `botnet_cc` classification and the port numbers rather than from observed traffic analysis. Reputation data is weakly corroborating at best: `80.190.77.86` has 10 VirusTotal malicious verdicts, but the other two IPs sit at 2 malicious against ~52 harmless, and AbuseIPDB has zero reports for all three in the last 90 days. That is normal for indicators first seen hours ago and does not indicate the IPs are benign — but it also means only one of the three has independent support.
