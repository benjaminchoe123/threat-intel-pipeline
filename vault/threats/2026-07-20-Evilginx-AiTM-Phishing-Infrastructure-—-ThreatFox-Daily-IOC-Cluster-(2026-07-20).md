---
title: Evilginx AiTM Phishing Infrastructure — ThreatFox Daily IOC Cluster (2026-07-20)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-07-20
severity: medium
confidence: medium
flagged: false
cve: []
family: [Evilginx]
attack_techniques: [T1557, T1566.002, T1539]
actors: []
tags: [threat, threatfox, severity/medium]
---

# Evilginx AiTM Phishing Infrastructure — ThreatFox Daily IOC Cluster (2026-07-20)

## What it is
ThreatFox reported six new server IOCs tagged as [[families/Evilginx]] infrastructure over 2026-07-19 and 2026-07-20. Evilginx is a widely used open-source adversary-in-the-middle (AiTM) phishing framework: it sits between a victim and a real login page, relaying traffic so it can capture credentials and session cookies — which lets attackers bypass most forms of multi-factor authentication. These IPs are the attacker-controlled servers that host the fake login proxies and their control panels, so traffic from your network to them likely means a user clicked a phishing link.

## Affected products / versions
Not applicable — this is an IOC cluster for attacker infrastructure, not a product vulnerability. Any organization whose users' credentials are phished (commonly Microsoft 365 and Google Workspace logins) is a potential target.

## ATT&CK mapping
- [[techniques/T1557]] — Adversary-in-the-Middle: Evilginx's core function is proxying victim sessions to a legitimate login service while intercepting the traffic.
- [[techniques/T1566.002]] — Phishing: Spearphishing Link: Evilginx lures are delivered as links to the attacker-hosted proxy pages served from infrastructure like these IPs.
- [[techniques/T1539]] — Steal Web Session Cookie: capturing the authenticated session cookie to bypass MFA is the framework's primary payoff.

## Observed IOCs
| type | value | context |
|------|-------|---------|
| ip:port | 185.212.131.28:9000 | ThreatFox botnet_cc, confidence 75, first seen 2026-07-20 09:44:09 UTC |
| ip:port | 185.212.128.155:9000 | ThreatFox botnet_cc, confidence 75, first seen 2026-07-20 09:44:07 UTC |
| ip:port | 169.58.12.228:443 | ThreatFox botnet_cc, confidence 75, first seen 2026-07-20 09:43:51 UTC |
| ip:port | 213.160.77.221:443 | ThreatFox botnet_cc, confidence 75, first seen 2026-07-19 19:44:23 UTC |
| ip:port | 159.65.232.209:8080 | ThreatFox botnet_cc, confidence 75, first seen 2026-07-19 19:43:41 UTC |
| ip:port | 157.230.235.215:8080 | ThreatFox botnet_cc, confidence 75, first seen 2026-07-19 19:43:40 UTC |

## Severity assessment
**medium** — Per the rubric, IOC-cluster notes from ThreatFox daily aggregates default to medium unless volume or an associated campaign justifies high. This cluster is small (6 IOCs) and the source provides no campaign context, victim targeting, or link to a ransomware-associated operation, so no upward adjustment applies. Evilginx itself is a serious capability — AiTM credential and session theft defeats most MFA — but this note documents fresh infrastructure sightings, not evidence of a large-scale active campaign. Reputation data is consistent with early-stage malicious infrastructure: modest VirusTotal detections (2–7 engines flagging each sampled IP) and zero AbuseIPDB reports, typical for indicators first seen within the last 48 hours. Block or alert on these IPs; escalate if outbound hits are observed, since a hit implies a user reached a live credential-phishing proxy.

## Confidence notes
The IOC values, ports, timestamps, and the Evilginx family attribution come directly from the ThreatFox source data, which rates each indicator at 75% confidence with no supporting reference URLs. The description of Evilginx as an AiTM phishing framework and all three ATT&CK mappings are based on well-established public knowledge of the family, not on behavior described in the source — the source only provides the family name and a generic `botnet_cc` threat type (a ThreatFox labeling convention; Evilginx servers are phishing proxies rather than botnet controllers in the traditional sense). Reputation corroboration is partial: several VirusTotal engines flag the sampled IPs, but AbuseIPDB shows no reports, so confidence is medium rather than high.
