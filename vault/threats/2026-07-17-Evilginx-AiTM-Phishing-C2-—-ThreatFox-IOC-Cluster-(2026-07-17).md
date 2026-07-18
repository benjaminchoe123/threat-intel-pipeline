---
title: Evilginx AiTM Phishing C2 — ThreatFox IOC Cluster (2026-07-17)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-07-17
severity: medium
confidence: medium
flagged: true
cve: []
family: [Evilginx]
attack_techniques: [T1566, T1557]
actors: []
tags: [threat, threatfox, severity/medium]
---

# Evilginx AiTM Phishing C2 — ThreatFox IOC Cluster (2026-07-17)

## What it is
ThreatFox published one command-and-control indicator for [[families/Evilginx]], an
open-source adversary-in-the-middle (AiTM) phishing toolkit. Evilginx runs as a reverse
proxy that sits between a victim and a real login page, letting an attacker capture
credentials and session cookies in real time — which defeats standard password-based MFA.
The indicator here is a single IP:port reported as command-and-control infrastructure, not
a described phishing campaign, so this note covers infrastructure tracking rather than an
active incident.

## Affected products / versions
Not applicable — this is IOC infrastructure data, not a software vulnerability.

## ATT&CK mapping
- [[techniques/T1566]] — Phishing: Evilginx's core function is credential/session
  harvesting via a reverse-proxied phishing page; this mapping is based on known tool
  behavior, not a delivery method described in this specific source record.
- [[techniques/T1557]] — Adversary-in-the-Middle: the C2 endpoint operates the reverse
  proxy that intercepts the victim-to-service session, the defining mechanism of Evilginx.

## Observed IOCs
| Type | Value | Context |
|------|-------|---------|
| ip:port | 194.32.142.225:3333 | Reported as `botnet_cc` for Evilginx, ThreatFox confidence 75%, first seen 2026-07-16 19:44:38 UTC |

## Severity assessment
**Medium** — This is a single-IOC ThreatFox family-day cluster with no associated campaign
or reference reporting, which per the rubric defaults to medium absent evidence of volume
or a notable campaign. It is not KEV-listed and Evilginx is a phishing/credential-theft
tool rather than ransomware, so neither of the severity-raising context adjustments apply.
Reputation data is mixed but doesn't push this higher: VirusTotal shows only 6 of 91
engines flagging the IP as malicious (2 suspicious, the rest harmless/undetected), and
AbuseIPDB has zero abuse reports in the last 90 days. That thin, inconsistent signal is
consistent with fresh, low-volume C2 infrastructure rather than evidence of a large-scale
active campaign.

## Confidence notes
Confidence is medium, not high. The source record is limited to one infrastructure IOC
with no reference URL and a ThreatFox confidence level of 75% (not maximum); no campaign
description, phishing lure, or targeting detail is provided. The ATT&CK mapping to
Phishing (T1566) and Adversary-in-the-Middle (T1557) is drawn from well-established public
knowledge of how Evilginx operates as a tool, not from behavior described in this specific
source record — flagging this note accordingly, per the low-confidence rule.
