---
title: FAKEUPDATES (SocGholish) Botnet C2 & Payload Delivery IOC Cluster — ThreatFox Daily Cluster (2026-07-17)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-07-17
severity: high
confidence: medium
flagged: true
cve: []
family: [FAKEUPDATES]
attack_techniques: [T1189, T1204.002, T1071.001]
actors: []
tags: [threat, threatfox, severity/high]
---

# FAKEUPDATES (SocGholish) Botnet C2 & Payload Delivery IOC Cluster — ThreatFox Daily Cluster (2026-07-17)

## What it is

This is a daily cluster of two indicators that ThreatFox tied to [[families/FAKEUPDATES]], better known publicly as SocGholish. FAKEUPDATES is a long-running JavaScript-based malware family that compromises legitimate websites and injects fake "your browser is out of date" prompts, tricking visitors into downloading and running what they think is a browser update. In reality it stages further malware on the victim's machine. It matters because it is one of the most widely used initial-access mechanisms in commodity crimeware, and infections have historically been followed by hands-on-keyboard access and ransomware deployment.

## Affected products / versions

Not applicable — this is a web-based social-engineering delivery mechanism, not a software vulnerability.

## ATT&CK mapping

- [[techniques/T1189]] — Drive-by Compromise: FAKEUPDATES' signature method is injecting fake update lures into compromised, otherwise-legitimate websites that visitors browse to normally.
- [[techniques/T1204.002]] — User Execution: Malicious File: the fake "update" is a file the victim is induced to download and run manually, consistent with the payload-delivery IOC in this cluster.
- [[techniques/T1071.001]] — Application Layer Protocol: Web Protocols: the botnet C2 indicator is a domain used for web-based command-and-control communication.

## Observed IOCs

| Type   | Value                                              | Context                                                                 |
|--------|-----------------------------------------------------|--------------------------------------------------------------------------|
| domain | up-to-date.paquetesparaorlando.com                 | botnet_cc, ThreatFox confidence 100, first seen 2026-07-17 14:09:56 UTC |
| url    | https://content-website-analytics.com/script.js    | payload_delivery, ThreatFox confidence 75, first seen 2026-07-17 06:36:21 UTC |

## Severity assessment

**high** — Per the rubric, ThreatFox family-day IOC clusters default to medium unless volume or an associated campaign justifies raising it. FAKEUPDATES/SocGholish is a well-documented, large-scale, ongoing campaign, and campaigns of this type are treated as ransomware-associated (SocGholish infections have repeatedly served as the entry point for hands-on-keyboard intrusions and ransomware deployment), which raises the rating one step per the rubric's context adjustments. This is not an actively-exploited CVE, so the KEV/critical floor does not apply. Reputation data reinforces the delivery IOC: the payload URL shows 18 malicious / 1 suspicious vendor verdicts on VirusTotal, a strong signal of active malicious use rather than a fresh, unconfirmed indicator. The C2 domain shows only 1 malicious / 2 suspicious verdicts against 52 harmless, which is weaker corroboration on its own but is expected for a newly-registered C2 host with low visibility.

## Confidence notes

Confidence is medium, and this note is flagged. The two IOCs and their ThreatFox metadata (type, confidence level, first-seen timestamps) are directly from the source. However, the description of FAKEUPDATES' behavior (fake browser-update lures via compromised sites, and its association with follow-on ransomware) is drawn from well-established public reporting on the family, not from anything stated in this specific source payload — the JSON gives only the family name and two IOCs. The ATT&CK mappings are likewise based on the family's known general behavior rather than confirmed specifics of this cluster, so they should be read as pattern-matched on the family name rather than verified against this particular activity.
