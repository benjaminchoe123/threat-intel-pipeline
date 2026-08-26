---
title: FAKEUPDATES C2 infrastructure — 1 domain indicator (2026-08-25)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-08-25
severity: high
confidence: medium
flagged: true
cve: []
family: [FAKEUPDATES]
attack_techniques: [T1071.001, T1189, T1204.002]
actors: []
tags: [threat, threatfox, severity/high]
---

# FAKEUPDATES C2 infrastructure — 1 domain indicator (2026-08-25)

## What it is
ThreatFox published one newly observed domain used as command-and-control infrastructure for [[families/FAKEUPDATES]] (widely tracked as SocGholish). FAKEUPDATES is a long-running malware delivery framework that hides behind fake browser or software update prompts on compromised websites: a visitor is told their browser is out of date, downloads the "update," and instead installs a loader that gives the operators a foothold on the machine. Those footholds are routinely sold or handed off to other criminal groups, and FAKEUPDATES infections have repeatedly ended in ransomware. The practical value of this note is the indicator itself — blocking or hunting for the domain below can catch an infection at the point where the victim machine calls home.

## Affected products / versions
Not applicable — this is an infrastructure indicator, not a product vulnerability. FAKEUPDATES delivery targets end-user endpoints via web browsers; the source data does not name any specific product or version.

## ATT&CK mapping
- [[techniques/T1071.001]] — Application Layer Protocol: Web Protocols: the source classifies this indicator as `botnet_cc` and the value is a hostname, so victim implants resolve and contact it over ordinary web traffic for command and control.
- [[techniques/T1189]] — Drive-by Compromise: FAKEUPDATES is delivered through compromised legitimate websites presenting fake update lures. This mapping comes from established public knowledge of the family, not from behavior described in this source record.
- [[techniques/T1204.002]] — User Execution: Malicious File: the fake-update lure requires the victim to run the downloaded payload. As above, this is family-level knowledge rather than something the source record observed.

## Observed IOCs

| type | value | context |
| --- | --- | --- |
| domain | `prime.destroythebrainonline.com` | FAKEUPDATES `botnet_cc`, ThreatFox confidence 100, first seen 2026-08-25 14:18:10 UTC. Reported via https://infosec.exchange/@monitorsg/117156556746728546 |

VirusTotal at time of lookup: 1 malicious / 2 suspicious / 53 harmless / 35 undetected.

## Severity assessment
**high** — Under the rubric, a ThreatFox family-day IOC cluster defaults to medium, and the volume here (a single domain) does not on its own justify more. The ransomware-association adjustment applies and raises it one step: FAKEUPDATES is a well-documented initial-access vector whose infections have repeatedly been handed to ransomware operators, so a live C2 callback for this family is an active-compromise signal rather than routine commodity noise. The indicator is also fresh and reported with maximum source confidence, meaning the infrastructure is likely operational right now. It is not critical: there is no vulnerability, nothing wormable, and no unauthenticated RCE — delivery depends on user interaction with a fake update prompt, which caps the exploitation profile. Low VirusTotal consensus (1 malicious out of ~91 engines) is expected for a same-day indicator and does not lower the rating.

## Confidence notes
Medium, and flagged. What the source directly supports: the domain value, its FAKEUPDATES attribution, its `botnet_cc` role, the first-seen timestamp, and the reporting reference — all of that is taken verbatim from ThreatFox and is not inferred. What is inference beyond the source: the description of FAKEUPDATES' fake-update delivery chain, the ransomware association that drove the severity step-up, and two of the three ATT&CK mappings ([[techniques/T1189]] and [[techniques/T1204.002]]), which are pattern-matched from the family name against public reporting rather than from any behavior recorded here. Only [[techniques/T1071.001]] is defensible from the source record itself. The record contains no payload hashes, no URLs, no victim or campaign details, and no actor attribution, so no actor is named. The low VirusTotal detection count means the domain's maliciousness rests on ThreatFox's single reporter rather than broad independent corroboration.
