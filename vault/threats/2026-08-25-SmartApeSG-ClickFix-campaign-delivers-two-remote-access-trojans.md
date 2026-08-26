---
title: "SmartApeSG ClickFix campaign delivers two remote access trojans"
type: threat
source: mta
source_url: https://www.malware-traffic-analysis.net/2026/08/21/index.html
date: 2026-08-25
severity: medium
confidence: low
flagged: true
cve: []
family: [SmartApeSG]
attack_techniques: [T1204.004, T1219]
actors: []
tags: [threat, mta, severity/medium]
---

# SmartApeSG ClickFix campaign delivers two remote access trojans

## What it is
A traffic analysis post published on 2026-08-21 documents an infection chain attributed to [[families/SmartApeSG]], a campaign that pushes fake pop-ups on compromised or malicious web pages. The pop-up uses the "ClickFix" trick: it tells the visitor that something is broken (a browser update, a CAPTCHA, a video codec) and instructs them to copy a provided command and run it themselves, which sidesteps the browser's own download protections. In this case the chain ended with two remote access trojans installed on the victim host. A remote access trojan gives an attacker interactive control of the machine — file access, credential theft, and a foothold for follow-on activity such as ransomware.

## Affected products / versions
- Unknown — not stated in source. ClickFix chains generally target Windows desktop users via the browser, but the source data available here names no product or version.

## ATT&CK mapping
- [[techniques/T1204.004]] — User Execution: Malicious Copy and Paste: "ClickFix" is by definition a lure that gets the victim to copy an attacker-supplied command and execute it locally, which is what the source title describes.
- [[techniques/T1219]] — Remote Access Tools: the source states the campaign "leads to two RATs," i.e. remote access tooling is installed for attacker control of the host.

## Observed IOCs
None in source. The ingested item contained only the post title, date, and link — no hashes, domains, IPs, or URLs were included.

## Severity assessment
**medium** — This is an active, real-world infection chain captured in network traffic rather than a theoretical issue, and the payload class (two RATs) means full interactive control of a compromised endpoint, which is a serious outcome. Against the rubric, however, the chain requires significant user interaction: the victim must read the lure, copy the command, and run it, which is the defining precondition of a ClickFix delivery. No vulnerability or CVE is involved and nothing here is KEV-listed, so no severity floor or exploitation-based escalation applies. The source data gives no indication of campaign volume or targeting scale, so the "active, large-scale malware campaign" condition that would justify high cannot be supported. No ransomware association is stated in the source, so the one-step ransomware raise does not apply either. Medium reflects a credible, user-interaction-gated commodity delivery chain; if the underlying post shows high-volume distribution or a ransomware-linked RAT, this should be re-rated to high.

## Confidence notes
Low confidence, flagged. The ingested source contained only a headline and a link — the RSS summary field was empty — so nothing in this note beyond the campaign name (SmartApeSG), the delivery style (ClickFix), and the outcome ("two RATs") comes from the source. Specifically uncertain: the identities of the two RATs are not named and have not been guessed; no IOCs, hashes, domains, or infrastructure are available; no affected platform or software version is stated; no threat actor is attributed. The two ATT&CK mappings are derived from the plain meaning of the words "ClickFix" and "RATs" in the title rather than from observed behavior described in the source, which is a weaker basis than a full technical write-up would provide. The description of how ClickFix lures work is well-established public knowledge about that technique, not a claim about this specific sample. Retrieving and re-enriching from the full post body would materially raise confidence and should be done before this note is cited in a report.
