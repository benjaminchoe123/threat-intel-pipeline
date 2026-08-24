---
title: "SmartApeSG ClickFix campaign pushes unidentified RAT"
type: threat
source: mta
source_url: https://www.malware-traffic-analysis.net/2026/07/31/index.html
date: 2026-08-04
severity: medium
confidence: low
flagged: true
cve: []
family: [SmartApeSG]
attack_techniques: [T1204, T1059]
actors: []
tags: [threat, mta, severity/medium]
---

# SmartApeSG ClickFix campaign pushes unidentified RAT

## What it is
A malware-traffic-analysis.net traffic capture published 2026-07-31 documents a [[families/SmartApeSG]] campaign using a "ClickFix" lure to deliver a remote access trojan (RAT) that the author did not identify. ClickFix lures show the victim a fake error or verification prompt — a broken-page notice, a "prove you're human" box — and instruct them to copy a supplied command and run it themselves, which sidesteps browser download warnings because the user performs the execution. The end result described in the source is a RAT, meaning hands-on-keyboard access to the affected workstation for whoever operates the campaign. The source for this note is a headline and link only; no packet capture contents, sample hashes, domains, or IP addresses were available at ingestion time.

## Affected products / versions
- Unknown — not stated in source. The delivery method targets end users on Windows workstations rather than a specific vulnerable product.

## ATT&CK mapping
- [[techniques/T1204]] — User Execution: the ClickFix pattern named in the source works by convincing the victim to run an attacker-supplied command themselves.
- [[techniques/T1059]] — Command and Scripting Interpreter: a pasted ClickFix command is executed through a local interpreter, though the source does not state which one.

## Observed IOCs
None in source.

## Severity assessment
**medium** — This is an active campaign delivering a RAT, which on its own would push toward high, but the rubric's preconditions factor caps it here: execution depends on the victim reading the lure, copying a command, and running it, so a single inattentive user is required per infection. The source gives no indication of campaign volume, targeting, or victim count, so the "large-scale campaign" condition for high cannot be evidenced. There is no CVE, no KEV listing, and no exploitation of a software flaw, so none of the escalation conditions apply. The payload is an unidentified RAT rather than a named ransomware-associated family, so the ransomware step-up does not apply either. If follow-up analysis identifies the RAT as a ransomware precursor or shows broad distribution, this rating should be revisited upward.

## Confidence notes
Low confidence, flagged. The source data contained only a title, a link, and a publication date — the `summary` field was empty, and no IOCs, hashes, network artifacts, or payload details were provided. What comes from the source: the campaign name SmartApeSG, the ClickFix delivery method, the fact that the payload is a RAT, and that the RAT is unidentified. Everything else is inference: the description of how ClickFix lures operate is well-established public knowledge about that technique, not something this source stated, and the assumption of Windows workstation targeting is drawn from the campaign name and general ClickFix tradecraft rather than from evidence here. Both ATT&CK mappings are derived from the meaning of "ClickFix" as a named technique rather than from observed behavior in this specific capture; T1059 in particular is mapped without a sub-technique because the interpreter is unknown, and no drive-by or initial-access technique is mapped because the source does not say how victims reached the lure. The malware family list contains SmartApeSG as a campaign identifier; the actual RAT family is deliberately left out rather than guessed. Anyone acting on this note should open the linked write-up for the real IOCs before hunting.
