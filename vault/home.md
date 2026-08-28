---
title: Threat Intel Home
type: dashboard
tags: [dashboard]
updated: 2026-08-27
---

# Threat Intel Dashboard

> **⚠ Pipeline health: DEGRADED** as of 2026-08-27 — newest threat note is 2026-08-27 (0 days old, threshold 3); a run started 2026-08-27T15:49:03.650648+00:00 and never finished; last run 2026-08-25T17:00:19.777652+00:00.
>
> A run was killed partway. Its unfinished items carry over to the next
> run — only `written` marks an item seen — so the usual fix is to let
> the next scheduled run pick them up rather than re-running by hand.

Auto-generated each pipeline run. Do not hand-edit — see `pipeline/notes.py`.

## Last 7 days

- [[threats/2026-08-27-CVE-2021-23758-—-Ajax.NET-Professional-Deserialization-of-Untrusted-Data-(KEV)]] — **high** ⚑ flagged
- [[threats/2026-08-27-CVE-2015-3246-—-Red-Hat-Libuser-Race-Condition-Vulnerability-(KEV)]] — **high**
- [[threats/2026-08-26-CVE-2026-60004-—-Gitea-diffpatch-Code-Injection-Allows-Git-Hook-Command-Execution]] — **high**
- [[threats/2026-08-25-SmartApeSG-ClickFix-campaign-delivers-two-remote-access-trojans]] — **medium** ⚑ flagged
- [[threats/2026-08-25-FAKEUPDATES-C2-infrastructure-—-1-domain-indicator-(2026-08-25)]] — **high** ⚑ flagged
- [[threats/2026-08-25-DCRat-C2-infrastructure-—-1-IP-port-indicator-(2026-08-25)]] — **medium** ⚑ flagged
- [[threats/2026-08-25-DarkComet-C2-infrastructure-—-1-IP-port-indicator-(2026-08-25)]] — **medium** ⚑ flagged
- [[threats/2026-08-25-CVE-2026-72529-—-TrueConf-Server-Missing-Authentication-for-Critical-Function]] — **critical** ⚑ flagged
- [[threats/2026-08-25-CVE-2026-65400-—-Apple-macOS-Improper-Authentication-in-Screen-Sharing]] — **critical**
- [[threats/2026-08-25-CVE-2026-64849-—-MLflow-Server-Side-Request-Forgery]] — **high**
- [[threats/2026-08-25-CVE-2026-59310-—-Broadcom-VMware-vCenter-Path-Traversal-Leading-to-Remote-Code-Execution]] — **critical**
- [[threats/2026-08-25-CVE-2026-55040-—-Microsoft-SharePoint-Weak-Authentication-Vulnerability]] — **critical** ⚑ flagged
- [[threats/2026-08-25-CVE-2026-33824-—-Microsoft-IKE-Service-Extensions-Double-Free-Remote-Code-Execution]] — **critical** ⚑ flagged
- [[threats/2026-08-25-CVE-2026-21962-—-Oracle-HTTP-Server-and-WebLogic-Server-Proxy-Plug-in-Improper-Access-Control]] — **critical** ⚑ flagged
- [[threats/2026-08-25-Cobalt-Strike-C2-infrastructure-—-27-IP-port-indicators-(2026-08-25)]] — **high** ⚑ flagged
- [[threats/2026-08-25-ClearFake-payload-delivery-infrastructure-—-121-IOCs-(2026-08-25)]] — **high** ⚑ flagged
- [[threats/2026-08-25-AsyncRAT-C2-infrastructure-—-3-IP-port-indicators-(2026-08-25)]] — **medium**
- [[threats/2026-08-25-Aisuru-botnet-C2-infrastructure-—-4-IP-port-indicators-(2026-08-25)]] — **medium** ⚑ flagged
- [[threats/2026-08-23-Zimbra-Collaboration-Suite-(ZCS)-OS-Command-Injection-(CVE-2026-73570)]] — **critical**
- [[threats/2026-08-23-TrueConf-Server-Code-Injection-(CVE-2026-72530)]] — **high** ⚑ flagged

## Review queue

See [[review-queue]] — 38 flagged item(s).

## Stats

| metric | value |
|---|---|
| total threat notes | 77 |
| malware families tracked | 23 |
| ATT&CK techniques seen | 43 |
| last run | 2026-08-27 |

## Live queries

*(These need the [Dataview](https://github.com/blacksmithgu/obsidian-dataview)
community plugin: Settings → Community plugins → Browse → "Dataview" → Install →
Enable. Until then they show as code blocks.)*

### Everything by severity

```dataview
TABLE severity, confidence, choice(flagged, "yes", "no") AS flagged, date
FROM "threats"
SORT choice(severity = "critical", 0, choice(severity = "high", 1,
     choice(severity = "medium", 2, 3))) ASC, date DESC
```

### Needs review (low confidence or flagged)

```dataview
TABLE severity, confidence, date
FROM "threats"
WHERE flagged = true OR confidence = "low"
SORT date DESC
```

### High and critical in the last 30 days

```dataview
TABLE severity, family, cve, date
FROM "threats"
WHERE (severity = "high" OR severity = "critical")
  AND date >= date(today) - dur(30 days)
SORT date DESC
```

### Most-seen ATT&CK techniques

```dataview
TABLE length(rows) AS notes
FROM "threats"
FLATTEN attack_techniques AS technique
GROUP BY technique
SORT length(rows) DESC
```

### Malware families seen

```dataview
TABLE length(rows) AS notes, min(rows.date) AS "first seen"
FROM "threats"
FLATTEN family AS fam
GROUP BY fam
SORT length(rows) DESC
```
