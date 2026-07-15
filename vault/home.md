---
title: Threat Intel Home
type: dashboard
tags: [dashboard]
updated: 2026-07-15
---

# Threat Intel Dashboard

Auto-generated each pipeline run. Do not hand-edit — see `pipeline/notes.py`.

## Last 7 days

- [[threats/2026-07-15-SonicWall-SMA1000-Appliances-Server-Side-Request-Forgery-(CVE-2026-15409)]] — **high**
- [[threats/2026-07-15-SonicWall-SMA1000-Appliances-Code-Injection-(CVE-2026-15410)]] — **high**
- [[threats/2026-07-15-ScreenConnect-themed-malware-distribution-on-137.184.133.198-—-2-new-IOCs-(URLhaus,-2026-07-15)]] — **medium**
- [[threats/2026-07-15-ScreenConnect-themed-malware-distribution-on-104.131.86.222-—-2-new-IOCs-(URLhaus,-2026-07-15)]] — **medium** ⚑ flagged
- [[threats/2026-07-15-Oracle-E-Business-Suite-Improper-Privilege-Management-Vulnerability-(CVE-2026-46817)]] — **critical**
- [[threats/2026-07-15-KNX-Protocol-Connection-Authorization-Flaw-Lets-Attackers-Purge-and-Lock-Building-Automation-Devices-(CVE-2023-4346)]] — **high**
- [[threats/2026-07-15-iCagenda-Unrestricted-File-Upload-(CVE-2026-48939)]] — **high**
- [[threats/2026-07-15-CVE-2026-56164-—-Microsoft-SharePoint-Server-unauthenticated-privilege-escalation-(KEV)]] — **critical**
- [[threats/2026-07-15-CVE-2026-56155-—-Microsoft-AD-FS-local-privilege-escalation-(KEV)]] — **high**
- [[threats/2026-07-15-Cisco-IOS-12.4-Cross-Site-Request-Forgery-(CVE-2008-4128)]] — **high**
- [[threats/2026-07-15-Balbooa-Forms-Unauthenticated-Arbitrary-File-Upload-(CVE-2026-56291)]] — **critical**
- [[threats/2026-07-15-Agent-Tesla-—-43-new-IOCs-(ThreatFox,-2026-07-15)]] — **medium**
- [[threats/2026-07-15-AdaptixC2-C2-infrastructure-—-7-new-IOCs-(ThreatFox,-2026-07-15)]] — **high** ⚑ flagged

## Review queue

See [[review-queue]] — 2 flagged item(s).

## Stats

| metric | value |
|---|---|
| total threat notes | 13 |
| malware families tracked | 2 |
| ATT&CK techniques seen | 10 |
| last run | 2026-07-15 |

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
