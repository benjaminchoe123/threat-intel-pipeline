---
title: Threat Intel Home
type: dashboard
tags: [dashboard]
updated: 2026-08-23
---

# Threat Intel Dashboard

> **Pipeline health: OK** — newest threat note 2026-08-23.

Auto-generated each pipeline run. Do not hand-edit — see `pipeline/notes.py`.

## Last 7 days

- [[threats/2026-08-23-Zimbra-Collaboration-Suite-(ZCS)-OS-Command-Injection-(CVE-2026-73570)]] — **critical**
- [[threats/2026-08-23-TrueConf-Server-Code-Injection-(CVE-2026-72530)]] — **high** ⚑ flagged

## Review queue

See [[review-queue]] — 26 flagged item(s).

## Stats

| metric | value |
|---|---|
| total threat notes | 59 |
| malware families tracked | 22 |
| ATT&CK techniques seen | 35 |
| last run | 2026-08-23 |

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
