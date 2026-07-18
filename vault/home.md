---
title: Threat Intel Home
type: dashboard
tags: [dashboard]
updated: 2026-07-17
---

# Threat Intel Dashboard

Auto-generated each pipeline run. Do not hand-edit — see `pipeline/notes.py`.

## Last 7 days

- [[threats/2026-07-17-Microsoft-SharePoint-Deserialization-Vulnerability-Actively-Exploited-(CVE-2026-58644)]] — **critical**
- [[threats/2026-07-17-Havoc-C2-Infrastructure-—-ThreatFox-Daily-IOC-Cluster-(2026-07-17)]] — **high** ⚑ flagged
- [[threats/2026-07-17-Ghost-RAT-Payload-IOC-—-ThreatFox-Daily-Cluster-(2026-07-17)]] — **medium** ⚑ flagged
- [[threats/2026-07-17-Fortinet-FortiSandbox-OS-Command-Injection-Vulnerability-(CVE-2026-39808)]] — **critical**
- [[threats/2026-07-17-FAKEUPDATES-(SocGholish)-Botnet-C2-&-Payload-Delivery-IOC-Cluster-—-ThreatFox-Daily-Cluster-(2026-07-17)]] — **high** ⚑ flagged
- [[threats/2026-07-17-Evilginx-AiTM-Phishing-C2-—-ThreatFox-IOC-Cluster-(2026-07-17)]] — **medium** ⚑ flagged
- [[threats/2026-07-17-DCRat-Botnet-C2-IOC-—-ThreatFox-Daily-Cluster-(2026-07-17)]] — **medium** ⚑ flagged
- [[threats/2026-07-17-DarkTortilla-Payload-IOC-—-ThreatFox-Daily-Cluster-(2026-07-17)]] — **medium** ⚑ flagged
- [[threats/2026-07-17-Cobalt-Strike-C2-Infrastructure-—-ThreatFox-Daily-IOC-Cluster-(2026-07-17)]] — **high** ⚑ flagged
- [[threats/2026-07-17-ClearFake-Payload-Delivery-Domain-Cluster-—-ThreatFox-Daily-IOC-Cluster-(2026-07-17)]] — **high** ⚑ flagged
- [[threats/2026-07-17-AsyncRAT-Botnet-C2-IOC-—-ThreatFox-Daily-Cluster-(2026-07-17)]] — **medium**
- [[threats/2026-07-17-Aisuru-Botnet-C2-IOC-—-ThreatFox-Daily-Cluster-(2026-07-17)]] — **medium** ⚑ flagged
- [[threats/2026-07-17-AdaptixC2-C2-Infrastructure-—-ThreatFox-Daily-IOC-Cluster-(2026-07-17)]] — **high** ⚑ flagged
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

See [[review-queue]] — 12 flagged item(s).

## Stats

| metric | value |
|---|---|
| total threat notes | 26 |
| malware families tracked | 12 |
| ATT&CK techniques seen | 18 |
| last run | 2026-07-17 |

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
