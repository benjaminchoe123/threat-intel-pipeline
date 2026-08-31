---
title: Threat Intel Home
type: dashboard
tags: [dashboard]
updated: 2026-08-31
---

# Threat Intel Dashboard

> **Pipeline health: OK** as of 2026-08-31 — newest threat note 2026-08-31.

Auto-generated each pipeline run. Do not hand-edit — see `pipeline/notes.py`.

## Last 7 days

- [[threats/2026-08-31-CVE-2026-8452-—-Citrix-NetScaler-ADC-and-Gateway-memory-buffer-flaw-causes-denial-of-service-(CISA-KEV)]] — **high** ⚑ flagged
- [[threats/2026-08-31-CVE-2026-66384-—-JFrog-Artifactory-path-traversal-allows-writes-outside-the-Docker-cache-directory-(CISA-KEV)]] — **high** ⚑ flagged
- [[threats/2026-08-31-CVE-2026-53362-—-Linux-kernel-IPv6-subsystem-privilege-escalation-(CISA-KEV)]] — **high** ⚑ flagged
- [[threats/2026-08-31-CVE-2022-0995-—-Linux-kernel-out-of-bounds-write-enables-local-privilege-escalation-(CISA-KEV)]] — **high**
- [[threats/2026-08-31-CVE-2019-1068-—-Microsoft-SQL-Server-Database-Engine-remote-code-execution-(CISA-KEV)]] — **high** ⚑ flagged
- [[threats/2026-08-31-CVE-2015-5287-—-Red-Hat-ABRT-local-privilege-escalation-via-symlink-attack-(CISA-KEV)]] — **high**
- [[threats/2026-08-31-Coinminer-payload-hashes-—-three-file-indicators-from-a-single-sample-(2026-08-31)]] — **medium** ⚑ flagged
- [[threats/2026-08-31-Cobalt-Strike-C2-infrastructure-—-32-indicators-across-nine-hosts-(2026-08-31)]] — **high** ⚑ flagged
- [[threats/2026-08-31-ClearFake-payload-delivery-infrastructure-—-56-indicators-observed-(2026-08-31)]] — **high** ⚑ flagged
- [[threats/2026-08-31-Chaos-C2-infrastructure-—-one-host-serving-botnet-controllers-on-ports-80-and-443-(2026-08-31)]] — **medium** ⚑ flagged
- [[threats/2026-08-31-Bashlite-C2-infrastructure-—-single-botnet-controller-on-a-high-non-standard-port-(2026-08-31)]] — **medium** ⚑ flagged
- [[threats/2026-08-31-AsyncRAT-C2-infrastructure-—-seven-botnet-controllers-observed-(2026-08-31)]] — **medium** ⚑ flagged
- [[threats/2026-08-31-Aisuru-botnet-C2-infrastructure-—-28-IP-port-indicators-across-15-hosts-(2026-08-31)]] — **medium** ⚑ flagged
- [[threats/2026-08-31-AdaptixC2-C2-infrastructure-—-four-listeners-on-a-single-host-(2026-08-31)]] — **medium** ⚑ flagged
- [[threats/2026-08-28-CVE-2023-49105-—-ownCloud-WebDAV-pre-signed-URL-authentication-bypass]] — **high**
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

## Review queue

See [[review-queue]] — 50 flagged item(s).

## Stats

| metric | value |
|---|---|
| total threat notes | 92 |
| malware families tracked | 24 |
| ATT&CK techniques seen | 45 |
| last run | 2026-08-31 |

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
