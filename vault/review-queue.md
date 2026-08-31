---
title: Review Queue
type: dashboard
tags: [dashboard, review]
updated: 2026-08-31
---

# Review Queue — flagged low-confidence notes

Notes where Claude flagged uncertainty instead of guessing (per the low-confidence
rule in `skills/threat-analyst.md`). Review each, correct or confirm, then remove
`flagged: true` from the note's frontmatter; the next run drops it from this list.

- [[threats/2026-08-31-CVE-2026-8452-—-Citrix-NetScaler-ADC-and-Gateway-memory-buffer-flaw-causes-denial-of-service-(CISA-KEV)]] — confidence: medium
- [[threats/2026-08-31-CVE-2026-66384-—-JFrog-Artifactory-path-traversal-allows-writes-outside-the-Docker-cache-directory-(CISA-KEV)]] — confidence: medium
- [[threats/2026-08-31-CVE-2026-53362-—-Linux-kernel-IPv6-subsystem-privilege-escalation-(CISA-KEV)]] — confidence: medium
- [[threats/2026-08-31-CVE-2019-1068-—-Microsoft-SQL-Server-Database-Engine-remote-code-execution-(CISA-KEV)]] — confidence: medium
- [[threats/2026-08-31-Coinminer-payload-hashes-—-three-file-indicators-from-a-single-sample-(2026-08-31)]] — confidence: medium
- [[threats/2026-08-31-Cobalt-Strike-C2-infrastructure-—-32-indicators-across-nine-hosts-(2026-08-31)]] — confidence: medium
- [[threats/2026-08-31-ClearFake-payload-delivery-infrastructure-—-56-indicators-observed-(2026-08-31)]] — confidence: medium
- [[threats/2026-08-31-Chaos-C2-infrastructure-—-one-host-serving-botnet-controllers-on-ports-80-and-443-(2026-08-31)]] — confidence: medium
- [[threats/2026-08-31-Bashlite-C2-infrastructure-—-single-botnet-controller-on-a-high-non-standard-port-(2026-08-31)]] — confidence: medium
- [[threats/2026-08-31-AsyncRAT-C2-infrastructure-—-seven-botnet-controllers-observed-(2026-08-31)]] — confidence: medium
- [[threats/2026-08-31-Aisuru-botnet-C2-infrastructure-—-28-IP-port-indicators-across-15-hosts-(2026-08-31)]] — confidence: medium
- [[threats/2026-08-31-AdaptixC2-C2-infrastructure-—-four-listeners-on-a-single-host-(2026-08-31)]] — confidence: medium
- [[threats/2026-08-27-CVE-2021-23758-—-Ajax.NET-Professional-Deserialization-of-Untrusted-Data-(KEV)]] — confidence: medium
- [[threats/2026-08-25-SmartApeSG-ClickFix-campaign-delivers-two-remote-access-trojans]] — confidence: low
- [[threats/2026-08-25-FAKEUPDATES-C2-infrastructure-—-1-domain-indicator-(2026-08-25)]] — confidence: medium
- [[threats/2026-08-25-DCRat-C2-infrastructure-—-1-IP-port-indicator-(2026-08-25)]] — confidence: medium
- [[threats/2026-08-25-DarkComet-C2-infrastructure-—-1-IP-port-indicator-(2026-08-25)]] — confidence: low
- [[threats/2026-08-25-CVE-2026-72529-—-TrueConf-Server-Missing-Authentication-for-Critical-Function]] — confidence: medium
- [[threats/2026-08-25-CVE-2026-55040-—-Microsoft-SharePoint-Weak-Authentication-Vulnerability]] — confidence: medium
- [[threats/2026-08-25-CVE-2026-33824-—-Microsoft-IKE-Service-Extensions-Double-Free-Remote-Code-Execution]] — confidence: medium
- [[threats/2026-08-25-CVE-2026-21962-—-Oracle-HTTP-Server-and-WebLogic-Server-Proxy-Plug-in-Improper-Access-Control]] — confidence: medium
- [[threats/2026-08-25-Cobalt-Strike-C2-infrastructure-—-27-IP-port-indicators-(2026-08-25)]] — confidence: medium
- [[threats/2026-08-25-ClearFake-payload-delivery-infrastructure-—-121-IOCs-(2026-08-25)]] — confidence: medium
- [[threats/2026-08-25-Aisuru-botnet-C2-infrastructure-—-4-IP-port-indicators-(2026-08-25)]] — confidence: medium
- [[threats/2026-08-23-TrueConf-Server-Code-Injection-(CVE-2026-72530)]] — confidence: medium
- [[threats/2026-08-04-SmartApeSG-ClickFix-campaign-pushes-unidentified-RAT]] — confidence: low
- [[threats/2026-08-04-Seven-Days-of-Scans-and-Probes-Against-an-Internet-Facing-Web-Server-(malware-traffic-analysis.net,-2026-07-31)]] — confidence: low
- [[threats/2026-08-04-N-able-N-central-Authentication-Bypass-via-Alternate-Path-(CVE-2026-18577)]] — confidence: medium
- [[threats/2026-08-04-Agent-Tesla-FTP-C2-Infrastructure-—-ThreatFox-Daily-IOC-Cluster-(2026-08-04)]] — confidence: medium
- [[threats/2026-08-04-AdaptixC2-C2-Infrastructure-—-ThreatFox-Daily-IOC-Cluster-(2026-08-04)]] — confidence: medium
- [[threats/2026-07-23-CVE-2026-63030-—-WordPress-Core-Interpretation-Conflict-Leading-to-SQL-Injection-and-RCE-(KEV)]] — confidence: medium
- [[threats/2026-07-23-CVE-2026-0770-—-Langflow-untrusted-code-inclusion-allows-remote-code-execution-(KEV)]] — confidence: medium
- [[threats/2026-07-23-Check-Point-SmartConsole-Improper-Authentication-(CVE-2026-16232)]] — confidence: medium
- [[threats/2026-07-21-Efimer-Malware-—-ClickFix-Distribution-Cluster-(MalwareBazaar,-2026-07-21)]] — confidence: medium
- [[threats/2026-07-21-CoinMiner-Cryptomining-Malware-—-2-New-Samples-(MalwareBazaar,-2026-07-21)]] — confidence: medium
- [[threats/2026-07-21-AgentTesla-Malware-Sample-Cluster-—-Invoice-Themed-Phishing-Lures-(MalwareBazaar,-2026-07-21)]] — confidence: medium
- [[threats/2026-07-20-BianLian-botnet-C2-IOC-—-ThreatFox-Daily-Cluster-(2026-07-20)]] — confidence: medium
- [[threats/2026-07-18-Seven-Days-of-Scans,-Probes,-and-Web-Traffic-Against-a-Honeypot-Web-Server]] — confidence: low
- [[threats/2026-07-17-Havoc-C2-Infrastructure-—-ThreatFox-Daily-IOC-Cluster-(2026-07-17)]] — confidence: medium
- [[threats/2026-07-17-Ghost-RAT-Payload-IOC-—-ThreatFox-Daily-Cluster-(2026-07-17)]] — confidence: medium
- [[threats/2026-07-17-FAKEUPDATES-(SocGholish)-Botnet-C2-&-Payload-Delivery-IOC-Cluster-—-ThreatFox-Daily-Cluster-(2026-07-17)]] — confidence: medium
- [[threats/2026-07-17-Evilginx-AiTM-Phishing-C2-—-ThreatFox-IOC-Cluster-(2026-07-17)]] — confidence: medium
- [[threats/2026-07-17-DCRat-Botnet-C2-IOC-—-ThreatFox-Daily-Cluster-(2026-07-17)]] — confidence: medium
- [[threats/2026-07-17-DarkTortilla-Payload-IOC-—-ThreatFox-Daily-Cluster-(2026-07-17)]] — confidence: medium
- [[threats/2026-07-17-Cobalt-Strike-C2-Infrastructure-—-ThreatFox-Daily-IOC-Cluster-(2026-07-17)]] — confidence: medium
- [[threats/2026-07-17-ClearFake-Payload-Delivery-Domain-Cluster-—-ThreatFox-Daily-IOC-Cluster-(2026-07-17)]] — confidence: medium
- [[threats/2026-07-17-Aisuru-Botnet-C2-IOC-—-ThreatFox-Daily-Cluster-(2026-07-17)]] — confidence: medium
- [[threats/2026-07-17-AdaptixC2-C2-Infrastructure-—-ThreatFox-Daily-IOC-Cluster-(2026-07-17)]] — confidence: medium
- [[threats/2026-07-15-ScreenConnect-themed-malware-distribution-on-104.131.86.222-—-2-new-IOCs-(URLhaus,-2026-07-15)]] — confidence: medium
- [[threats/2026-07-15-AdaptixC2-C2-infrastructure-—-7-new-IOCs-(ThreatFox,-2026-07-15)]] — confidence: medium
