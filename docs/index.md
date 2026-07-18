---
title: Threat Intel Pipeline
---

# Threat Intel Pipeline

An automated threat intelligence pipeline that ingests public threat feeds daily, uses
Claude (headless) to enrich each item into analyst-quality notes, stores everything as a
wikilinked knowledge graph in an Obsidian vault, and drafts a weekly analyst report that a
human reviews and approves before anything is published.

Built by an aspiring SOC analyst as a working exercise in threat intel triage: every
design decision optimizes for **honest, auditable analysis** — the pipeline is engineered
so the AI can say "I don't know," and a human is always the last gate before publication.

[View the source on GitHub](https://github.com/benjaminchoe123/threat-intel-pipeline) ·
[Read the full README](https://github.com/benjaminchoe123/threat-intel-pipeline#readme)

## Stats

| metric | value |
|---|---|
| threat notes | 26 |
| malware families tracked | 12 |
| ATT&CK techniques observed | 18 |
| feeds ingested | CISA KEV, ThreatFox, URLhaus, MalwareBazaar, MTA blog RSS |
| enrichment cost | ~$0.37/note ([full audit trail](https://github.com/benjaminchoe123/threat-intel-pipeline/tree/main/logs/audit)) |

Every note ships with a matching [STIX 2.1 bundle](https://github.com/benjaminchoe123/threat-intel-pipeline/tree/main/vault/docs/stix)
and feeds an [ATT&CK Navigator layer](https://github.com/benjaminchoe123/threat-intel-pipeline/blob/main/vault/docs/attack-layer.json)
(load it at [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/)).

## Recent threats

- <span style="background:#c0392b;color:#fff;padding:1px 8px;border-radius:3px;font-size:0.78em;font-weight:600;letter-spacing:0.03em">CRITICAL</span> [Microsoft SharePoint Deserialization Vulnerability Actively Exploited (CVE-2026-58644)](https://github.com/benjaminchoe123/threat-intel-pipeline/blob/main/vault/threats/2026-07-17-Microsoft-SharePoint-Deserialization-Vulnerability-Actively-Exploited-%28CVE-2026-58644%29.md) (2026-07-17)
- <span style="background:#d35400;color:#fff;padding:1px 8px;border-radius:3px;font-size:0.78em;font-weight:600;letter-spacing:0.03em">HIGH</span> [Havoc C2 Infrastructure — ThreatFox Daily IOC Cluster (2026-07-17)](https://github.com/benjaminchoe123/threat-intel-pipeline/blob/main/vault/threats/2026-07-17-Havoc-C2-Infrastructure-%E2%80%94-ThreatFox-Daily-IOC-Cluster-%282026-07-17%29.md)
- <span style="background:#b7950b;color:#fff;padding:1px 8px;border-radius:3px;font-size:0.78em;font-weight:600;letter-spacing:0.03em">MEDIUM</span> [Ghost RAT Payload IOC — ThreatFox Daily Cluster (2026-07-17)](https://github.com/benjaminchoe123/threat-intel-pipeline/blob/main/vault/threats/2026-07-17-Ghost-RAT-Payload-IOC-%E2%80%94-ThreatFox-Daily-Cluster-%282026-07-17%29.md)
- <span style="background:#c0392b;color:#fff;padding:1px 8px;border-radius:3px;font-size:0.78em;font-weight:600;letter-spacing:0.03em">CRITICAL</span> [Fortinet FortiSandbox OS Command Injection Vulnerability (CVE-2026-39808)](https://github.com/benjaminchoe123/threat-intel-pipeline/blob/main/vault/threats/2026-07-17-Fortinet-FortiSandbox-OS-Command-Injection-Vulnerability-%28CVE-2026-39808%29.md) (2026-07-17)
- <span style="background:#d35400;color:#fff;padding:1px 8px;border-radius:3px;font-size:0.78em;font-weight:600;letter-spacing:0.03em">HIGH</span> [FAKEUPDATES (SocGholish) Botnet C2 & Payload Delivery IOC Cluster — ThreatFox Daily Cluster (2026-07-17)](https://github.com/benjaminchoe123/threat-intel-pipeline/blob/main/vault/threats/2026-07-17-FAKEUPDATES-%28SocGholish%29-Botnet-C2-%26-Payload-Delivery-IOC-Cluster-%E2%80%94-ThreatFox-Daily-Cluster-%282026-07-17%29.md)
- <span style="background:#b7950b;color:#fff;padding:1px 8px;border-radius:3px;font-size:0.78em;font-weight:600;letter-spacing:0.03em">MEDIUM</span> [Evilginx AiTM Phishing C2 — ThreatFox IOC Cluster (2026-07-17)](https://github.com/benjaminchoe123/threat-intel-pipeline/blob/main/vault/threats/2026-07-17-Evilginx-AiTM-Phishing-C2-%E2%80%94-ThreatFox-IOC-Cluster-%282026-07-17%29.md)
- <span style="background:#b7950b;color:#fff;padding:1px 8px;border-radius:3px;font-size:0.78em;font-weight:600;letter-spacing:0.03em">MEDIUM</span> [DCRat Botnet C2 IOC — ThreatFox Daily Cluster (2026-07-17)](https://github.com/benjaminchoe123/threat-intel-pipeline/blob/main/vault/threats/2026-07-17-DCRat-Botnet-C2-IOC-%E2%80%94-ThreatFox-Daily-Cluster-%282026-07-17%29.md)
- <span style="background:#b7950b;color:#fff;padding:1px 8px;border-radius:3px;font-size:0.78em;font-weight:600;letter-spacing:0.03em">MEDIUM</span> [DarkTortilla Payload IOC — ThreatFox Daily Cluster (2026-07-17)](https://github.com/benjaminchoe123/threat-intel-pipeline/blob/main/vault/threats/2026-07-17-DarkTortilla-Payload-IOC-%E2%80%94-ThreatFox-Daily-Cluster-%282026-07-17%29.md)
- <span style="background:#d35400;color:#fff;padding:1px 8px;border-radius:3px;font-size:0.78em;font-weight:600;letter-spacing:0.03em">HIGH</span> [Cobalt Strike C2 Infrastructure — ThreatFox Daily IOC Cluster (2026-07-17)](https://github.com/benjaminchoe123/threat-intel-pipeline/blob/main/vault/threats/2026-07-17-Cobalt-Strike-C2-Infrastructure-%E2%80%94-ThreatFox-Daily-IOC-Cluster-%282026-07-17%29.md)
- <span style="background:#d35400;color:#fff;padding:1px 8px;border-radius:3px;font-size:0.78em;font-weight:600;letter-spacing:0.03em">HIGH</span> [ClearFake Payload-Delivery Domain Cluster — ThreatFox Daily IOC Cluster (2026-07-17)](https://github.com/benjaminchoe123/threat-intel-pipeline/blob/main/vault/threats/2026-07-17-ClearFake-Payload-Delivery-Domain-Cluster-%E2%80%94-ThreatFox-Daily-IOC-Cluster-%282026-07-17%29.md)
- <span style="background:#b7950b;color:#fff;padding:1px 8px;border-radius:3px;font-size:0.78em;font-weight:600;letter-spacing:0.03em">MEDIUM</span> [AsyncRAT Botnet C2 IOC — ThreatFox Daily Cluster (2026-07-17)](https://github.com/benjaminchoe123/threat-intel-pipeline/blob/main/vault/threats/2026-07-17-AsyncRAT-Botnet-C2-IOC-%E2%80%94-ThreatFox-Daily-Cluster-%282026-07-17%29.md)
- <span style="background:#b7950b;color:#fff;padding:1px 8px;border-radius:3px;font-size:0.78em;font-weight:600;letter-spacing:0.03em">MEDIUM</span> [Aisuru Botnet C2 IOC — ThreatFox Daily Cluster (2026-07-17)](https://github.com/benjaminchoe123/threat-intel-pipeline/blob/main/vault/threats/2026-07-17-Aisuru-Botnet-C2-IOC-%E2%80%94-ThreatFox-Daily-Cluster-%282026-07-17%29.md)
- <span style="background:#d35400;color:#fff;padding:1px 8px;border-radius:3px;font-size:0.78em;font-weight:600;letter-spacing:0.03em">HIGH</span> [AdaptixC2 C2 Infrastructure — ThreatFox Daily IOC Cluster (2026-07-17)](https://github.com/benjaminchoe123/threat-intel-pipeline/blob/main/vault/threats/2026-07-17-AdaptixC2-C2-Infrastructure-%E2%80%94-ThreatFox-Daily-IOC-Cluster-%282026-07-17%29.md)
- <span style="background:#d35400;color:#fff;padding:1px 8px;border-radius:3px;font-size:0.78em;font-weight:600;letter-spacing:0.03em">HIGH</span> [SonicWall SMA1000 Appliances Server-Side Request Forgery (CVE-2026-15409)](https://github.com/benjaminchoe123/threat-intel-pipeline/blob/main/vault/threats/2026-07-15-SonicWall-SMA1000-Appliances-Server-Side-Request-Forgery-%28CVE-2026-15409%29.md) (2026-07-15)
- <span style="background:#d35400;color:#fff;padding:1px 8px;border-radius:3px;font-size:0.78em;font-weight:600;letter-spacing:0.03em">HIGH</span> [SonicWall SMA1000 Appliances Code Injection (CVE-2026-15410)](https://github.com/benjaminchoe123/threat-intel-pipeline/blob/main/vault/threats/2026-07-15-SonicWall-SMA1000-Appliances-Code-Injection-%28CVE-2026-15410%29.md) (2026-07-15)
- <span style="background:#b7950b;color:#fff;padding:1px 8px;border-radius:3px;font-size:0.78em;font-weight:600;letter-spacing:0.03em">MEDIUM</span> [ScreenConnect-themed malware distribution on 137.184.133.198 — 2 new IOCs (URLhaus, 2026-07-15)](https://github.com/benjaminchoe123/threat-intel-pipeline/blob/main/vault/threats/2026-07-15-ScreenConnect-themed-malware-distribution-on-137.184.133.198-%E2%80%94-2-new-IOCs-%28URLhaus%2C-2026-07-15%29.md) (2026-07-15)
- <span style="background:#b7950b;color:#fff;padding:1px 8px;border-radius:3px;font-size:0.78em;font-weight:600;letter-spacing:0.03em">MEDIUM</span> [ScreenConnect-themed malware distribution on 104.131.86.222 — 2 new IOCs (URLhaus, 2026-07-15)](https://github.com/benjaminchoe123/threat-intel-pipeline/blob/main/vault/threats/2026-07-15-ScreenConnect-themed-malware-distribution-on-104.131.86.222-%E2%80%94-2-new-IOCs-%28URLhaus%2C-2026-07-15%29.md) (2026-07-15)
- <span style="background:#c0392b;color:#fff;padding:1px 8px;border-radius:3px;font-size:0.78em;font-weight:600;letter-spacing:0.03em">CRITICAL</span> [Oracle E-Business Suite Improper Privilege Management Vulnerability (CVE-2026-46817)](https://github.com/benjaminchoe123/threat-intel-pipeline/blob/main/vault/threats/2026-07-15-Oracle-E-Business-Suite-Improper-Privilege-Management-Vulnerability-%28CVE-2026-46817%29.md) (2026-07-15)
- <span style="background:#d35400;color:#fff;padding:1px 8px;border-radius:3px;font-size:0.78em;font-weight:600;letter-spacing:0.03em">HIGH</span> [KNX Protocol Connection Authorization Flaw Lets Attackers Purge and Lock Building Automation Devices (CVE-2023-4346)](https://github.com/benjaminchoe123/threat-intel-pipeline/blob/main/vault/threats/2026-07-15-KNX-Protocol-Connection-Authorization-Flaw-Lets-Attackers-Purge-and-Lock-Building-Automation-Devices-%28CVE-2023-4346%29.md) (2026-07-15)
- <span style="background:#d35400;color:#fff;padding:1px 8px;border-radius:3px;font-size:0.78em;font-weight:600;letter-spacing:0.03em">HIGH</span> [iCagenda Unrestricted File Upload (CVE-2026-48939)](https://github.com/benjaminchoe123/threat-intel-pipeline/blob/main/vault/threats/2026-07-15-iCagenda-Unrestricted-File-Upload-%28CVE-2026-48939%29.md) (2026-07-15)
- <span style="background:#c0392b;color:#fff;padding:1px 8px;border-radius:3px;font-size:0.78em;font-weight:600;letter-spacing:0.03em">CRITICAL</span> [CVE-2026-56164 — Microsoft SharePoint Server unauthenticated privilege escalation (KEV)](https://github.com/benjaminchoe123/threat-intel-pipeline/blob/main/vault/threats/2026-07-15-CVE-2026-56164-%E2%80%94-Microsoft-SharePoint-Server-unauthenticated-privilege-escalation-%28KEV%29.md) (2026-07-15)
- <span style="background:#d35400;color:#fff;padding:1px 8px;border-radius:3px;font-size:0.78em;font-weight:600;letter-spacing:0.03em">HIGH</span> [CVE-2026-56155 — Microsoft AD FS local privilege escalation (KEV)](https://github.com/benjaminchoe123/threat-intel-pipeline/blob/main/vault/threats/2026-07-15-CVE-2026-56155-%E2%80%94-Microsoft-AD-FS-local-privilege-escalation-%28KEV%29.md) (2026-07-15)
- <span style="background:#d35400;color:#fff;padding:1px 8px;border-radius:3px;font-size:0.78em;font-weight:600;letter-spacing:0.03em">HIGH</span> [Cisco IOS 12.4 Cross-Site Request Forgery (CVE-2008-4128)](https://github.com/benjaminchoe123/threat-intel-pipeline/blob/main/vault/threats/2026-07-15-Cisco-IOS-12.4-Cross-Site-Request-Forgery-%28CVE-2008-4128%29.md) (2026-07-15)
- <span style="background:#c0392b;color:#fff;padding:1px 8px;border-radius:3px;font-size:0.78em;font-weight:600;letter-spacing:0.03em">CRITICAL</span> [Balbooa Forms Unauthenticated Arbitrary File Upload (CVE-2026-56291)](https://github.com/benjaminchoe123/threat-intel-pipeline/blob/main/vault/threats/2026-07-15-Balbooa-Forms-Unauthenticated-Arbitrary-File-Upload-%28CVE-2026-56291%29.md) (2026-07-15)
- <span style="background:#b7950b;color:#fff;padding:1px 8px;border-radius:3px;font-size:0.78em;font-weight:600;letter-spacing:0.03em">MEDIUM</span> [Agent Tesla — 43 new IOCs (ThreatFox, 2026-07-15)](https://github.com/benjaminchoe123/threat-intel-pipeline/blob/main/vault/threats/2026-07-15-Agent-Tesla-%E2%80%94-43-new-IOCs-%28ThreatFox%2C-2026-07-15%29.md) (2026-07-15)
- <span style="background:#d35400;color:#fff;padding:1px 8px;border-radius:3px;font-size:0.78em;font-weight:600;letter-spacing:0.03em">HIGH</span> [AdaptixC2 C2 infrastructure — 7 new IOCs (ThreatFox, 2026-07-15)](https://github.com/benjaminchoe123/threat-intel-pipeline/blob/main/vault/threats/2026-07-15-AdaptixC2-C2-infrastructure-%E2%80%94-7-new-IOCs-%28ThreatFox%2C-2026-07-15%29.md) (2026-07-15)

*(This list is a static snapshot, refreshed manually — not an automated feed. Browse
[vault/threats](https://github.com/benjaminchoe123/threat-intel-pipeline/tree/main/vault/threats)
directly on GitHub for the current set.)*

## What makes this different from a scraper + LLM

- **The AI is not trusted.** Every enrichment is validated against a strict schema before
  it can touch the vault, and every claim is audit-logged against its source.
- **Failure is loud, not silent.** A dead feed, a malformed entry, or a bad model output
  quarantines the item instead of corrupting the record — see the
  ["what went wrong, and what it taught me"](https://github.com/benjaminchoe123/threat-intel-pipeline#readme) section of the README.
- **A human is always the last gate.** Nothing reaches LinkedIn or a public report without
  explicit review and approval.
