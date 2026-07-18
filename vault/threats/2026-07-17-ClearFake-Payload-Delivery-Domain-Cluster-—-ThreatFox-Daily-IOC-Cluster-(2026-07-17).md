---
title: ClearFake Payload-Delivery Domain Cluster — ThreatFox Daily IOC Cluster (2026-07-17)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-07-17
severity: high
confidence: medium
flagged: true
cve: []
family: [ClearFake]
attack_techniques: [T1189, T1204.001]
actors: []
tags: [threat, threatfox, severity/high]
---

# ClearFake Payload-Delivery Domain Cluster — ThreatFox Daily IOC Cluster (2026-07-17)

## What it is

[[families/ClearFake]] is a JavaScript-based malicious framework, publicly documented since 2023, that is typically injected into web pages to display fake browser/software "update" prompts and social-engineer victims into running commands that install infostealer malware. ThreatFox tagged 75 domains to this family on 2026-07-17 (50 provided in this batch) under the `payload_delivery` threat type, all submitted with 100% confidence over a roughly 24-hour window. The domains largely impersonate or reference gambling/betting brands and services (e.g. "1xbet", "hazarat", "shartbandi", "bet90"), consistent with malvertising or typosquat landing infrastructure rather than a single compromised site.

## Affected products / versions

Not applicable — this is an IOC cluster of attacker-controlled/abused domains, not a product vulnerability.

## ATT&CK mapping

- [[techniques/T1189]] — Drive-by Compromise: ClearFake's established modus operandi is serving malicious JavaScript/fake-update lures from web pages to trigger payload delivery without direct exploitation. This is inferred from well-documented public reporting on the family, not from behavioral detail present in this specific batch.
- [[techniques/T1204.001]] — User Execution: Malicious Link: The domain naming pattern (gambling/betting brand impersonation) suggests victims are directed to these pages via links (ads, redirects, or shared URLs), matching ClearFake's known social-engineering delivery chain. This mapping is also pattern-matched from family-level TTPs rather than confirmed by source data.

## Observed IOCs

| type | value | context |
|------|-------|---------|
| domain | tiwdt.hazzarat.com | ThreatFox confidence 100, first seen 2026-07-17 15:57:01 UTC |
| domain | qzfhwillb.crazyhotchicken.net | ThreatFox confidence 100, first seen 2026-07-17 15:54:48 UTC |
| domain | crazyhotchicken.net | ThreatFox confidence 100, first seen 2026-07-17 15:52:10 UTC |
| domain | sebw9xod.site-asli-bedon-filter-1xbet.com | ThreatFox confidence 100, first seen 2026-07-17 15:44:09 UTC |
| domain | 3u06kg6l.onjabet1.com | ThreatFox confidence 100, first seen 2026-07-17 15:00:06 UTC |
| domain | cgavi.derbi.promo | ThreatFox confidence 100, first seen 2026-07-17 14:55:15 UTC |
| domain | prl0ivfr.hazaratbet.games | ThreatFox confidence 100, first seen 2026-07-17 14:54:12 UTC |
| domain | cachmkcqj.venus90bet.com | ThreatFox confidence 100, first seen 2026-07-17 14:52:29 UTC |
| domain | dtsmmaphe.tampabayspin.com | ThreatFox confidence 100, first seen 2026-07-17 13:55:49 UTC |
| domain | caudzzwo.coop-fresh.com | ThreatFox confidence 100, first seen 2026-07-17 13:55:11 UTC |
| domain | mlmaatvd.behtarin-site-shartbandi.com | ThreatFox confidence 100, first seen 2026-07-17 13:42:16 UTC |
| domain | djqiyxyx.calirayalake.com | ThreatFox confidence 100, first seen 2026-07-17 12:54:58 UTC |
| domain | gkpaspaky.taktikkbet.com | ThreatFox confidence 100, first seen 2026-07-17 12:52:26 UTC |
| domain | gdtuyoor.gamehazarat.com | ThreatFox confidence 100, first seen 2026-07-17 11:55:35 UTC |
| domain | xfakmoduw.lion1bet.com | ThreatFox confidence 100, first seen 2026-07-17 11:54:56 UTC |
| domain | 8kq7qw7a.site-takhtenard-sharti-betland.com | ThreatFox confidence 100, first seen 2026-07-17 11:43:18 UTC |
| domain | wtkxprzu.funxbet.casino | ThreatFox confidence 100, first seen 2026-07-17 10:57:28 UTC |
| domain | hzdmfcatc.sky7bet.casino | ThreatFox confidence 100, first seen 2026-07-17 10:50:39 UTC |
| domain | vzsagfrw.derbi.football | ThreatFox confidence 100, first seen 2026-07-17 09:52:30 UTC |
| domain | dvc734k1.hazaratbet.game | ThreatFox confidence 100, first seen 2026-07-17 09:52:03 UTC |
| domain | 3x6v81kc.varzeshlife.ir | ThreatFox confidence 100, first seen 2026-07-17 09:51:46 UTC |
| domain | lhozmsokb.nextbahis.coupons | ThreatFox confidence 100, first seen 2026-07-17 09:49:15 UTC |
| domain | eogwp3fe.site-shartbandi-pasor.online | ThreatFox confidence 100, first seen 2026-07-17 09:41:27 UTC |
| domain | pygnidup.gem90bet.com | ThreatFox confidence 100, first seen 2026-07-17 08:52:38 UTC |
| domain | dsdvsvqgy.jetbet.download | ThreatFox confidence 100, first seen 2026-07-17 08:48:37 UTC |
| domain | dlylkjaji.jetboro.fun | ThreatFox confidence 100, first seen 2026-07-17 08:48:31 UTC |
| domain | bgtnaqoc.fileboroo.com | ThreatFox confidence 100, first seen 2026-07-17 07:52:49 UTC |
| domain | aefauhqwk.irani-music.com | ThreatFox confidence 100, first seen 2026-07-17 07:50:14 UTC |
| domain | iodz0i3f.behtarin-site-shartbandi-football.com | ThreatFox confidence 100, first seen 2026-07-17 07:31:19 UTC |
| domain | arvujwijm.irani-music.com | ThreatFox confidence 100, first seen 2026-07-17 07:05:54 UTC |
| domain | itwynsuh.enfejartime.com | ThreatFox confidence 100, first seen 2026-07-17 06:51:14 UTC |
| domain | scjzlqeyk.hazzarat.world | ThreatFox confidence 100, first seen 2026-07-17 06:03:17 UTC |
| domain | suwqmlyd.efbetfarsi.com | ThreatFox confidence 100, first seen 2026-07-17 05:51:17 UTC |
| domain | 6j7gyyz9.barkerautoms.com | ThreatFox confidence 100, first seen 2026-07-17 05:30:10 UTC |
| domain | wexltdqtf.hazzarat.com | ThreatFox confidence 100, first seen 2026-07-17 05:07:23 UTC |
| domain | los16zn2.celebritiesadda.com | ThreatFox confidence 100, first seen 2026-07-17 04:51:15 UTC |
| domain | dy6t0cul.hazarat.now | ThreatFox confidence 100, first seen 2026-07-17 04:51:01 UTC |
| domain | ggitkzzn.derbi.promo | ThreatFox confidence 100, first seen 2026-07-17 04:49:52 UTC |
| domain | nruyvebwd.taktikkbet.com | ThreatFox confidence 100, first seen 2026-07-17 04:02:26 UTC |
| domain | ovbeoktk.coop-fresh.com | ThreatFox confidence 100, first seen 2026-07-17 03:52:19 UTC |
| domain | jorjsrfgd.lion1bet.com | ThreatFox confidence 100, first seen 2026-07-17 03:42:38 UTC |
| domain | u5dn1e6x.bazisangkaqazgeychidancepoli.com | ThreatFox confidence 100, first seen 2026-07-17 03:14:25 UTC |
| domain | chsxhscsh.tampabayspin.com | ThreatFox confidence 100, first seen 2026-07-17 02:35:04 UTC |
| domain | vkvmygpg.betbuf90.com | ThreatFox confidence 100, first seen 2026-07-17 02:27:55 UTC |
| domain | rdusnlyzh.sky7bet.casino | ThreatFox confidence 100, first seen 2026-07-17 01:32:14 UTC |
| domain | iqgxtjfc.hazzarat.world | ThreatFox confidence 100, first seen 2026-07-17 01:27:06 UTC |
| domain | a1h9t4pt.venus90bet.com | ThreatFox confidence 100, first seen 2026-07-17 01:12:33 UTC |
| domain | dvzzqxef.gamehazarat.com | ThreatFox confidence 100, first seen 2026-07-17 00:27:22 UTC |
| domain | g3b4hjbg.calculadoracomisiones.com | ThreatFox confidence 100, first seen 2026-07-16 23:50:53 UTC |
| domain | wig5l9be.calirayalake.com | ThreatFox confidence 100, first seen 2026-07-16 23:50:46 UTC |

## Severity assessment

**High** — This is not KEV-listed (no CVE involved) and ClearFake is not classified as ransomware, so neither the KEV floor nor the ransomware step-up applies. The rubric defaults IOC-cluster notes to medium "unless volume or an associated campaign justifies high." Here, 75 distinct domains (50 captured in this batch) were registered/observed within roughly a 24-hour window at 100% ThreatFox confidence, which is a large volume for a single family-day cluster and indicates an active, large-scale campaign rather than isolated commodity distribution. VirusTotal shows only 1-2 malicious/suspicious engine detections out of ~90 for the sampled domains, but this is expected for infrastructure this fresh and does not indicate lower risk — it reflects detection lag, not benignity.

## Confidence notes

Confidence is medium and this note is flagged. The source data provides only domain values, a `payload_delivery` threat type, ThreatFox's own confidence score, and first-seen timestamps — it contains no page content, malware sample, or C2 traffic detail. The description of ClearFake's fake-update/ClickFix delivery mechanism and both ATT&CK mappings (T1189, T1204.001) are drawn from established public reporting on the family, not confirmed behavior in this specific batch — this is pattern-matching on the family name. The characterization of the domains as gambling/betting-brand impersonation is a direct observation of the naming pattern in the source data, but the inference that this indicates malvertising/typosquat lures (as opposed to some other delivery mechanism) is not confirmed by the source.
