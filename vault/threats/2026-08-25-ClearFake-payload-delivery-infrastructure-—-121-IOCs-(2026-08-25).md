---
title: ClearFake payload-delivery infrastructure — 121 IOCs (2026-08-25)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-08-25
severity: high
confidence: medium
flagged: true
cve: []
family: [ClearFake]
attack_techniques: [T1189, T1584.001, T1583.001, T1102, T1071.001]
actors: []
tags: [threat, threatfox, severity/high]
---

# ClearFake payload-delivery infrastructure — 121 IOCs (2026-08-25)

## What it is
ThreatFox published 121 indicators on 2026-08-25 attributed to [[families/ClearFake]], a web-based malware delivery operation that serves fake software-update and verification pages to people browsing ordinary websites. Almost every indicator is a domain used to deliver a payload; one is a command-and-control domain and one is a public CDN URL used to host attacker-controlled script content. The domain set splits into two clear groups: legitimate-looking business sites that appear to have been compromised and repurposed for delivery, and purpose-registered lure domains built around consumer-scam themes (supplement, memory-aid, and political-merchandise names). For a defender this matters because the delivery pages sit on sites employees have no reason to distrust, so URL reputation and category filtering alone will not catch them.

## Affected products / versions
- Not applicable — this is an IOC cluster, not a product vulnerability. The delivery infrastructure targets end-user web browsers generally; the source does not name a specific browser, plugin, or CMS version.
- Many of the 90-confidence domains resolve to small-business and agency websites (including a `wpengine.com` staging host), which is consistent with compromised third-party web hosting, but the source does not state the compromise vector.

## ATT&CK mapping
- [[techniques/T1189]] — Drive-by Compromise: the indicators are tagged `payload_delivery` and consist of web hosts serving content to visiting browsers, which is delivery by web page rather than by attachment or exploit service.
- [[techniques/T1584.001]] — Compromise Infrastructure: Domains: a large share of the domains are ordinary business sites (law firms, dental clinics, remodeling contractors, a WP Engine staging host) that are implausible as attacker registrations, indicating reuse of compromised sites for delivery.
- [[techniques/T1583.001]] — Acquire Infrastructure: Domains: the 100-confidence entries follow a machine-generated pattern (`sv41ylmi.eng--nervealive.com`, `2hc0b19k.en-us-en-darkreset.com`, `en-trumplapelpin.com`) that reflects purpose-registered domains with rotating subdomains.
- [[techniques/T1102]] — Web Service: the payload URL `https://cdn.jsdelivr.net/gh/Justin-97483/dfh45iek8/jjy44gfl7` stages attacker content on a legitimate public CDN backed by a GitHub repository, so retrieval traffic blends with normal developer activity.
- [[techniques/T1071.001]] — Application Layer Protocol: Web Protocols: `dome.369bbqsifangonline.com` is tagged `botnet_cc`, indicating post-compromise control over HTTP(S) from the same campaign infrastructure.

## Observed IOCs

Sample of 50 indicators published for this family-day; the full ThreatFox set for 2026-08-25 contains 121.

| type | value | context |
| --- | --- | --- |
| domain | iconicprogrammers.com | payload_delivery, confidence 90, first seen 16:39:20 UTC |
| domain | empyreanmbs.com | payload_delivery, confidence 90, first seen 16:39:20 UTC |
| domain | pearlglobalsourcing.co | payload_delivery, confidence 90, first seen 16:39:19 UTC |
| domain | dubaiicc.org | payload_delivery, confidence 90, first seen 16:39:19 UTC |
| domain | hcbusinessadvisory.com | payload_delivery, confidence 90, first seen 16:29:18 UTC |
| domain | phunkster.com | payload_delivery, confidence 90, first seen 16:29:17 UTC |
| domain | journeesmerchandising.com | payload_delivery, confidence 90, first seen 16:29:17 UTC |
| domain | economictimes.com.au | payload_delivery, confidence 90, first seen 16:19:16 UTC |
| domain | alexautodz.com | payload_delivery, confidence 90, first seen 16:19:16 UTC |
| domain | amhstage.wpengine.com | payload_delivery, confidence 90, first seen 16:19:15 UTC — WP Engine staging host |
| domain | amineshoot.com | payload_delivery, confidence 90, first seen 16:19:15 UTC |
| domain | dominobrand.io | payload_delivery, confidence 90, first seen 16:19:15 UTC |
| domain | digitaltransform.com.au | payload_delivery, confidence 90, first seen 16:19:15 UTC |
| domain | lbsco.co.uk | payload_delivery, confidence 90, first seen 16:09:13 UTC |
| domain | atlanticlaw.in | payload_delivery, confidence 90, first seen 16:09:13 UTC |
| domain | atlanturesports.com | payload_delivery, confidence 90, first seen 16:09:13 UTC |
| domain | bathroomremodelpalmdale.com | payload_delivery, confidence 90, first seen 16:09:13 UTC |
| domain | flipsguide.com | payload_delivery, confidence 90, first seen 16:09:12 UTC |
| domain | clinicadentalgarciaselva.com | payload_delivery, confidence 90, first seen 16:09:12 UTC |
| domain | digitalmarketingagence.com | payload_delivery, confidence 90, first seen 16:09:12 UTC |
| domain | delgadoexposito.com | payload_delivery, confidence 90, first seen 15:59:11 UTC |
| domain | futureexpected.com | payload_delivery, confidence 90, first seen 15:59:10 UTC |
| domain | landscapingdesignlancaster.com | payload_delivery, confidence 90, first seen 15:59:10 UTC |
| domain | hebaazeez.com | payload_delivery, confidence 90, first seen 15:59:10 UTC |
| domain | fondationinternationaletrokapercfa.org | payload_delivery, confidence 90, first seen 15:59:09 UTC |
| domain | w0a86nbg.eng--neurowave.com | payload_delivery, confidence 100, first seen 15:27:28 UTC — randomized subdomain |
| domain | fz9hhl90.eng-us-neurowave.com | payload_delivery, confidence 100, first seen 15:06:51 UTC — randomized subdomain |
| domain | marcoguazzini.com | payload_delivery, confidence 90, first seen 15:04:39 UTC |
| domain | en-us-en-heroup.com | payload_delivery, confidence 100, first seen 15:01:57 UTC |
| domain | q7ufuwnu.en-trump-token.com | payload_delivery, confidence 100, first seen 14:49:05 UTC |
| domain | dome.369bbqsifangonline.com | **botnet_cc**, confidence 100, first seen 14:18:10 UTC |
| domain | en-memrylift.com | payload_delivery, confidence 100, first seen 14:12:24 UTC |
| domain | en-leptozan-us.com | payload_delivery, confidence 100, first seen 13:52:43 UTC |
| domain | sv41ylmi.eng--nervealive.com | payload_delivery, confidence 100, first seen 13:27:26 UTC — randomized subdomain |
| domain | whstle.site | payload_delivery, confidence 90, first seen 12:34:59 UTC |
| domain | michie.ch | payload_delivery, confidence 90, first seen 12:34:59 UTC |
| domain | floridacustomsbroker.com | payload_delivery, confidence 90, first seen 12:34:58 UTC |
| domain | entretien-toiture.ch | payload_delivery, confidence 90, first seen 12:24:57 UTC |
| domain | h1v48ygy.eng-usa-neurowave.com | payload_delivery, confidence 100, first seen 12:23:32 UTC — randomized subdomain |
| domain | feldschiessen-sense.ch | payload_delivery, confidence 90, first seen 12:04:56 UTC |
| url | https://cdn.jsdelivr.net/gh/Justin-97483/dfh45iek8/jjy44gfl7 | payload_delivery, confidence 100, first seen 11:57:40 UTC — jsDelivr/GitHub-hosted content |
| domain | en-us-andliberty.com | payload_delivery, confidence 100, first seen 11:56:23 UTC |
| domain | b4l0cqbk.eng--memorylift.com | payload_delivery, confidence 100, first seen 11:26:46 UTC — randomized subdomain |
| domain | tsnjsimoo.en-us-en-eloncode.com | payload_delivery, confidence 100, first seen 10:56:49 UTC — randomized subdomain |
| domain | en-us-en-eloncode.com | payload_delivery, confidence 100, first seen 10:55:39 UTC — parent of the above |
| domain | ue0xfkgn.en-trumplapelpin.com | payload_delivery, confidence 100, first seen 10:35:16 UTC — randomized subdomain |
| domain | en-trumplapelpin.com | payload_delivery, confidence 100, first seen 10:34:45 UTC — parent of the above |
| domain | pretuniflex.ca | payload_delivery, confidence 90, first seen 10:29:10 UTC |
| domain | 2hc0b19k.en-us-en-darkreset.com | payload_delivery, confidence 100, first seen 10:07:20 UTC — randomized subdomain |
| domain | en-us-en-darkreset.com | payload_delivery, confidence 100, first seen 10:04:09 UTC — parent of the above |

## Severity assessment
**high** — The IOC-cluster default is medium, and the volume here is what moves it up: 121 indicators in a single day, arriving in clustered bursts roughly every ten minutes across a ten-hour window, is an active large-scale distribution campaign rather than routine commodity churn. The infrastructure is unauthenticated to reach and requires no target-side vulnerability, only a user visiting a web page, so the exploitation precondition is weak. Reuse of apparently compromised legitimate business sites and a public CDN means reputation and category-based web filtering will under-block this traffic, widening effective scope. Offsetting factors keep it below critical: there is no exploited CVE, nothing wormable, no KEV listing, and the source does not evidence a ransomware association — the impact is initial access on individual endpoints, not infrastructure-wide compromise. One `botnet_cc` indicator shows post-compromise control follows successful delivery, which supports high rather than medium.

## Confidence notes
Medium, and flagged. What the source directly supports: the indicator values, their types, the `payload_delivery` and `botnet_cc` threat tags, per-IOC confidence levels, first-seen timestamps, the total of 121, and the ThreatFox attribution to ClearFake. What is inference: the description of ClearFake's delivery mechanism as fake update/verification lure pages comes from public knowledge of the family, not from this source — the source describes no page content, payload, or user-interaction step, so no User Execution technique is mapped even though the family is commonly associated with one. The split between compromised sites and registered lure domains is inferred from domain naming and plausibility, not stated by ThreatFox; individual attributions in that split may be wrong. The final payload and any downstream malware family are unknown from this data. VirusTotal returned 0 malicious detections across all four sampled domains (`iconicprogrammers.com`, `empyreanmbs.com`, `pearlglobalsourcing.co`, `dubaiicc.org`), each with 56 harmless verdicts — expected for freshly compromised legitimate sites whose reputation predates the compromise, but it means these four have no independent corroboration beyond ThreatFox's 90-confidence rating. Only 50 of the 121 indicators were provided; the IOC table is a partial view and blocklists should be built from the full ThreatFox export.
