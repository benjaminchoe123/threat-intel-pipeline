---
title: ClearFake payload-delivery infrastructure — 56 indicators observed (2026-08-31)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-08-31
severity: high
confidence: medium
flagged: true
cve: []
family: [ClearFake]
attack_techniques: [T1189, T1102, T1608.001]
actors: []
tags: [threat, threatfox, severity/high]
---

# ClearFake payload-delivery infrastructure — 56 indicators observed (2026-08-31)

## What it is
ThreatFox published 56 indicators tied to [[families/ClearFake]] over roughly a 29-hour window ending 2026-08-31. Almost all are domains labelled `payload_delivery` — the web addresses a victim's browser is sent to in order to fetch malicious content. Two of them are raw file URLs on `raw.githubusercontent.com`, meaning the operators are using a legitimate, widely-allowed developer service to host payload content rather than their own servers. For a defender the practical meaning is simple: these are addresses to block and to hunt for in proxy and DNS logs, because a machine that contacted one was likely one step away from downloading malware.

## Affected products / versions
- Not applicable — this is an infrastructure/IOC cluster, not a vulnerability in a specific product. The source data names no affected software or versions.

## ATT&CK mapping
- [[techniques/T1189]] — Drive-by Compromise: the entire indicator set is typed `payload_delivery` and consists of web hosts a browser is directed to; [[families/ClearFake]] is publicly documented as a browser-delivered injection campaign. See Confidence notes — the delivery mechanism is not described in the source itself.
- [[techniques/T1102]] — Web Service: two indicators are `raw.githubusercontent.com` URLs under attacker-controlled accounts (`Christa6547/fling`, `Kath19634/ural3495`), i.e. content retrieved from a legitimate third-party service instead of dedicated attacker infrastructure. This is directly visible in the source data.
- [[techniques/T1608.001]] — Stage Capabilities: Upload Malware: the same GitHub raw paths are staged payload locations, which is what the `payload_delivery` threat type asserts about them.

## Observed IOCs
All 50 indicators returned in this snapshot are listed below; the source reports 56 for the day, so a small number are not included here. Confidence is ThreatFox's own 0–100 score. Times are UTC.

| type | value | context |
|---|---|---|
| domain | wdccb3xe.home-power-shield.com | payload_delivery, conf 100, first seen 2026-08-31 05:36 |
| domain | prgfeg84.getdsm.com | payload_delivery, conf 100, first seen 2026-08-31 05:03 |
| url | https://raw.githubusercontent.com/Christa6547/fling/refs/heads/main/scoop | payload_delivery, conf 100, first seen 2026-08-31 03:13 |
| domain | dphx1pvb.en-us-glucotrustt-bites.com | payload_delivery, conf 100, first seen 2026-08-31 03:06 |
| domain | bp3mtp82.shop-aizenpower.us | payload_delivery, conf 100, first seen 2026-08-31 01:42 |
| domain | qa5c8tze.www-glucotrust-bites.com | payload_delivery, conf 100, first seen 2026-08-31 01:29 |
| domain | m3c33sfv.rtinaclear.com | payload_delivery, conf 100, first seen 2026-08-31 01:25 |
| domain | rtinaclear.com | payload_delivery, conf 100, first seen 2026-08-31 01:24 |
| domain | 353qfu36.en-trump-token.com | payload_delivery, conf 100, first seen 2026-08-31 01:02 |
| domain | www.forumeciv-afriquecentrale.com | payload_delivery, conf 90, first seen 2026-08-31 00:36 |
| domain | h5xluule.barbashat.com | payload_delivery, conf 100, first seen 2026-08-30 23:01 |
| domain | 0qa0xgkt.retinaclr.com | payload_delivery, conf 100, first seen 2026-08-30 21:14 |
| domain | retinaclr.com | payload_delivery, conf 100, first seen 2026-08-30 21:13 |
| domain | xnjbjf7o.shop-aquapeace.us | payload_delivery, conf 100, first seen 2026-08-30 21:01 |
| domain | shop-aquapeace.us | payload_delivery, conf 100, first seen 2026-08-30 21:00 |
| domain | 29l1b9y1.shop-aeroslim.us | payload_delivery, conf 100, first seen 2026-08-30 20:40 |
| domain | p0iqkjuq.usen-glucotrust-bites.com | payload_delivery, conf 100, first seen 2026-08-30 20:20 |
| domain | usen-glucotrust-bites.com | payload_delivery, conf 100, first seen 2026-08-30 20:19 |
| domain | eelsq5rh.shop-aquaburn.us | payload_delivery, conf 100, first seen 2026-08-30 19:02 |
| domain | shop-aquaburn.us | payload_delivery, conf 100, first seen 2026-08-30 18:59 |
| domain | 7109hvuj.retinaclier.com | payload_delivery, conf 100, first seen 2026-08-30 17:03 |
| domain | retinaclier.com | payload_delivery, conf 100, first seen 2026-08-30 17:03 |
| domain | lf2qo513.shop-aquaburn.com | payload_delivery, conf 100, first seen 2026-08-30 17:00 |
| domain | shop-aquaburn.com | payload_delivery, conf 100, first seen 2026-08-30 16:59 |
| domain | shop-alphatonic.us | payload_delivery, conf 100, first seen 2026-08-30 16:57 |
| domain | glyco--free.com | payload_delivery, conf 100, first seen 2026-08-30 16:54 |
| domain | www.maxmetalpackage.com | payload_delivery, conf 90, first seen 2026-08-30 16:06 |
| domain | 7ytwphx3.purabst.com | payload_delivery, conf 100, first seen 2026-08-30 15:35 |
| domain | purabst.com | payload_delivery, conf 100, first seen 2026-08-30 15:33 |
| domain | 2uehzspm.prosta-fense.org | payload_delivery, conf 100, first seen 2026-08-30 15:06 |
| domain | prosta-fense.org | payload_delivery, conf 100, first seen 2026-08-30 15:02 |
| domain | zyo61rgc.shop-alphasurge.us | payload_delivery, conf 100, first seen 2026-08-30 14:58 |
| domain | shop-alphasurge.us | payload_delivery, conf 100, first seen 2026-08-30 14:57 |
| domain | eq7rkug7.shop-alphastreamplus.us | payload_delivery, conf 100, first seen 2026-08-30 12:58 |
| domain | glucotrust-bites.us.com | payload_delivery, conf 100, first seen 2026-08-30 12:57 |
| domain | shop-alphastreamplus.us | payload_delivery, conf 100, first seen 2026-08-30 12:56 |
| url | https://raw.githubusercontent.com/Kath19634/ural3495/refs/heads/main/fds5412 | payload_delivery, conf 100, first seen 2026-08-30 12:55 |
| domain | 84pa4isp.retinaclearofficials.com | payload_delivery, conf 100, first seen 2026-08-30 12:55 |
| domain | retinaclearofficials.com | payload_delivery, conf 100, first seen 2026-08-30 12:52 |
| domain | lbsa.nova-dev.ch | payload_delivery, conf 90, first seen 2026-08-30 12:41 |
| domain | woodfield.global | payload_delivery, conf 90, first seen 2026-08-30 12:41 |
| domain | hendersonlawjax.net | payload_delivery, conf 90, first seen 2026-08-30 12:01 |
| domain | 4u4hidmw.shop-alphaboostpro.us | payload_delivery, conf 100, first seen 2026-08-30 10:57 |
| domain | shop-alphaboostpro.us | payload_delivery, conf 100, first seen 2026-08-30 10:56 |
| domain | 3pynvhuk.ultralightlondon.uk | payload_delivery, conf 100, first seen 2026-08-30 10:54 |
| domain | ultralightlondon.uk | payload_delivery, conf 100, first seen 2026-08-30 10:53 |
| domain | 1jtxup9c.pura--boost.us | payload_delivery, conf 100, first seen 2026-08-30 10:34 |
| domain | pura--boost.us | payload_delivery, conf 100, first seen 2026-08-30 10:33 |
| domain | uehky4jw.prosta--fense.com | payload_delivery, conf 100, first seen 2026-08-30 10:02 |
| domain | xy08z5pm.shop-aizenpower.us | payload_delivery, conf 100, first seen 2026-08-30 09:01 |

Two structural patterns are worth noting for detection: most apex domains appear alongside an eight-character random-looking subdomain of themselves (`shop-aquaburn.us` and `eelsq5rh.shop-aquaburn.us`), and a large share of the apexes imitate health-supplement or wellness storefronts (`glucotrust`, `retinaclear`, `aquaburn`, `alphatonic`, and close misspellings of each).

## Severity assessment
**high** — This is an IOC-cluster note, which the rubric defaults to medium, but the volume moves it up: 56 indicators across roughly 29 hours, from an operation registering fresh apex domains at a rate of several per hour, is an active large-scale campaign rather than routine commodity churn. The rubric rates an active, large-scale malware campaign as high. There is no CVE, no KEV listing, and no unauthenticated-RCE or wormable component here, so nothing floors or pushes this to critical, and the source ties no ransomware family to the cluster (which would otherwise raise it a step). The VirusTotal sample argues the same way from the opposite direction: 1–4 malicious engines against ~50 harmless on four sampled indicators is the signature of infrastructure too new for reputation systems to have caught up, not of benign hosts — blocklist coverage is the weak point, which is what makes a fresh indicator list like this operationally valuable.

## Confidence notes
**Medium, flagged.** What the source directly supports: every indicator value, its type, its ThreatFox confidence score, its `payload_delivery` threat type, and its first-seen timestamp; the two GitHub raw URLs and therefore the [[techniques/T1102]] and [[techniques/T1608.001]] mappings; and the family attribution to [[families/ClearFake]], which is ThreatFox's own label.

What is inference beyond the source:

- The [[techniques/T1189]] mapping rests on public knowledge of how ClearFake operates (malicious JavaScript injected into web pages, presented to the visitor as a browser or software update) plus the `payload_delivery` typing. The source contains no description of the delivery chain, no injected script, and no landing-page evidence. This is partly pattern-matching on the family name and should be treated as such.
- Nothing in the source states what payload these hosts serve. ClearFake is publicly associated with infostealer delivery, but no hash, filename, or second-stage family appears in this data, so no payload family is recorded in the frontmatter.
- The mixed character of the domain set — bulk-registered supplement-shop lookalikes at confidence 100 versus a handful of ordinary-looking business and organisation domains at confidence 90 (`www.forumeciv-afriquecentrale.com`, `www.maxmetalpackage.com`, `lbsa.nova-dev.ch`, `woodfield.global`, `hendersonlawjax.net`) — is consistent with the lower-scored group being compromised legitimate sites rather than attacker-registered ones. The source does not say this, so no Compromise Infrastructure technique is mapped and the reading is offered here only as a hypothesis to check before blocking those five outright; blocking a compromised legitimate domain has different collateral cost than blocking a throwaway.
- User Execution ([[techniques/T1204]]) is deliberately **not** mapped despite being characteristic of ClearFake's fake-update and clipboard-paste lures, because this snapshot contains no evidence of the victim-side interaction.
- The listing covers 50 of the 56 indicators the source reports for the day; the remaining 6 were not in the returned data and are not reconstructed here.
