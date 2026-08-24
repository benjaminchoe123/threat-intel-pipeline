---
title: ClearFake Payload Delivery and C2 Infrastructure — ThreatFox Daily IOC Cluster (2026-07-20)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-07-20
severity: high
confidence: medium
flagged: false
cve: []
family: [ClearFake]
attack_techniques: [T1189, T1204.004, T1071.001]
actors: []
tags: [threat, threatfox, severity/high]
---

# ClearFake Payload Delivery and C2 Infrastructure — ThreatFox Daily IOC Cluster (2026-07-20)

## What it is

ThreatFox reported 206 new indicators tied to [[families/ClearFake]] on 2026-07-20, one of the largest single-day clusters for this family in recent weeks. ClearFake is a malicious JavaScript framework injected into compromised legitimate websites that shows visitors fake browser-update or "verify you are human" (ClickFix) prompts to trick them into running malware, typically information stealers. This cluster mixes payload-delivery domains — many of them randomized subdomains on what appear to be compromised small-business and community websites — with a set of command-and-control domains on `.garden` top-level domains.

## Affected products / versions

Not applicable — this is an IOC cluster for an ongoing distribution campaign, not a product vulnerability. Anyone browsing a compromised website is a potential victim.

## ATT&CK mapping

- [[techniques/T1189]] — Drive-by Compromise: ClearFake operates by injecting scripts into compromised legitimate websites so that ordinary visits expose users to the lure.
- [[techniques/T1204.004]] — User Execution: Malicious Copy and Paste: ClearFake is a primary distributor of ClickFix lures that instruct victims to paste commands into the Run dialog or terminal.
- [[techniques/T1071.001]] — Application Layer Protocol: Web Protocols: the cluster includes domains tagged `botnet_cc`, indicating web-based command-and-control infrastructure.

## Observed IOCs

Feed reported 206 IOCs for the day; the 50 included in the source snapshot are listed below.

| type | value | context |
|---|---|---|
| domain | z52rumys.customhomebuildersplainfield.com | payload_delivery, confidence 100 |
| domain | 47ytdzjs.economywindowsparts.com | payload_delivery, confidence 100 |
| domain | gravitfluxbox.grovessa.garden | botnet_cc, confidence 90 |
| domain | kzsf.concretewestgj.com | payload_delivery, confidence 100 |
| domain | tjhsq.onjabet1.com | payload_delivery, confidence 100 |
| domain | concretewestgj.com | payload_delivery, confidence 100 |
| domain | urbanhostgate.grovessa.garden | botnet_cc, confidence 90 |
| domain | smartmeshsys2.petalune.garden | botnet_cc, confidence 90 |
| domain | 2zm9lhlg.groeschelcompany.com | payload_delivery, confidence 100 |
| domain | groeschelcompany.com | payload_delivery, confidence 100 |
| domain | zpbn.comptonanimalrescue.com | payload_delivery, confidence 100 |
| domain | lxlwn.nextbahis.one | payload_delivery, confidence 100 |
| domain | comptonanimalrescue.com | payload_delivery, confidence 100 |
| domain | glmm.colg1.org | payload_delivery, confidence 100 |
| domain | lcare.mrslopezsings.org | payload_delivery, confidence 100 |
| domain | wctvn.mrslopezsings.org | payload_delivery, confidence 100 |
| domain | lvcrn.monicarobles.org | payload_delivery, confidence 100 |
| domain | monicarobles.org | payload_delivery, confidence 100 |
| domain | drsvt.nextbahis.poker | payload_delivery, confidence 100 |
| domain | axoo.colg1.org | payload_delivery, confidence 100 |
| domain | colg1.org | payload_delivery, confidence 100 |
| domain | xhbgt.nextbahis.blog | payload_delivery, confidence 100 |
| domain | aeiyi.jetbet.download | payload_delivery, confidence 100 |
| domain | pjjuosk1.fredcoplumbingpros.com | payload_delivery, confidence 100 |
| domain | igsx.closedfistllc.com | payload_delivery, confidence 100 |
| domain | aruhq.jbgroup21.com | payload_delivery, confidence 100 |
| domain | vastlogicweb.petalune.garden | botnet_cc, confidence 90 |
| domain | stellar5bit.petalune.garden | botnet_cc, confidence 90 |
| domain | wbpypinui.generososbakerycafe.com | payload_delivery, confidence 100 |
| domain | generososbakerycafe.com | payload_delivery, confidence 100 |
| domain | cglp.cleantruckchecksac.com | payload_delivery, confidence 100 |
| domain | embvx.hazaratbet.bet | payload_delivery, confidence 100 |
| domain | grandnode3unit.solavern.garden | botnet_cc, confidence 90 |
| domain | freetasksite8.petalune.garden | botnet_cc, confidence 90 |
| domain | a6du2gsx.fit2leadconference.com | payload_delivery, confidence 100 |
| domain | hag0wqv7.estrelamardedetizadora.com | payload_delivery, confidence 100 |
| domain | fit2leadconference.com | payload_delivery, confidence 100 |
| domain | estrelamardedetizadora.com | payload_delivery, confidence 100 |
| domain | qaqatrf8.dermatologycongress.org | payload_delivery, confidence 100 |
| domain | bcmej6hr.goodlifelakerentals.com | payload_delivery, confidence 100 |
| domain | 2gfxwchj.emeraldualzone.com | payload_delivery, confidence 100 |
| domain | dermatologycongress.org | payload_delivery, confidence 100 |
| domain | goodlifelakerentals.com | payload_delivery, confidence 100 |
| domain | emeraldualzone.com | payload_delivery, confidence 100 |
| domain | bhrbc90m.fredcoplumbingpros.com | payload_delivery, confidence 100 |
| domain | xgu7k53h.economywindowsparts.com | payload_delivery, confidence 100 |
| domain | fredcoplumbingpros.com | payload_delivery, confidence 100 |
| domain | ea168jci.customhomebuildersplainfield.com | payload_delivery, confidence 100 |
| domain | economywindowsparts.com | payload_delivery, confidence 100 |
| domain | customhomebuildersplainfield.com | payload_delivery, confidence 100 |

## Severity assessment

**high** — IOC-cluster notes default to medium under the rubric, but two factors raise this one. First, volume: 206 indicators in a single day is well above routine daily reporting and indicates a large, actively expanding operation. Second, this reflects an active, large-scale malware campaign — ClearFake is a prolific distribution framework whose lures run on compromised legitimate websites, so exposure is broad and not limited to users seeking risky content. The mix of fresh payload-delivery domains and dedicated command-and-control infrastructure (the `.garden` domains, one of which VirusTotal already scores 8/91 malicious) shows both the delivery and control sides of the operation being provisioned the same day. No ransomware association is claimed in the source, so no further step up applies.

## Confidence notes

The IOC list, threat-type labels, and per-indicator confidence scores come directly from the ThreatFox source data. The description of how ClearFake operates (compromised-site injection, fake-update/ClickFix lures) and all three ATT&CK mappings are based on well-established public reporting about the family, not on behavior described in this feed — the source provides only domains and threat-type tags. Because the mappings rest on family-level knowledge rather than observed behavior in the source, confidence is capped at medium. VirusTotal coverage of the sampled fresh delivery domains is low (0–1 engines), which is normal for indicators first seen the same day and neither confirms nor undermines the feed's labels.
