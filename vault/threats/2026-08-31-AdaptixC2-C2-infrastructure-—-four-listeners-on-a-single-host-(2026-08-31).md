---
title: AdaptixC2 C2 infrastructure — four listeners on a single host (2026-08-31)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-08-31
severity: medium
confidence: medium
flagged: true
cve: []
family: [AdaptixC2]
attack_techniques: [T1071.001, T1571]
actors: []
tags: [threat, threatfox, severity/medium]
---

# AdaptixC2 C2 infrastructure — four listeners on a single host (2026-08-31)

## What it is
ThreatFox reported four command-and-control indicators for [[families/AdaptixC2]] on 2026-08-31, all pointing at the same IP address on four different ports. AdaptixC2 is a publicly available post-exploitation and command-and-control framework — the kind of tool an attacker installs *after* getting into a network, to keep a foothold and issue commands to compromised machines. A machine talking to one of these addresses is very likely already compromised, so these indicators are most useful as detection content for outbound network traffic rather than as something to patch.

## Affected products / versions
Not applicable — this is an IOC cluster, not a product vulnerability.

## ATT&CK mapping
- [[techniques/T1071.001]] — Application Layer Protocol: Web Protocols: three of the four listeners sit on 80, 443, and 8080, the ports AdaptixC2 HTTP/HTTPS beacons normally use to blend C2 traffic into ordinary web traffic. Inferred from the port numbers, not from observed protocol data — see Confidence notes.
- [[techniques/T1571]] — Non-Standard Port: the fourth listener is on 4444, a port with no legitimate web role, indicating C2 over a non-standard port on the same host.

## Observed IOCs

| type | value | context |
| --- | --- | --- |
| ip:port | 121.127.253.146:4444 | botnet_cc, ThreatFox confidence 100, first seen 2026-08-30 14:05:05 UTC |
| ip:port | 121.127.253.146:80 | botnet_cc, ThreatFox confidence 100, first seen 2026-08-30 13:05:07 UTC |
| ip:port | 121.127.253.146:8080 | botnet_cc, ThreatFox confidence 100, first seen 2026-08-30 13:05:07 UTC |
| ip:port | 121.127.253.146:443 | botnet_cc, ThreatFox confidence 100, first seen 2026-08-30 13:05:06 UTC |

VirusTotal on 121.127.253.146: 5 malicious, 2 suspicious, 50 harmless, 34 undetected. AbuseIPDB: abuse confidence 0%, 0 reports in the last 90 days.

## Severity assessment
**medium** — This is a URLhaus/ThreatFox family-day IOC cluster, which the rubric defaults to medium, and nothing here justifies raising it. Volume is small: four indicators that collapse to a single host, seen over roughly one hour on 2026-08-30, with no campaign, victim set, or delivery mechanism described in the source. There is no CVE, no KEV listing, and no exploitation claim to floor the rating higher. I did not apply the ransomware step-up: AdaptixC2 is a general post-exploitation framework rather than a ransomware family, and the source data says nothing about a ransomware operation using this infrastructure. Corroboration is real but thin — 5 VirusTotal engines call the IP malicious while 50 call it harmless, and AbuseIPDB has zero reports in 90 days, which is unremarkable for infrastructure first seen one day earlier. The counterweight keeping this out of the low band is what a hit means: outbound traffic to a C2 listener implies a host is already under attacker control, so the per-detection impact is high even though the observed scope is not.

## Confidence notes
**medium, flagged.** What the source supports directly: the four IP:port values, their `botnet_cc` threat type, the ThreatFox confidence of 100, the first-seen timestamps, and the attribution to the AdaptixC2 family. Everything else is inference and should be treated as such:

- The ATT&CK mappings are derived from the port numbers plus general knowledge of how AdaptixC2 listeners are configured, not from any observed traffic, sample, or protocol analysis in the source. Ports 80/443/8080 are strong but not conclusive evidence of HTTP/HTTPS beaconing, and a service on 4444 is not proof of C2 on that port beyond ThreatFox's own labeling.
- The description of AdaptixC2 as a post-exploitation C2 framework is well-established public knowledge about the family, not something the source data states.
- Every reference is `null`, so there is no reportable public write-up behind these indicators; the family attribution rests on the submitter's classification alone.
- No actors are named because the source names none, and mapping a shared open-source framework to a specific operator without corroboration would be a guess.
- The four indicators share one IP. Anyone blocking on this should note that the value here is the host, not four independent sightings, and that fresh C2 infrastructure like this is often short-lived.
