---
title: Cobalt Strike C2 infrastructure — 32 indicators across nine hosts (2026-08-31)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-08-31
severity: high
confidence: medium
flagged: true
cve: []
family: [Cobalt Strike]
attack_techniques: [T1071.001]
actors: []
tags: [threat, threatfox, severity/high]
---

# Cobalt Strike C2 infrastructure — 32 indicators across nine hosts (2026-08-31)

## What it is
ThreatFox published 32 command-and-control indicators for [[families/Cobalt Strike]] in the 24 hours ending 2026-08-31. Cobalt Strike is a commercial red-team tool whose cracked and pirated builds are one of the most widely abused intrusion toolkits in the world; its "beacon" implant is what an attacker installs on a compromised machine to keep control of it and move deeper into a network. The indicators are nine server IP addresses (plus one reported domain) that beacons were seen calling home to, most of them exposing several listening ports each. For a defender the practical value is simple: outbound traffic from an internal host to any of these addresses should be treated as a probable active compromise, not as background noise.

## Affected products / versions
Not applicable — this is an infrastructure/IOC cluster, not a product vulnerability. Cobalt Strike beacons are platform-agnostic payloads delivered after an initial compromise; no specific vendor product is implicated by the source data.

## ATT&CK mapping
- [[techniques/T1071.001]] — Application Layer Protocol: Web Protocols: 20 of the 32 indicators are on HTTP/HTTPS-typical ports (80, 443, 8080, 8443, 8888, 4433), consistent with beacon traffic blending into ordinary web browsing. Supported by the observed ports plus well-established Cobalt Strike beacon behaviour; the source itself describes no traffic content.

No other technique is mapped. The source records only `botnet_cc` addresses and ports — there is no delivery, execution, or persistence detail to map against.

## Observed IOCs

| type | value | context |
|---|---|---|
| ip:port | 106.15.10.2:5672 | botnet_cc, confidence 100, first seen 2026-08-31 05:05 UTC |
| ip:port | 106.15.10.2:111 | botnet_cc, confidence 100, first seen 2026-08-31 04:05 UTC |
| ip:port | 106.15.10.2:4369 | botnet_cc, confidence 100, first seen 2026-08-31 04:05 UTC |
| ip:port | 101.42.136.73:8080 | botnet_cc, confidence 100, first seen 2026-08-31 01:05 UTC |
| ip:port | 216.203.20.232:443 | botnet_cc, confidence 50, first seen 2026-08-31 01:05 UTC |
| ip:port | 101.42.136.73:443 | botnet_cc, confidence 100, first seen 2026-08-31 01:05 UTC |
| ip:port | 196.251.121.183:4433 | botnet_cc, confidence 50, first seen 2026-08-31 01:05 UTC |
| ip:port | 150.158.102.111:5003 | botnet_cc, confidence 100, first seen 2026-08-31 00:05 UTC |
| ip:port | 101.42.136.73:80 | botnet_cc, confidence 75, first seen 2026-08-30 23:46 UTC |
| ip:port | 101.42.136.73:8443 | botnet_cc, confidence 75, first seen 2026-08-30 23:46 UTC |
| ip:port | 150.158.102.111:22 | botnet_cc, confidence 100, first seen 2026-08-30 23:05 UTC |
| ip:port | 150.158.102.111:8082 | botnet_cc, confidence 100, first seen 2026-08-30 23:05 UTC |
| ip:port | 150.158.102.111:85 | botnet_cc, confidence 100, first seen 2026-08-30 23:05 UTC |
| ip:port | 109.236.50.145:22 | botnet_cc, confidence 100, first seen 2026-08-30 23:05 UTC |
| ip:port | 150.158.102.111:80 | botnet_cc, confidence 100, first seen 2026-08-30 22:05 UTC |
| ip:port | 150.158.102.111:8080 | botnet_cc, confidence 100, first seen 2026-08-30 22:05 UTC |
| ip:port | 150.158.102.111:443 | botnet_cc, confidence 100, first seen 2026-08-30 22:05 UTC |
| ip:port | 104.168.102.116:22 | botnet_cc, confidence 100, first seen 2026-08-30 21:05 UTC |
| ip:port | 104.168.102.116:8080 | botnet_cc, confidence 100, first seen 2026-08-30 21:05 UTC |
| ip:port | 104.168.102.116:443 | botnet_cc, confidence 100, first seen 2026-08-30 21:05 UTC |
| ip:port | 104.168.102.116:80 | botnet_cc, confidence 100, first seen 2026-08-30 21:05 UTC |
| ip:port | 109.236.50.145:8443 | botnet_cc, confidence 100, first seen 2026-08-30 20:05 UTC |
| ip:port | 109.236.50.145:80 | botnet_cc, confidence 100, first seen 2026-08-30 20:05 UTC |
| ip:port | 109.236.50.145:8080 | botnet_cc, confidence 100, first seen 2026-08-30 20:05 UTC |
| ip:port | 109.236.50.145:8888 | botnet_cc, confidence 100, first seen 2026-08-30 20:05 UTC |
| ip:port | 109.236.50.145:443 | botnet_cc, confidence 100, first seen 2026-08-30 20:05 UTC |
| domain | check1.judicica1n | botnet_cc, confidence 75, first seen 2026-08-30 19:46 UTC |
| ip:port | 172.245.91.44:22 | botnet_cc, confidence 100, first seen 2026-08-30 08:05 UTC |
| ip:port | 185.195.65.180:443 | botnet_cc, confidence 50, first seen 2026-08-30 07:09 UTC |
| ip:port | 172.245.91.44:80 | botnet_cc, confidence 100, first seen 2026-08-30 06:05 UTC |
| ip:port | 172.245.91.44:8080 | botnet_cc, confidence 100, first seen 2026-08-30 06:05 UTC |
| ip:port | 172.245.91.44:443 | botnet_cc, confidence 100, first seen 2026-08-30 06:05 UTC |

Reputation context (not from ThreatFox): VirusTotal flags 106.15.10.2 as malicious by 13 engines (3 suspicious), 196.251.121.183 by 5, and 101.42.136.73 and 216.203.20.232 by 3 each. AbuseIPDB shows 0% abuse confidence for all four sampled addresses, with a single report against 106.15.10.2 in 90 days.

## Severity assessment
**high** — The rubric defaults an IOC-cluster note to medium, and two factors move it up. First, [[families/Cobalt Strike]] beacon infrastructure is routinely the staging layer for hands-on-keyboard intrusions that end in ransomware deployment, and the rubric raises a ransomware-associated family one step. Second, the volume and freshness support "an active, large-scale campaign": 32 indicators across nine distinct hosts inside a single day, 25 of them carrying ThreatFox confidence 100. Working against a higher rating, this is generic commodity C2 tracking rather than an attributed campaign against a named victim set, there is no CVE or exploitation chain in the source, and third-party reputation is thin — AbuseIPDB reports 0% abuse confidence for every sampled address, and only one of four sampled IPs has substantial VirusTotal detection. Critical is not defensible: there is no wormable or unauthenticated-RCE component here, only post-compromise control channels. High is the right rating for indicators that mean "an intrusion is already underway" if they appear in egress logs.

## Confidence notes
Medium, and flagged. What is directly from the source: every IOC value, port, threat type, per-IOC confidence level, and first-seen timestamp; the family label "Cobalt Strike"; the 32-indicator count.

What is inference and should be treated as such:

- **The severity uplift.** ThreatFox says only `botnet_cc`. The link between Cobalt Strike and ransomware intrusions is well-established public knowledge, not something this day's data shows. No ransomware family, actor, or victim appears in the source.
- **The ATT&CK mapping.** T1071.001 rests on the observed HTTP/HTTPS-family ports plus general beacon behaviour. No traffic content, profile, or malleable C2 detail was provided, so the mapping is behaviourally plausible rather than directly evidenced.
- **The non-web ports.** Several entries for hosts already listed on web ports sit on 22 (SSH), 111 (rpcbind), 4369 (Erlang EPMD), and 5672 (AMQP). Those are unlikely to be beacon channels; they more plausibly reflect other services listening on the same server, captured by whatever scanning fed the ThreatFox entry. Treat the host as the indicator and the non-web ports as host-attribution evidence, not as C2 channels to alert on individually.
- **The domain.** `check1.judicica1n` is recorded verbatim from the source. The trailing label is not a valid public TLD, so the entry may be malformed or truncated upstream; it was not corrected or expanded here, and it should be verified before being loaded into a blocklist.
- **Reputation disagreement.** Low AbuseIPDB scores and low VirusTotal detection on three of four sampled IPs are consistent with recently stood-up infrastructure that scanners have not caught up with, but they are equally consistent with false positives in the ThreatFox submission. This is not resolvable from the data given.
