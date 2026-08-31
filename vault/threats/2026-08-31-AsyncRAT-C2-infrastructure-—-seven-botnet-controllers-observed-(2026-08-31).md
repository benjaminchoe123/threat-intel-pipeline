---
title: AsyncRAT C2 infrastructure — seven botnet controllers observed (2026-08-31)
type: threat
source: threatfox
source_url: https://threatfox.abuse.ch/
date: 2026-08-31
severity: medium
confidence: medium
flagged: true
cve: []
family: [AsyncRAT]
attack_techniques: [T1571, T1219]
actors: []
tags: [threat, threatfox, severity/medium]
---

# AsyncRAT C2 infrastructure — seven botnet controllers observed (2026-08-31)

## What it is
ThreatFox reported seven command-and-control endpoints for [[families/AsyncRAT]], all first
seen on 2026-08-30. Each entry is an IP address plus a specific port that infected machines
call home to; the operator uses that channel to issue commands to the victim computer.
[[families/AsyncRAT]] is a widely reused, openly available remote access tool, so these are
almost certainly several unrelated operators rather than one campaign. This matters as a
blocklist and detection-hunting input: if a machine on the network connects to one of these
IP/port pairs, treat it as a likely active infection.

## Affected products / versions
Not applicable — this is an IOC cluster describing attacker infrastructure, not a
vulnerability in a product.

## ATT&CK mapping
- [[techniques/T1571]] — Non-Standard Port: every observed controller listens on an
  arbitrary high or unusual port (1217, 5812, 972, 5555, 2414, 50, 8808) rather than a
  service-standard port, which is directly visible in the source data.
- [[techniques/T1219]] — Remote Access Tools: the source classifies these as
  `botnet_cc` for [[families/AsyncRAT]], a remote access tool. This mapping rests on
  what [[families/AsyncRAT]] is known to be, not on behavior described in the source —
  see Confidence notes.

## Observed IOCs

| type | value | context |
| --- | --- | --- |
| ip:port | 112.213.103.17:1217 | botnet_cc, confidence 75, first seen 2026-08-30 23:50:19 UTC; tied to MalwareBazaar sample `f6f7dbd6561e7ee6ba7e6abffdb1e5de01bf511318aade34825d888e99db645f` |
| ip:port | 112.213.103.58:5812 | botnet_cc, confidence 75, first seen 2026-08-30 23:50:19 UTC; tied to MalwareBazaar sample `9109d9bd117f540aed9afa6f293c1396cc18ed979056eadca97c69e3f957c14d` |
| ip:port | 91.219.239.81:972 | botnet_cc, confidence 75, first seen 2026-08-30 19:46:33 UTC; no reference sample |
| ip:port | 160.119.69.30:5555 | botnet_cc, confidence 75, first seen 2026-08-30 19:43:51 UTC; no reference sample |
| ip:port | 80.190.77.86:2414 | botnet_cc, confidence 75, first seen 2026-08-30 09:47:12 UTC; no reference sample |
| ip:port | 64.177.112.21:50 | botnet_cc, confidence 75, first seen 2026-08-30 09:47:00 UTC; no reference sample |
| ip:port | 188.212.158.203:8808 | botnet_cc, confidence 100, first seen 2026-08-30 06:05:05 UTC; no reference sample |

Two of the seven addresses (112.213.103.17 and 112.213.103.58) sit in the same /24 and were
reported in the same minute against different samples, which is consistent with one operator
using adjacent hosting.

## Severity assessment
**medium** — Per the rubric, ThreatFox family-day IOC aggregates default to medium unless
volume or an association with a specific campaign justifies raising it. Neither applies here:
seven indicators across seven distinct hosts in one day is routine commodity-malware
distribution for [[families/AsyncRAT]], and the source names no actor or campaign. There is
no CVE and no KEV listing, so the KEV floor does not apply, and nothing in the source ties
this cluster to ransomware, so the ransomware step-up does not apply either. Reputation data
supports rather than raises the rating: VirusTotal shows only mild consensus on the four IPs
checked (3–6 malicious engines each, against 48–54 harmless), and AbuseIPDB has 0% abuse
confidence and zero reports in 90 days for all four — typical of infrastructure first seen
roughly one day earlier and not yet widely reported. The practical impact of any single
confirmed hit is high (full remote control of the host), but the exposure this note describes
is narrow: these are blockable endpoints, not an exploitable weakness in software the
organization runs.

## Confidence notes
Medium. The IOC values, ports, threat type, first-seen times, per-IOC confidence levels, and
the two MalwareBazaar sample references are all taken directly from the source, as is the
family attribution. Two things go beyond it. First, [[techniques/T1219]] is derived from
[[families/AsyncRAT]] being a remote access tool by public reputation — the source data
describes no observed behavior, only C2 endpoints — so that mapping is family-name inference,
which is why this note is flagged and confidence is capped at medium.
[[techniques/T1571]] is the only mapping the source data itself supports. Second, the
statement that these endpoints likely belong to several unrelated operators, and the reading
of the two 112.213.103.0/24 addresses as one operator's adjacent hosting, are analyst
inference from the shape of the data, not source claims. Five of the seven IOCs carry no
reference sample, so for those there is no linked evidence connecting the endpoint to
[[families/AsyncRAT]] beyond ThreatFox's own 75% confidence rating. The low AbuseIPDB scores
should not be read as evidence of benignity given how recent the indicators are.
