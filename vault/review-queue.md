---
title: Review Queue
type: dashboard
tags: [dashboard, review]
updated: 2026-07-16
---

# Review Queue — flagged low-confidence notes

Notes where Claude flagged uncertainty instead of guessing (per the low-confidence
rule in `skills/threat-analyst.md`). Review each, correct or confirm, then remove
`flagged: true` from the note's frontmatter; the next run drops it from this list.

- [[threats/2026-07-15-ScreenConnect-themed-malware-distribution-on-104.131.86.222-—-2-new-IOCs-(URLhaus,-2026-07-15)]] — confidence: medium
- [[threats/2026-07-15-AdaptixC2-C2-infrastructure-—-7-new-IOCs-(ThreatFox,-2026-07-15)]] — confidence: medium
