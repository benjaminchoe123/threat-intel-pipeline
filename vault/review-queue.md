---
title: Review Queue
type: dashboard
tags: [dashboard, review]
updated: 2026-07-15
---

# Review Queue — flagged low-confidence notes

Notes where Claude flagged uncertainty instead of guessing (per the low-confidence
rule in `skills/threat-analyst.md`). Review each, correct or confirm, then remove
`flagged: true` from the note's frontmatter; the next run drops it from this list.

- [[threats/2026-07-15-Empty-MTA-feed-item-—-no-source-data-received-(ingestion-failure-suspected)]] — confidence: low
