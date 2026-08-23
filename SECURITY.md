# Security policy

This is a personal, non-commercial research project. It has no users to protect and no
production deployment, so there is no formal SLA here — but reports are genuinely welcome and
will be acted on.

## Reporting a vulnerability in the code

Use GitHub's **[private vulnerability reporting](https://github.com/benjaminchoe123/threat-intel-pipeline/security/advisories/new)**
(Security tab → Report a vulnerability). That keeps the report private until there's a fix.

Please don't open a public issue for something exploitable. For everything non-sensitive —
bugs, wrong analysis, broken links — a normal issue is perfect.

Expect a reply within about a week. I'm a full-time student; this is not a staffed inbox.

## What's in scope

The pipeline code: feed ingestion and parsing, the enrichment path and its schema validation,
the report verification gate, the approval-gated publish path, and anything that writes to the
vault or executes on a schedule.

Things I'd especially like to hear about:

- A way to get unvalidated model output past `verify_report` and into a published report.
- A malformed or hostile feed entry that escapes quarantine and corrupts the vault or the
  state database.
- Path traversal or injection through feed-controlled fields — indicator values and threat
  titles become filenames, and that is exactly the kind of thing that goes wrong quietly.
- Anything that could cause the scheduled task to execute attacker-controlled input.

## What's out of scope

- The upstream feeds themselves — report those to CISA or abuse.ch.
- Missing hardening on a component that is documented as not-yet-built (see the README's
  limitations section).
- Findings that depend on already having write access to the machine running the pipeline.

## Secrets

No credentials belong in this repository. `.env` is gitignored, `.env.example` documents the
required keys with placeholder values, and CI runs **gitleaks over the full commit history** on
every push — not just the tip — because deleting a commit does not un-leak a key.

If you ever spot a live credential in this repo or its history, please report it privately via
the link above rather than opening an issue.

## Indicator takedown and correction requests

This repository republishes indicators of compromise collected from public threat feeds. Hosts
listed here are often compromised third parties rather than malicious actors, and indicators go
stale as infrastructure is cleaned up.

If you own an indicator listed here, or you find a factual error in a threat note, open an issue
or use the private reporting link. Removal and correction requests are honored — you do not need
to prove anything to me first. See [DATA-SOURCES.md](DATA-SOURCES.md) for provenance and
handling guidance.
