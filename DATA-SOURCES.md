# Data sources, licensing, and handling

This repository does two different things with two different legal characters, and it is worth
separating them plainly:

- **The code** (`pipeline/`, `tests/`, `scripts/`) is mine, released under the [MIT License](LICENSE).
- **The published vault** (`vault/threats/`, `vault/docs/stix/`, `vault/reports/`) is *derived
  from third-party threat feeds*. The MIT license does not and cannot relicense that data. Each
  upstream source keeps its own terms, listed below.

This project is a **non-commercial student portfolio and learning exercise**. Nothing here is
sold, and no feed data is offered as a commercial product or service.

## Sources

### CISA Known Exploited Vulnerabilities (KEV) catalog

- **Used for:** actively-exploited CVEs, remediation due dates, KEV membership.
- **Terms:** public domain. The catalog is a work of the U.S. federal government and CISA
  publishes the data repository under **CC0** — universal public domain dedication, no
  restrictions on reuse or redistribution.
- <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>

### abuse.ch — ThreatFox, URLhaus, MalwareBazaar

- **Used for:** IOC clusters (C2 infrastructure, payload hashes, malware distribution URLs) and
  malware family labels.
- **Terms:** **not** an open license. abuse.ch (now operated under Spamhaus Technology) makes
  the API available free of charge under its *fair use principles* for non-commercial use;
  companies, networks, or individuals with commercial or for-profit needs may require a paid
  commercial API subscription. Access requires a free registered Auth-Key.
- This project relies on the non-commercial fair-use path. If you fork this and put it to
  commercial use, that is your obligation to resolve with abuse.ch, not something this
  repository's MIT license grants you.
- Policies: [ThreatFox](https://threatfox.abuse.ch/faq/#policy) ·
  [URLhaus](https://urlhaus.abuse.ch/api/#policy) ·
  [MalwareBazaar](https://bazaar.abuse.ch/api/#policy)

### malware-traffic-analysis.net

- **Used for:** blog RSS, as narrative context for traffic-analysis writeups.
- **Terms:** the site's posts and packet captures are the author's own work. This project links
  to and summarizes posts; it does not mirror captures or republish post content wholesale.
- <https://www.malware-traffic-analysis.net/>

### MITRE ATT&CK

- **Used for:** technique IDs and names, and the generated Navigator layer.
- **Terms:** ATT&CK is available for use under MITRE's terms, which permit reuse with
  attribution. © 2026 The MITRE Corporation. This project is not affiliated with or endorsed
  by MITRE.
- <https://attack.mitre.org/>

## Handling: this repository contains live malicious indicators

`vault/threats/` and `vault/docs/stix/` contain **real, in-the-wild indicators** — C2 IP
addresses and ports, malware distribution URLs, and payload hashes — collected from public
feeds. Treat them accordingly:

- Do not resolve, browse to, or fetch anything listed here from a machine you care about.
- Indicators are recorded as published by the upstream feed. Presence in this repository is
  **not** an accusation against any host, network, or registrant — hosts are frequently
  compromised third parties, and indicators go stale as infrastructure is remediated.
- Reputation and enrichment context reflect a point in time. Re-check before acting on
  anything here operationally.

## Accuracy, and how to get something corrected

Notes in `vault/threats/` are drafted by an automated pipeline that uses an LLM to enrich each
item, validated against a schema, and — for anything published as a weekly report — reviewed by
a human before release. That process is designed to make unsupported claims fail loudly rather
than pass quietly, but it is not infallible.

If you are the owner of an indicator listed here, or you find a factual error, open an issue or
see [SECURITY.md](SECURITY.md) for contact. Removal and correction requests are honored.
