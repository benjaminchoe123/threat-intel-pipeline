---
title: Signal & Noise
permalink: /newsletter/
---

# Signal & Noise

A weekly threat report for people who run IT without a security team. Each issue answers one
question: *what happened this week that you might actually need to act on?* Plain English,
priorities in order, and an honest disclaimer when the week's data is thin.

Issues are drafted by this [open-source pipeline](https://github.com/benjaminchoe123/threat-intel-pipeline)
from public threat feeds. Every CVE and claim is checked against its source notes before
anything ships, and a week with too little data is held back rather than padded.

**Subscribe:** [RSS feed]({{ site.baseurl }}/feed.xml) — free, weekly, no account.

## Issues

{% for post in site.posts %}- [{{ post.title }}]({{ post.url | relative_url }}) — week ending {{ post.date | date: "%B %-d, %Y" }}
{% endfor %}
