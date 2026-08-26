"""Automated draft verification: catch a wrong claim before it reaches GitHub
unattended, the way a human review used to be the only thing that did.

Two past incidents in this repo were caught by a human looking at output, not
by any test: the README's "flagship anecdote" was actually a mis-filed bug,
and EPSS scores of 0.99999 rendered as "100.0% probability" — a certainty the
model never claimed. This module is the automated stand-in for that human
catch when nobody is at the keyboard to publish.

FActScore-style, not SelfCheckGPT-style: this pipeline has real ground truth
for every report claim (the week's audit-logged, ATT&CK/EPSS/VT-validated
threat notes), so verification means checking claims against that reference,
not sampling the model against itself.
"""

import json
import re

from . import enrich

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def extract_entities(draft_text):
    """Structured IDs cited in the draft — the only entities with a fixed
    enough shape to check without semantic judgment. See the deviation note
    in the plan for why family names and severity aren't handled here."""
    return {
        "cve": set(CVE_RE.findall(draft_text)),
        "attack_techniques": set(ATTACK_ID_RE.findall(draft_text)),
    }


def check_entities(entities, week_notes):
    """Every cited CVE/ATT&CK ID must trace to one of this week's real notes."""
    known_cves = set()
    known_techniques = set()
    for note in week_notes:
        known_cves.update(note.get("cve") or [])
        known_techniques.update(str(t) for t in (note.get("attack_techniques") or []))

    mismatches = []
    for cve in sorted(entities["cve"] - known_cves):
        mismatches.append(f"draft cites {cve}, which is not in any of this week's notes")
    for tid in sorted(entities["attack_techniques"] - known_techniques):
        mismatches.append(f"draft cites {tid}, which is not in any of this week's notes")
    return mismatches


CLAIM_VERIFICATION_PROMPT = """You are fact-checking a draft weekly threat intelligence \
report against the source threat notes it was supposed to be drafted from. Identify the \
report's substantive claims (recommendations, "what changed" statements, severity framing, \
any other assertion beyond a bare structured ID) and judge whether each is directly \
supported by the source notes below.

<source-notes count="{count}">
{notes_blob}
</source-notes>

<draft-report>
{draft_text}
</draft-report>

Return ONLY a JSON array, no markdown fence, no commentary. Each element:
{{"claim": "<the atomic claim, quoted or closely paraphrased from the report>", \
"supported": true or false, "reason": "<one sentence: what supports it, or why it doesn't>"}}

If the report makes no claims beyond what the source notes already state, return []."""


ADVICE_HEADING = "## What a small organization should actually do"

#: A single verification pass was observed to flag different subsets of the same
#: draft on different runs -- one claim passed rounds 1-8 and was rejected on
#: round 9. One pass therefore certifies "passed this roll of the dice", not
#: "passed". Running N passes and failing on the union of their objections is
#: strictly stricter than one pass, and makes a green result mean something
#: stable enough to publish on unattended.
VERIFICATION_ROUNDS = 3


def split_advice_section(draft_text):
    """Split the draft into (factual_text, advice_text).

    The two halves get different questions asked of them. Everything except the
    recommendations section is a factual claim about the week and must trace to
    the notes. The recommendations section is analyst judgement and is checked
    for invented fact and contradiction instead -- see ADVICE_VERIFICATION_PROMPT.

    A draft with no recommendations section is entirely factual, which is also
    exactly what a report looks like after someone strips the advice by hand to
    get it past the old gate.
    """
    start = draft_text.find(ADVICE_HEADING)
    if start == -1:
        return draft_text, ""

    rest = draft_text[start + len(ADVICE_HEADING):]
    next_heading = rest.find("\n## ")
    if next_heading == -1:
        advice = draft_text[start:]
        tail = ""
    else:
        advice = draft_text[start:start + len(ADVICE_HEADING) + next_heading]
        tail = rest[next_heading:]

    factual = draft_text[:start] + tail.lstrip("\n")
    return factual, advice


ADVICE_VERIFICATION_PROMPT = """You are reviewing the recommendations section of a weekly \
threat intelligence report against the source threat notes the report was drafted from.

This section exists to carry an analyst's judgement about what a reader should do. Its \
recommendations are EXPECTED to go beyond anything the notes state outright — that is the \
section's whole purpose — so a recommendation is not defective merely for being absent from \
the notes.

Judge a recommendation UNSOUND ("supported": false) if ANY of these hold:
- it asserts a fact the notes do not carry: a count, a date, a remediation deadline, a CVE \
ID, a version number, an exploitation status, a vendor statement, a volume or scale figure;
- it contradicts something the notes say;
- it tells the reader to act on a product, service or platform that this week's notes never \
mention;
- it states something about the world in absolute terms that is simply false ("no legitimate \
site ever asks you to run a command");
- the action it prescribes would not actually reduce exposure to the threat it cites.

Otherwise judge it SOUND ("supported": true) — including when it is ordinary, well-established \
security practice that the notes never spell out.

<source-notes count="{count}">
{notes_blob}
</source-notes>

<recommendations-section>
{draft_text}
</recommendations-section>

Return ONLY a JSON array, no markdown fence, no commentary. Each element:
{{"claim": "<the atomic recommendation, quoted or closely paraphrased>", \
"supported": true or false, "reason": "<one sentence: why it is sound, or which rule above \
it breaks>"}}

If the section makes no recommendations, return []."""


class VerificationError(RuntimeError):
    """The verification call did not return a usable result.

    Raised, never swallowed into a default pass — a broken checker must look
    like a failed check, not like a clean one."""


def extract_and_verify_claims(draft_text, week_notes, runner=enrich.run_claude,
                              prompt_template=CLAIM_VERIFICATION_PROMPT):
    notes_blob = "\n\n---\n\n".join(n["_body"] for n in week_notes)
    prompt = prompt_template.format(
        count=len(week_notes), notes_blob=notes_blob, draft_text=draft_text
    )
    response_text, _ = runner(prompt)
    text = enrich._strip_code_fence(response_text)
    try:
        claims = json.loads(text)
    except json.JSONDecodeError as e:
        raise VerificationError(f"claim verification response was not valid JSON: {e}") from e
    if not isinstance(claims, list):
        raise VerificationError("claim verification response was not a JSON array")

    results = []
    for c in claims:
        if not isinstance(c, dict) or "claim" not in c or "supported" not in c:
            raise VerificationError(f"malformed claim entry: {c!r}")
        if not isinstance(c["supported"], bool):
            supported_type = type(c["supported"]).__name__
            raise VerificationError(
                f"malformed claim entry: 'supported' must be a boolean, "
                f"got {supported_type}"
            )
        results.append({
            "claim": c["claim"],
            "supported": c["supported"],
            "reason": c.get("reason", ""),
        })
    return results


def _union_objections(rounds):
    """Merge N rounds of claim results, failing on the union of their objections.

    A claim any round objected to is objected to. This is deliberately one-sided:
    the flaky round is the one that noticed something, not the one that was wrong,
    so a disagreement between rounds resolves against publishing.
    """
    objected = {}
    accepted = {}
    for results in rounds:
        for c in results:
            target = accepted if c["supported"] else objected
            target.setdefault(c["claim"], c["reason"])

    merged = [{"claim": k, "supported": False, "reason": v} for k, v in objected.items()]
    merged += [{"claim": k, "supported": True, "reason": v}
               for k, v in accepted.items() if k not in objected]
    return merged


def verify_claims_repeated(draft_text, week_notes, runner=enrich.run_claude,
                           prompt_template=CLAIM_VERIFICATION_PROMPT,
                           rounds=VERIFICATION_ROUNDS):
    """Run the claim check `rounds` times and fail on the union of objections."""
    return _union_objections([
        extract_and_verify_claims(draft_text, week_notes, runner=runner,
                                  prompt_template=prompt_template)
        for _ in range(rounds)
    ])


class VerificationResult:
    def __init__(self, passed, entity_mismatches, claim_results, advice_results=None,
                 error=None):
        self.passed = passed
        self.entity_mismatches = entity_mismatches
        self.claim_results = claim_results
        self.advice_results = advice_results or []
        self.error = error

    def report(self):
        lines = []
        if self.error:
            lines.append(f"verification call failed: {self.error}")
        for m in self.entity_mismatches:
            lines.append(f"ENTITY MISMATCH: {m}")
        for c in self.claim_results:
            if not c["supported"]:
                lines.append(f"UNSUPPORTED CLAIM: {c['claim']} ({c['reason']})")
        for c in self.advice_results:
            if not c["supported"]:
                lines.append(f"UNSOUND RECOMMENDATION: {c['claim']} ({c['reason']})")
        if not lines:
            lines.append(
                "verification passed: all cited IDs and claims are supported by "
                "this week's notes."
            )
        return "\n".join(lines)


def verify(draft_text, week_notes, runner=enrich.run_claude):
    entities = extract_entities(draft_text)
    mismatches = check_entities(entities, week_notes)
    factual_text, advice_text = split_advice_section(draft_text)
    try:
        claim_results = verify_claims_repeated(
            factual_text, week_notes, runner=runner,
            prompt_template=CLAIM_VERIFICATION_PROMPT,
        )
        # An empty advice section is not worth a verification call, let alone
        # VERIFICATION_ROUNDS of them.
        advice_results = verify_claims_repeated(
            advice_text, week_notes, runner=runner,
            prompt_template=ADVICE_VERIFICATION_PROMPT,
        ) if advice_text.strip() else []
    except Exception as e:
        # Any failure while getting claim results -- not just a malformed-response
        # VerificationError, but a runner exception too (e.g. enrich.EnrichmentError
        # on a subprocess timeout/non-zero exit/is_error payload) -- must look like a
        # failed check, never an uncaught crash that skips the audit trail. This holds
        # for every round, not just the first: one broken round fails the whole check.
        return VerificationResult(
            passed=False, entity_mismatches=mismatches, claim_results=[], error=str(e)
        )
    unsupported = [c for c in claim_results + advice_results if not c["supported"]]
    passed = not mismatches and not unsupported
    return VerificationResult(passed=passed, entity_mismatches=mismatches,
                               claim_results=claim_results, advice_results=advice_results)
