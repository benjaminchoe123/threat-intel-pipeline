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


class VerificationError(RuntimeError):
    """The verification call did not return a usable result.

    Raised, never swallowed into a default pass — a broken checker must look
    like a failed check, not like a clean one."""


def extract_and_verify_claims(draft_text, week_notes, runner=enrich.run_claude):
    notes_blob = "\n\n---\n\n".join(n["_body"] for n in week_notes)
    prompt = CLAIM_VERIFICATION_PROMPT.format(
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


class VerificationResult:
    def __init__(self, passed, entity_mismatches, claim_results, error=None):
        self.passed = passed
        self.entity_mismatches = entity_mismatches
        self.claim_results = claim_results
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
        if not lines:
            lines.append(
                "verification passed: all cited IDs and claims are supported by "
                "this week's notes."
            )
        return "\n".join(lines)


def verify(draft_text, week_notes, runner=enrich.run_claude):
    entities = extract_entities(draft_text)
    mismatches = check_entities(entities, week_notes)
    try:
        claim_results = extract_and_verify_claims(draft_text, week_notes, runner=runner)
    except VerificationError as e:
        return VerificationResult(
            passed=False, entity_mismatches=mismatches, claim_results=[], error=str(e)
        )
    unsupported = [c for c in claim_results if not c["supported"]]
    passed = not mismatches and not unsupported
    return VerificationResult(passed=passed, entity_mismatches=mismatches,
                               claim_results=claim_results)
