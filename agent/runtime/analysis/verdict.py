"""
Structured diagnosis verdict parsing and validation.

Both triage and investigation agents end their final message with a fenced JSON
verdict block (the diagnosis contract). This module extracts that block, validates
it against the contract, and enforces the citation policy: a `tp` or `fp` verdict
must cite at least one piece of supporting evidence, otherwise it is demoted to
`inconclusive`.

The contract:

    {
      "verdict": "tp | fp | inconclusive | needs_investigation",
      "confidence": "low | medium | high",
      "impact_state": "active | contained | unknown",
      "scope_state": "isolated | lateral_spread | unknown",
      "matched_patterns": [],
      "supporting_evidence": [],
      "contradicting_evidence": [],
      "missing_evidence": [],
      "recommended_action": ""
    }
"""
from __future__ import annotations

import json
import re

# Canonical verdict values in display order. `VALID_VERDICTS` is the membership
# set derived from it; use `VERDICT_ORDER` where presentation order matters.
VERDICT_ORDER = ("tp", "fp", "inconclusive", "needs_investigation")
VALID_VERDICTS = frozenset(VERDICT_ORDER)
VALID_CONFIDENCE = frozenset({"low", "medium", "high"})
VALID_IMPACT_STATE = frozenset({"active", "contained", "unknown"})
VALID_SCOPE_STATE = frozenset({"isolated", "lateral_spread", "unknown"})

# Verdicts that must be backed by cited evidence. `inconclusive` and
# `needs_investigation` are honest "not enough" states and need no citation.
_CITATION_REQUIRED = frozenset({"tp", "fp"})

_LIST_FIELDS = (
    "matched_patterns",
    "supporting_evidence",
    "contradicting_evidence",
    "missing_evidence",
)

_ENUM_FIELDS = (
    ("impact_state", VALID_IMPACT_STATE),
    ("scope_state", VALID_SCOPE_STATE),
)

# Matches ```json ... ``` or bare ``` ... ``` fenced blocks (non-greedy, multiline).
_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL | re.IGNORECASE)

# Gaps that block a confident verdict even in investigation mode (strict=False).
_BLOCKING_GAP_RE = re.compile(
    r"cannot rule out|no telemetry|unable to verify lateral|unconfirmed c2|"
    r"unknown persistence|missing log",
    re.IGNORECASE,
)


_VERDICT_ALIASES: dict[str, str] = {
    "benign": "fp",
    "false_positive": "fp",
    "false positive": "fp",
    "falsepositive": "fp",
    "not malicious": "fp",
    "legitimate": "fp",
    "true_positive": "tp",
    "true positive": "tp",
    "truepositive": "tp",
    "malicious": "tp",
    "attack": "tp",
    "compromised": "tp",
    "unknown": "inconclusive",
    "undetermined": "inconclusive",
    "unclear": "inconclusive",
    "insufficient evidence": "inconclusive",
    "investigate": "needs_investigation",
    "needs investigation": "needs_investigation",
}


def _coerce(raw: dict) -> dict:
    """Normalize a parsed object into the full contract shape with safe defaults."""
    verdict = str(raw.get("verdict", "")).strip().lower()
    verdict = _VERDICT_ALIASES.get(verdict, verdict)
    confidence = str(raw.get("confidence", "")).strip().lower()

    out: dict = {
        "verdict": verdict,
        "confidence": confidence,
        "recommended_action": str(raw.get("recommended_action", "") or "").strip(),
    }
    for field in _LIST_FIELDS:
        value = raw.get(field, [])
        if value is None:
            value = []
        elif isinstance(value, str):
            value = [value] if value.strip() else []
        elif not isinstance(value, list):
            value = [value]
        out[field] = value
    for field, valid in _ENUM_FIELDS:
        raw_val = str(raw.get(field, "") or "").strip().lower()
        out[field] = raw_val if raw_val in valid else "unknown"
    return out


def parse_verdict(text: str) -> dict | None:
    """Extract and normalize the verdict block from agent output.

    Scans fenced JSON blocks (last one wins, since the contract requires the
    verdict to be the final element) for an object carrying a `verdict` key.
    Returns the normalized contract dict, or None if no parseable verdict block
    is present.
    """
    if not text:
        return None

    candidates: list[dict] = []
    for match in _FENCE_RE.finditer(text):
        snippet = match.group(1)
        try:
            obj = json.loads(snippet)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(obj, dict) and "verdict" in obj:
            candidates.append(obj)

    if not candidates:
        return None
    # The contract puts the verdict last; honour the final valid block.
    return _coerce(candidates[-1])


def validate_verdict(v: dict) -> list[str]:
    """Return a list of contract violations. Empty list means valid."""
    problems: list[str] = []

    verdict = v.get("verdict")
    if verdict not in VALID_VERDICTS:
        problems.append(
            f"verdict must be one of {sorted(VALID_VERDICTS)}, got {verdict!r}"
        )

    confidence = v.get("confidence")
    if confidence not in VALID_CONFIDENCE:
        problems.append(
            f"confidence must be one of {sorted(VALID_CONFIDENCE)}, got {confidence!r}"
        )

    if verdict in _CITATION_REQUIRED and not v.get("supporting_evidence"):
        problems.append(
            f"{verdict!r} verdict requires non-empty supporting_evidence"
        )

    for field, valid in _ENUM_FIELDS:
        val = v.get(field)
        if val not in valid:
            problems.append(f"{field} must be one of {sorted(valid)}, got {val!r}")

    return problems


def citation_check(v: dict) -> bool:
    """True if the verdict satisfies the citation requirement.

    A `tp`/`fp` verdict must carry at least one supporting_evidence entry. All
    other verdicts pass trivially.
    """
    if v.get("verdict") in _CITATION_REQUIRED:
        return bool(v.get("supporting_evidence"))
    return True


def apply_citation_policy(v: dict) -> tuple[dict, bool]:
    """Demote an uncited tp/fp verdict to inconclusive.

    Returns (verdict, demoted). When demoted, the original verdict is preserved
    under `demoted_from` and a note is appended to the contract so the reason is
    visible downstream.
    """
    if citation_check(v):
        return v, False

    demoted = dict(v)
    demoted["demoted_from"] = v.get("verdict")
    demoted["verdict"] = "inconclusive"
    note = (
        f"Original verdict {v.get('verdict','').upper()} demoted to INCONCLUSIVE: "
        "no supporting evidence was cited."
    )
    action = demoted.get("recommended_action") or ""
    demoted["recommended_action"] = (action + " " + note).strip() if action else note
    return demoted, True


def apply_open_gaps_policy(v: dict, *, strict: bool = True) -> tuple[dict, bool]:
    """Demote a tp/fp verdict to needs_investigation when evidence gaps remain.

    strict=True (triage): any missing_evidence triggers demotion — triage is early-stage
    and should never close a case while acknowledging gaps.
    strict=False (investigation): only demote when ≥3 gaps exist or a gap names a blocking
    condition (lateral movement unverified, no C2 telemetry, etc.) — investigation always
    leaves some leads open and those alone should not invalidate a confident verdict.
    """
    if v.get("verdict") not in ("fp", "tp"):
        return v, False
    gaps = v.get("missing_evidence") or []
    if not gaps:
        return v, False
    if not strict:
        blocking = [g for g in gaps if _BLOCKING_GAP_RE.search(str(g))]
        if len(gaps) < 3 and not blocking:
            return v, False

    demoted = dict(v)
    demoted["demoted_from"] = v.get("verdict")
    demoted["verdict"] = "needs_investigation"
    gaps_txt = ", ".join(str(g) for g in gaps)
    note = (
        f"Original verdict {v.get('verdict', '').upper()} demoted to NEEDS_INVESTIGATION: "
        f"verdict declared with open evidence gaps: {gaps_txt}."
    )
    action = demoted.get("recommended_action") or ""
    demoted["recommended_action"] = (note + " " + action).strip() if action else note
    return demoted, True
