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
      "classification_basis": "malicious_evidence | benign_evidence | insufficient_evidence | conflicting_evidence",
      "matched_patterns": [],
      "supporting_evidence": [],
      "contradicting_evidence": [],
      "blocking_gaps": [],
      "nonblocking_gaps": [],
      "missing_evidence": [],  # legacy alias
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
VALID_CLASSIFICATION_BASIS = frozenset({
    "malicious_evidence",
    "benign_evidence",
    "insufficient_evidence",
    "conflicting_evidence",
})

# Verdicts that must be backed by cited evidence. `inconclusive` and
# `needs_investigation` are honest "not enough" states and need no citation.
_CITATION_REQUIRED = frozenset({"tp", "fp"})

_LIST_FIELDS = (
    "matched_patterns",
    "supporting_evidence",
    "contradicting_evidence",
    "blocking_gaps",
    "nonblocking_gaps",
    "missing_evidence",
)

# String fields that downstream nodes (e.g. reassess_verdict) may attach to the
# contract dict.  Pass them through _coerce unchanged so they survive round-trips
# through parse_verdict.
_PASSTHROUGH_FIELDS = ("triage_verdict", "reassessment_reason", "demoted_from")

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

_NONBLOCKING_FOLLOWUP_GAP_RE = re.compile(
    r"initial access|source ip|network telemetry|connection attempt|callback|"
    r"authorization context|sudo authorization|cron executions|execution count|"
    r"lateral movement|broader scope|campaign|analyst correction|pattern|hash",
    re.IGNORECASE,
)

_CLASSIFICATION_BLOCKING_GAP_RE = re.compile(
    r"cannot distinguish|cannot classify|prevents classification|"
    r"persistence cannot be confirmed|cannot be confirmed or excluded|"
    r"malicious intent cannot be established|benign intent cannot be established",
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


def _trailing_json_object(text: str) -> dict | None:
    """Best-effort fallback for a final bare JSON object.

    The contract requires fenced JSON, but older runs may end with a raw object.
    Only accept an object that reaches the end of the string (aside from trailing
    whitespace), so prose examples earlier in the report are ignored.
    """
    decoder = json.JSONDecoder()
    for start in reversed([i for i, ch in enumerate(text) if ch == "{"]):
        try:
            obj, end = decoder.raw_decode(text[start:])
        except (json.JSONDecodeError, ValueError):
            continue
        if start + end != len(text.rstrip()):
            continue
        if isinstance(obj, dict) and "verdict" in obj:
            return obj
    return None


def _list_value(raw: dict, field: str) -> list:
    value = raw.get(field, [])
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if not isinstance(value, list):
        return [value]
    return value


def _coerce(raw: dict) -> dict:
    """Normalize a parsed object into the full contract shape with safe defaults."""
    verdict = str(raw.get("verdict", "")).strip().lower()
    verdict = _VERDICT_ALIASES.get(verdict, verdict)
    confidence = str(raw.get("confidence", "")).strip().lower()
    basis = str(raw.get("classification_basis", "") or "").strip().lower()

    out: dict = {
        "verdict": verdict,
        "confidence": confidence,
        "classification_basis": basis if basis in VALID_CLASSIFICATION_BASIS else "",
        "recommended_action": str(raw.get("recommended_action", "") or "").strip(),
    }
    for field in _LIST_FIELDS:
        out[field] = _list_value(raw, field)
    # Backward compatibility: older agents only emitted `missing_evidence`.
    # Classify those gaps without letting a mere count of open leads change TP/FP.
    if out["missing_evidence"] and "blocking_gaps" not in raw and "nonblocking_gaps" not in raw:
        out["blocking_gaps"] = [
            g for g in out["missing_evidence"] if _BLOCKING_GAP_RE.search(str(g))
        ]
        out["nonblocking_gaps"] = [
            g for g in out["missing_evidence"] if not _BLOCKING_GAP_RE.search(str(g))
        ]
    for field, valid in _ENUM_FIELDS:
        raw_val = str(raw.get(field, "") or "").strip().lower()
        out[field] = raw_val if raw_val in valid else "unknown"
    for field in _PASSTHROUGH_FIELDS:
        if field in raw:
            out[field] = raw[field]
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
        trailing = _trailing_json_object(text.rstrip())
        return _coerce(trailing) if trailing else None
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

    basis = v.get("classification_basis")
    if basis and basis not in VALID_CLASSIFICATION_BASIS:
        problems.append(
            f"classification_basis must be one of {sorted(VALID_CLASSIFICATION_BASIS)}, got {basis!r}"
        )
    if verdict == "tp" and basis != "malicious_evidence":
        problems.append("tp verdict requires classification_basis='malicious_evidence'")
    if verdict == "fp" and basis != "benign_evidence":
        problems.append("fp verdict requires classification_basis='benign_evidence'")

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


def normalize_followup_gaps(v: dict) -> dict:
    """Move known follow-up gaps out of `blocking_gaps` when proof is present.

    This is intentionally conservative: it only runs for cited TP/FP contracts
    whose `classification_basis` already matches the verdict. Gaps that say the
    activity cannot be classified, or that persistence/intent cannot be
    established, remain blocking.
    """
    verdict = v.get("verdict")
    if verdict not in ("tp", "fp"):
        return v
    expected_basis = "malicious_evidence" if verdict == "tp" else "benign_evidence"
    if v.get("classification_basis") != expected_basis or not v.get("supporting_evidence"):
        return v

    blocking = list(v.get("blocking_gaps") or [])
    if not blocking:
        return v

    kept: list = []
    moved: list = []
    for gap in blocking:
        text = str(gap)
        if _CLASSIFICATION_BLOCKING_GAP_RE.search(text):
            kept.append(gap)
        elif _NONBLOCKING_FOLLOWUP_GAP_RE.search(text):
            moved.append(gap)
        else:
            kept.append(gap)

    if not moved:
        return v

    out = dict(v)
    out["blocking_gaps"] = kept
    nonblocking = list(out.get("nonblocking_gaps") or [])
    for gap in moved:
        if gap not in nonblocking:
            nonblocking.append(gap)
    out["nonblocking_gaps"] = nonblocking
    return out


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
    """Demote tp/fp only when classification proof is absent or gaps block it.

    `missing_evidence` is retained as a legacy alias. Generic missing evidence is
    treated as nonblocking follow-up; blocking gaps must be explicit or match the
    legacy blocking-gap phrase list.
    """
    if v.get("verdict") not in ("fp", "tp"):
        return v, False
    verdict = v.get("verdict")
    basis = v.get("classification_basis") or ""
    expected_basis = "malicious_evidence" if verdict == "tp" else "benign_evidence"
    explicit_blocking = list(v.get("blocking_gaps") or [])
    legacy_blocking = [
        g for g in (v.get("missing_evidence") or [])
        if _BLOCKING_GAP_RE.search(str(g)) and g not in explicit_blocking
    ]
    blocking_gaps = explicit_blocking + legacy_blocking
    if basis == expected_basis and not blocking_gaps:
        return v, False

    demoted = dict(v)
    demoted["demoted_from"] = v.get("verdict")
    demoted["verdict"] = "needs_investigation"
    if blocking_gaps:
        demoted["blocking_gaps"] = blocking_gaps
        gaps_txt = ", ".join(str(g) for g in blocking_gaps)
        note = (
            f"Original verdict {v.get('verdict', '').upper()} demoted to NEEDS_INVESTIGATION: "
            f"blocking evidence gaps remain: {gaps_txt}."
        )
    else:
        note = (
            f"Original verdict {v.get('verdict', '').upper()} demoted to NEEDS_INVESTIGATION: "
            f"classification_basis must be {expected_basis!r}, got {basis or 'missing'!r}."
        )
    action = demoted.get("recommended_action") or ""
    demoted["recommended_action"] = (note + " " + action).strip() if action else note
    return demoted, True
