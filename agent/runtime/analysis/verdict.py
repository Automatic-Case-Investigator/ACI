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
    r"successful authenticated session|post-login|process execution|execution telemetry|"
    r"shell-launch|persistence|c2|command and control|exfiltration|file-transfer|impact|"
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


# Verdicts that affirmatively clear a case as not-a-threat. These cannot stand
# when the run already escalated an active compromise or was cut short before
# finishing — both contradict a confident "benign" conclusion.
_CLEARING_VERDICTS = frozenset({"fp"})


def apply_completeness_floor(
    v: dict, *, escalation_posted: bool = False, over_budget: bool = False
) -> tuple[dict, bool]:
    """Floor a case-clearing verdict the run is not entitled to assert.

    Two integrity rules, both flooring an `fp` to `needs_investigation`:

    - **escalation_posted** — an active-compromise alert was posted to the case
      during this run (a cited, active-compromise ## Findings fact). A benign
      verdict directly contradicts that, so it must not be the final answer.
    - **over_budget** — the run exhausted its step/call budget before completing.
      An incomplete run cannot affirmatively clear a case as benign.

    A `tp` is left untouched in both cases: escalation is consistent with TP, and
    finding malice on partial budget is still a valid finding. `inconclusive` /
    `needs_investigation` already hold for analyst review and are left untouched.

    Idempotent: re-applying to an already-floored verdict is a no-op. Returns
    (verdict, floored).
    """
    verdict = v.get("verdict")
    if verdict not in _CLEARING_VERDICTS:
        return v, False
    reasons: list[str] = []
    if escalation_posted:
        reasons.append("an active-compromise escalation was posted during this run")
    if over_budget:
        reasons.append("the run exhausted its budget before completing")
    if not reasons:
        return v, False

    floored = dict(v)
    floored["demoted_from"] = verdict
    floored["verdict"] = "needs_investigation"
    note = (
        f"Original verdict {verdict.upper()} floored to NEEDS_INVESTIGATION: "
        + "; ".join(reasons) + "."
    )
    floored["reassessment_reason"] = note
    action = floored.get("recommended_action") or ""
    floored["recommended_action"] = (note + " " + action).strip() if action else note
    return floored, True


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


# ---------------------------------------------------------------------------
# Verdict-aware gap classification + offensive-close floor + unified pipeline.
#
# The pre-existing policies above are verdict-blind: they treat a "downstream
# success / lateral / initial-access" gap as non-blocking follow-up regardless of
# whether the verdict is TP or FP. That is correct for a TP (those are scoping
# gaps) but wrong for an FP, where those are the exact checks that would OVERTURN
# the benign call. The functions below make the classification verdict-aware and
# add a floor for a benign close of an offensive alert whose success was never
# ruled out. `apply_verdict_integrity` runs the whole ordered pipeline in one place.
# ---------------------------------------------------------------------------

# An alert whose signature is itself an offensive action (scan/recon/brute/exploit),
# where "no observed success" is absence-of-proof, NOT positive benign evidence.
# Derived from the verdict's own matched_patterns / supporting_evidence / action text.
_OFFENSIVE_ALERT_RE = re.compile(
    r"\bscan(ning|ner)?\b|recon|probe|brute[\s-]?force|initial access|exploit|"
    r"web_scan|vulnerability scan|\bnmap\b|wpscan|t1595|t1190|t1110|t1078|t1046",
    re.IGNORECASE,
)

# Gaps that would OVERTURN a benign verdict if resolved (blocking for FP), but are
# merely downstream follow-up scoping for a TP (nonblocking).
_OFFENSIVE_DOWNSTREAM_GAP_RE = re.compile(
    r"success|follow-?on|follow[\s-]?up activity|logged[\s-]?in|authenticat|post-scan|"
    r"downstream|lateral|initial access|got in|succeed|execution|persistence|"
    r"callback|command and control|\bc2\b|exfil",
    re.IGNORECASE,
)

# Text showing the run actually ADDRESSED downstream success (positive result or a
# confirmed negative) — its presence means success was not simply ignored.
_SUCCESS_ADDRESSED_RE = re.compile(
    r"success|authenticat|logged[\s-]?in|200 ok|established|executed|"
    r"valid credential|session opened|accepted|no .*(login|access|auth)",
    re.IGNORECASE,
)

# Positive benign justification that legitimately supports an FP on an offensive alert.
_BENIGN_JUSTIFICATION_RE = re.compile(
    r"authorized|approved|expected|sanctioned|whitelist|known[\s-]?good|known scanner|"
    r"legitimate|administrative|maintenance window|internal (scanner|scan)|"
    r"security team|pentest|penetration test|vulnerability management|scheduled scan",
    re.IGNORECASE,
)


def _verdict_text(v: dict) -> str:
    """Flatten the verdict fields that describe what was matched/observed."""
    parts = list(v.get("matched_patterns") or []) + list(v.get("supporting_evidence") or [])
    parts.append(str(v.get("recommended_action") or ""))
    return " ".join(str(p) for p in parts)


def is_offensive_alert(v: dict) -> bool:
    """True if the verdict describes an offensive-action alert (scan/recon/brute/exploit)."""
    return bool(_OFFENSIVE_ALERT_RE.search(_verdict_text(v)))


def classify_fp_gaps(v: dict) -> tuple[dict, bool]:
    """Verdict-aware gap classification for an FP.

    A downstream-success / lateral / initial-access / execution / callback gap is the
    exact check that would OVERTURN a benign verdict, so for an ``fp`` it is BLOCKING —
    the opposite of its follow-up (nonblocking) role under a ``tp``. Promote any such gap
    out of ``nonblocking_gaps`` / ``missing_evidence`` into ``blocking_gaps`` so the
    open-gaps policy then demotes an unearned FP to ``needs_investigation``. No-op for
    non-FP verdicts. Returns (verdict, changed).
    """
    if v.get("verdict") != "fp":
        return v, False
    blocking = list(v.get("blocking_gaps") or [])
    keep_nonblocking: list = []
    promoted: list = []
    for gap in (v.get("nonblocking_gaps") or []):
        if _OFFENSIVE_DOWNSTREAM_GAP_RE.search(str(gap)):
            promoted.append(gap)
        else:
            keep_nonblocking.append(gap)
    for gap in (v.get("missing_evidence") or []):
        if _OFFENSIVE_DOWNSTREAM_GAP_RE.search(str(gap)) and gap not in promoted:
            promoted.append(gap)
    promoted = [g for g in promoted if g not in blocking]
    if not promoted:
        return v, False
    out = dict(v)
    out["nonblocking_gaps"] = keep_nonblocking
    out["blocking_gaps"] = blocking + promoted
    return out, True


def apply_success_verification_floor(v: dict, *, offensive_alert: bool) -> tuple[dict, bool]:
    """Floor a benign close of an OFFENSIVE alert that never ruled out success.

    An ``fp`` on a scan/recon/brute/exploit alert must rest on positive benign evidence
    (authorized / known-scanner / maintenance) OR a downstream success check (a positive
    result or a confirmed negative). "We saw the scan and no success" is absence-of-proof,
    not proof of benign. When neither is present, floor ``fp -> needs_investigation`` so an
    unverified benign close cannot auto-close the case. No-op for non-FP or non-offensive
    alerts. Idempotent. Returns (verdict, floored).
    """
    if v.get("verdict") != "fp" or not offensive_alert:
        return v, False
    text = _verdict_text(v)
    if _BENIGN_JUSTIFICATION_RE.search(text) or _SUCCESS_ADDRESSED_RE.search(text):
        return v, False
    floored = dict(v)
    floored["demoted_from"] = "fp"
    floored["verdict"] = "needs_investigation"
    note = (
        "Original verdict FP floored to NEEDS_INVESTIGATION: benign close on an offensive "
        "(scan/recon/exploit) alert without positive benign evidence or a downstream success "
        "check — the source's success was never ruled out."
    )
    floored["reassessment_reason"] = note
    action = floored.get("recommended_action") or ""
    floored["recommended_action"] = (note + " " + action).strip() if action else note
    return floored, True


def apply_verdict_integrity(
    v: dict,
    *,
    strict: bool,
    escalation_posted: bool = False,
    over_budget: bool = False,
    offensive_alert: bool | None = None,
    classify_gaps: bool = True,
) -> tuple[dict, list[tuple[str, str]]]:
    """Single ordered verdict-integrity pipeline shared by every verdict node.

    Runs, in order:
      1. citation           — uncited tp/fp -> inconclusive
      2. gap classification — tp: relieve follow-up gaps (nonblocking);
                              fp: promote overturning gaps (blocking)
      3. open-gaps          — demote a tp/fp with blocking gaps or a mismatched basis
      4. success floor      — fp on an offensive alert w/o benign proof -> needs_investigation
      5. completeness floor — escalated / over-budget fp -> needs_investigation

    Returns ``(verdict, notes)`` where ``notes`` is a list of ``(emit_kind, message)``
    for the caller to surface. Idempotent, so ``publish_finish`` can safely re-run it on
    a reassess-resolved verdict that bypassed the pipeline.
    """
    notes: list[tuple[str, str]] = []
    verdict = v
    if offensive_alert is None:
        offensive_alert = is_offensive_alert(verdict)

    verdict, demoted = apply_citation_policy(verdict)
    if demoted:
        notes.append((
            "note",
            f"verdict {verdict.get('demoted_from', '').upper()} demoted to "
            "INCONCLUSIVE — no supporting evidence cited",
        ))

    if classify_gaps:
        current = verdict.get("verdict")
        if current == "tp":
            normalized = normalize_followup_gaps(verdict)
            if (
                normalized is not verdict
                and normalized.get("blocking_gaps") != verdict.get("blocking_gaps")
            ):
                notes.append(("note", "verdict contract: moved follow-up gaps to nonblocking_gaps"))
            verdict = normalized
        elif current == "fp":
            verdict, promoted = classify_fp_gaps(verdict)
            if promoted:
                notes.append((
                    "note",
                    "verdict contract: promoted overturning gaps (unconfirmed success / "
                    "lateral / execution) to blocking_gaps for FP",
                ))

    verdict, demoted = apply_open_gaps_policy(verdict, strict=strict)
    if demoted:
        reason = "blocking gaps" if verdict.get("blocking_gaps") else "classification basis"
        notes.append((
            "note",
            f"verdict {verdict.get('demoted_from', '').upper()} demoted to "
            f"NEEDS_INVESTIGATION — {reason}",
        ))

    verdict, floored = apply_success_verification_floor(verdict, offensive_alert=offensive_alert)
    if floored:
        notes.append((
            "note",
            f"verdict {verdict.get('demoted_from', '').upper()} floored to "
            "NEEDS_INVESTIGATION — offensive alert closed benign without a success check",
        ))

    verdict, floored = apply_completeness_floor(
        verdict, escalation_posted=escalation_posted, over_budget=over_budget
    )
    if floored:
        notes.append((
            "note",
            f"verdict {verdict.get('demoted_from', '').upper()} floored to "
            f"NEEDS_INVESTIGATION — {verdict.get('reassessment_reason', '')[:160]}",
        ))

    return verdict, notes
