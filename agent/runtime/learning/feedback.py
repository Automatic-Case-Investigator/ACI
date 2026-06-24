"""Analyst feedback — immediate, mutable verdict corrections.

When an analyst confirms or overturns an agent verdict, record it as a
`FeedbackEntry`. There is exactly one entry per run; submitting again updates
the existing row rather than appending a new one.

Feedback takes effect immediately: the `aci-memory` MCP server exposes it via
`search_feedback`, which agents query both for the current case and (optionally)
across recent cases to learn from past corrections without any admin step.

The `context` field carries the structured pivots from the case (rule_ids, users,
hosts, alert_types) so that future cross-case queries can assess relevance without
re-fetching the original case data.
"""
from __future__ import annotations

from agent.models import FeedbackEntry, PatternCandidate


def _normalize_verdict(value) -> dict | None:
    """Accept a bare verdict string or a full contract dict; return a dict or None."""
    if value is None:
        return None
    if isinstance(value, str):
        v = value.strip().lower()
        return {"verdict": v} if v else None
    if isinstance(value, dict):
        return value
    return None


def _normalize_context(context) -> dict:
    """Ensure context is a dict with expected list fields coerced to lists."""
    if not isinstance(context, dict):
        return {}
    out = {}
    for key in ("rule_ids", "users", "hosts", "alert_types"):
        val = context.get(key)
        if isinstance(val, list):
            out[key] = [str(v) for v in val if v]
        elif isinstance(val, str) and val:
            out[key] = [val]
    return out


def record_feedback(
    run,
    analyst_verdict,
    note: str = "",
    created_by: str = "",
    context: dict | None = None,
) -> tuple[FeedbackEntry, PatternCandidate | None]:
    """Record or update analyst feedback for a run.

    Returns (feedback_entry, candidate). `candidate` is a new PatternCandidate
    (status=PENDING, never promoted automatically) when the analyst verdict
    contradicts the agent verdict on a tp/fp axis. Returns None on agreement or
    when the analyst verdict is not a valid pattern label (inconclusive,
    needs_investigation). `analyst_verdict` may be a bare string ("tp") or a
    full verdict dict ({"verdict": "fp", "confidence": "high"}).

    `context` should contain the key pivots from the case — rule_ids, users,
    hosts, alert_types — so future cross-case feedback queries can filter by
    overlap. The caller (dashboard or API) is responsible for providing this;
    it is stored as-is and never inferred from the run record.
    """
    original = run.verdict if isinstance(run.verdict, dict) else None
    analyst = _normalize_verdict(analyst_verdict)

    feedback, _ = FeedbackEntry.objects.update_or_create(
        run_id=str(run.id),
        defaults={
            "case_id": run.case_id,
            "agent_name": run.agent_name,
            "original_verdict": original,
            "analyst_verdict": analyst,
            "context": _normalize_context(context or {}),
            "note": note or "",
            "created_by": created_by or "",
        },
    )

    candidate = None
    av = analyst.get("verdict", "") if analyst else ""
    ov = (original or {}).get("verdict", "") if original else ""
    # Feedback is re-assessable (the analyst can change their verdict), so clear
    # any prior pending candidate for this feedback before (re)creating — otherwise
    # each change appends a duplicate to the review queue. Reviewed/promoted
    # candidates (non-PENDING) are left untouched.
    PatternCandidate.objects.filter(
        source_feedback=feedback, status=PatternCandidate.STATUS_PENDING
    ).delete()
    # Only tp/fp are reusable pattern labels; inconclusive/needs_investigation are not.
    if av in ("tp", "fp") and av != ov:
        candidate = PatternCandidate.objects.create(
            name=f"Review: case {run.case_id}",
            verdict=av,
            confidence=analyst.get("confidence", "medium"),
            source_feedback=feedback,
            status=PatternCandidate.STATUS_PENDING,
            conditions={},
        )

    return feedback, candidate
