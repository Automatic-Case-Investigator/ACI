"""Verdict aggregation for the dashboard diagnosis view.

Aggregates `AgentRun.verdict` for the TP/FP trend and breakdown panels. The
verdict is a JSON contract; SQLite JSON aggregation through the ORM is awkward and
backend-specific, so we pull the (small) set of recent verdicts and tally them in
Python. Demoted verdicts count under their final value (`inconclusive`), which is
the honest tally an analyst wants.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from agent.runtime.analysis.verdict import VERDICT_ORDER as VERDICT_VALUES

_GROUPABLE = {"agent_name", "trigger", "confidence", "verdict"}


def _verdict_of(run, feedback_map: dict | None = None) -> str | None:
    # Prefer analyst correction when available.
    if feedback_map is not None:
        av = feedback_map.get(str(run.id))
        if isinstance(av, dict):
            val = av.get("verdict")
            if val in VERDICT_VALUES:
                return val
    v = run.verdict
    if isinstance(v, dict):
        val = v.get("verdict")
        return val if val in VERDICT_VALUES else None
    return None


def _confidence_of(run) -> str:
    v = run.verdict
    if isinstance(v, dict):
        return v.get("confidence") or "unknown"
    return "unknown"


def _runs_since(days: int):
    from agent.models import AgentRun

    since = datetime.now(timezone.utc) - timedelta(days=max(1, days))
    runs = list(AgentRun.objects.filter(
        created_at__gte=since, verdict__isnull=False
    ).only("id", "agent_name", "trigger", "verdict", "created_at", "metadata"))
    # Exclude all interactive child runs (triage/investigation sub-agents owned by
    # an orchestrator session). Their verdict is propagated to the session row which
    # IS counted. Counting children separately causes double-counting and makes the
    # totals inconsistent with the list view (which hides them via _is_child_run).
    return [r for r in runs if not _is_interactive_child(r)]


def _is_interactive_child(run) -> bool:
    """True for any specialist sub-agent run that belongs to a dashboard session."""
    from agent.models import AgentRun

    return (
        run.trigger == AgentRun.TRIGGER_INTERACTIVE
        and run.agent_name != "orchestrator"
        and bool((run.metadata or {}).get("session_id"))
    )


def _build_feedback_map(run_ids: list) -> dict:
    """Return {run_id: analyst_verdict} for runs that have analyst corrections."""
    from agent.models import FeedbackEntry

    return {
        fb.run_id: fb.analyst_verdict
        for fb in FeedbackEntry.objects.filter(run_id__in=run_ids).only("run_id", "analyst_verdict")
        if fb.analyst_verdict is not None
    }


def load_verdict_runs(days: int = 7) -> tuple[list, dict]:
    """Fetch the recent runs and their analyst-correction map for the window.

    Returns ``(runs, feedback_map)`` so a caller rendering both the trend and the
    breakdown can share a single DB scan instead of querying twice.
    """
    runs = _runs_since(days)
    feedback_map = _build_feedback_map([str(r.id) for r in runs])
    return runs, feedback_map


def _finalize_rows(buckets: dict, key_field: str, *, sort_by_total: bool) -> list[dict]:
    """Turn ``{key: {verdict: count}}`` into sorted rows with a ``total``."""
    out = []
    for key in sorted(buckets):
        counts = buckets[key]
        out.append({key_field: key, **counts, "total": sum(counts.values())})
    if sort_by_total:
        out.sort(key=lambda r: r["total"], reverse=True)
    return out


def verdict_trend(days: int = 7, *, runs: list | None = None, feedback_map: dict | None = None) -> list[dict]:
    """Per-day counts of each verdict value over the window (oldest first).

    Uses the analyst-corrected verdict where available, falling back to the
    agent's original verdict. Pass `runs`/`feedback_map` from `load_verdict_runs`
    to reuse a scan shared with `verdict_breakdown`.
    """
    if runs is None or feedback_map is None:
        runs, feedback_map = load_verdict_runs(days)
    buckets: dict[str, dict[str, int]] = defaultdict(lambda: {v: 0 for v in VERDICT_VALUES})
    for run in runs:
        v = _verdict_of(run, feedback_map)
        if v is None:
            continue
        day = run.created_at.date().isoformat()
        buckets[day][v] += 1
    return _finalize_rows(buckets, "date", sort_by_total=False)


def verdict_breakdown(days: int = 7, group_by: str = "agent_name", *, runs: list | None = None, feedback_map: dict | None = None) -> list[dict]:
    """Counts of each verdict value grouped by a run/verdict attribute.

    Uses the analyst-corrected verdict where available.
    """
    if group_by not in _GROUPABLE:
        group_by = "agent_name"
    if runs is None or feedback_map is None:
        runs, feedback_map = load_verdict_runs(days)
    groups: dict[str, dict[str, int]] = defaultdict(lambda: {v: 0 for v in VERDICT_VALUES})
    for run in runs:
        v = _verdict_of(run, feedback_map)
        if v is None:
            continue
        if group_by == "confidence":
            key = _confidence_of(run)
        elif group_by == "verdict":
            key = v
        else:
            key = getattr(run, group_by, "") or "(none)"
        groups[key][v] += 1
    return _finalize_rows(groups, group_by, sort_by_total=True)
