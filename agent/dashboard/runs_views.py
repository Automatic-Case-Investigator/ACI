"""All-runs management page (local console, no auth).

A single table of every top-level run — live interactive sessions and automatic
workflow runs — with stop/delete actions (per-row and bulk). Server-rendered in the
same style as `settings_views.py`: row-builder helpers plus `@require_POST` handlers
that mutate, drop a `messages` entry, and redirect back to the current segment.

Child specialist runs of a live session (those with `metadata.session_id`) are hidden
here — they're reachable inside the session's chatbox.
"""
from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlencode

from django.contrib import messages
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from agent.models import AgentRun

from .run_actions import (
    ACTIVE_STATES,
    delete_run,
    display_status,
    humanize_age as _humanize_age,
    is_inferring,
    is_orchestrator_session,
    stop_run,
)
from .runner import (
    can_restart_from_prior_run,
    restart_from_prior_run,
    start_investigation_from_triage,
)

_VALID_VERDICTS = ("tp", "fp", "inconclusive", "needs_investigation")

SEGMENTS = ("all", "live", "workflows", "active", "completed")
_WORKFLOW_TRIGGERS = (AgentRun.TRIGGER_AUTO, AgentRun.TRIGGER_SCHEDULED)
# Most recent runs scanned before the child-run filter + display cap are applied.
_SCAN_LIMIT = 500
_DISPLAY_LIMIT = 200
_RUNS_PER_PAGE = 25

_ESCALATION_LABEL = {
    "auto_close": "Auto-close",
    "auto_escalate": "Auto-escalate",
    "hold": "Hold for analyst",
    "none": "",
}


def is_reviewable_workflow(run: AgentRun) -> bool:
    """A completed automatic triage run waiting for an analyst investigation decision."""
    verdict = run.verdict if isinstance(run.verdict, dict) else {}
    return (
        run.trigger in _WORKFLOW_TRIGGERS
        and run.status == AgentRun.STATUS_COMPLETED
        and verdict.get("verdict") == "needs_investigation"
        and bool((run.result or "").strip())
    )


def _has_investigation_child(session_id: str) -> bool:
    try:
        return AgentRun.objects.filter(
            agent_name="investigation",
            metadata__session_id=str(session_id),
        ).exists()
    except Exception:
        return any(
            (r.metadata or {}).get("session_id") == str(session_id)
            for r in AgentRun.objects.filter(agent_name="investigation").order_by("-updated_at")[:200]
        )


def review_rows(limit: int = 5) -> list[dict]:
    runs = [
        r for r in AgentRun.objects.order_by("-updated_at")[:_SCAN_LIMIT]
        if is_reviewable_workflow(r)
    ][:limit]
    now = datetime.now(timezone.utc)
    return [
        {
            "id": str(r.id),
            "agent_name": r.agent_name,
            "case_id": r.case_id,
            "question": r.question,
            "confidence": (r.verdict or {}).get("confidence") if isinstance(r.verdict, dict) else "",
            "age": _humanize_age(int((now - r.created_at).total_seconds())),
            "review_url": reverse("dashboard:run_review", args=[r.id]),
        }
        for r in runs
    ]


def _is_child_run(run: AgentRun) -> bool:
    """A specialist run that belongs to a live session (not a top-level row)."""
    return (
        run.trigger == AgentRun.TRIGGER_INTERACTIVE
        and run.agent_name != "orchestrator"
        and bool((run.metadata or {}).get("session_id"))
    )


def _matches_query(run: AgentRun, ql: str) -> bool:
    verdict = run.verdict.get("verdict", "") if isinstance(run.verdict, dict) else ""
    return any(ql in field.lower() for field in (
        str(run.id), run.case_id or "", run.agent_name or "", run.question or "", verdict,
    ))


def _visible_runs(seg: str, query: str = "", verdict: str = "") -> list[AgentRun]:
    """Top-level runs for a segment (+ optional verdict filter and keyword search),
    shared by the list view and bulk handlers so the displayed set and the acted-on
    set are always identical. 'Active' / 'completed' are split by live inference, not
    raw status: an idle session reads as completed."""
    runs = [
        r for r in AgentRun.objects.order_by("-updated_at")[:_SCAN_LIMIT]
        if not _is_child_run(r)
    ]
    if seg == "live":
        runs = [r for r in runs if is_orchestrator_session(r)]
    elif seg == "workflows":
        runs = [r for r in runs if r.trigger in _WORKFLOW_TRIGGERS]
    elif seg == "active":
        runs = [r for r in runs if is_inferring(r)]
    elif seg == "completed":
        runs = [r for r in runs if not is_inferring(r)]
    if verdict in _VALID_VERDICTS:
        from agent.stats import _build_feedback_map, _verdict_of
        fmap = _build_feedback_map([str(r.id) for r in runs])
        runs = [r for r in runs if _verdict_of(r, fmap) == verdict]
    if query:
        ql = query.strip().lower()
        runs = [r for r in runs if _matches_query(r, ql)]
    return runs[:_DISPLAY_LIMIT]


def _run_rows(seg: str, query: str = "", verdict: str = "") -> list[dict]:
    from agent.stats import _build_feedback_map, _verdict_of

    runs = _visible_runs(seg, query, verdict)
    feedback_map = _build_feedback_map([str(r.id) for r in runs])
    now = datetime.now(timezone.utc)
    rows = []
    for r in runs:
        verdict_contract = r.verdict if isinstance(r.verdict, dict) else {}
        escalation = (r.metadata or {}).get("escalation") or {}
        action = escalation.get("action") or ""
        can_review = is_reviewable_workflow(r)
        rows.append({
            "id": str(r.id),
            "is_live": is_orchestrator_session(r),
            "agent_name": r.agent_name,
            "case_id": r.case_id,
            "question": r.question,
            "status": display_status(r),
            "is_inferring": is_inferring(r),
            "verdict": _verdict_of(r, feedback_map),
            "recommended_action": verdict_contract.get("recommended_action") or "",
            "escalation_label": _ESCALATION_LABEL.get(action, action),
            "execution_error": escalation.get("execution_error") or "",
            "age": _humanize_age(int((now - r.created_at).total_seconds())),
            "open_url": reverse("dashboard:session", args=[r.id]) if is_orchestrator_session(r) else None,
            "can_review": can_review,
            "review_url": reverse("dashboard:run_review", args=[r.id]) if can_review else None,
            "can_restart": can_restart_from_prior_run(r),
            "restart_url": reverse("dashboard:run_restart", args=[r.id]),
        })
    return rows


def _segment(value: str | None) -> str:
    return value if value in SEGMENTS else "all"


def _filters_from(source) -> dict:
    """Pull the active seg / verdict / search filters from a GET or POST mapping."""
    verdict = source.get("verdict") or ""
    return {
        "seg": _segment(source.get("seg")),
        "query": (source.get("q") or "").strip(),
        "verdict": verdict if verdict in _VALID_VERDICTS else "",
    }


def _redirect_back(request):
    f = _filters_from(request.POST)
    params = {"seg": f["seg"]}
    if f["verdict"]:
        params["verdict"] = f["verdict"]
    if f["query"]:
        params["q"] = f["query"]
    return redirect(f"{reverse('dashboard:runs')}?{urlencode(params)}")


def runs_view(request):
    f = _filters_from(request.GET)
    rows = _run_rows(f["seg"], f["query"], f["verdict"])
    rows_page = Paginator(rows, _RUNS_PER_PAGE).get_page(request.GET.get("p"))
    return render(request, "dashboard/runs.html", {
        "rows_page": rows_page,
        "segment": f["seg"],
        "segments": SEGMENTS,
        "query": f["query"],
        "verdict": f["verdict"],
        "subtitle": "Runs",
    })


def run_review(request, run_id):
    run = get_object_or_404(AgentRun, id=str(run_id))
    verdict = run.verdict if isinstance(run.verdict, dict) else {}
    escalation = (run.metadata or {}).get("escalation") or {}
    existing_session_id = ((run.metadata or {}).get("review") or {}).get("investigation_session_id")
    existing_session = None
    if existing_session_id:
        existing = AgentRun.objects.filter(id=existing_session_id, agent_name="orchestrator").first()
        if existing is not None and _has_investigation_child(str(existing.id)):
            existing_session = existing
    return render(request, "dashboard/run_review.html", {
        "run": run,
        "verdict": verdict,
        "escalation": escalation,
        "can_investigate": is_reviewable_workflow(run),
        "existing_session": existing_session,
    })


@csrf_exempt
@require_POST
def run_investigate(request, run_id):
    run = AgentRun.objects.filter(id=str(run_id)).first()
    if run is None:
        messages.error(request, "Workflow run not found.")
        return redirect("dashboard:runs")
    if not is_reviewable_workflow(run):
        messages.error(request, "This workflow is not waiting for investigation review.")
        return redirect("dashboard:run_review", run_id=run.id)

    review = dict((run.metadata or {}).get("review") or {})
    existing_session_id = review.get("investigation_session_id")
    if existing_session_id:
        existing = AgentRun.objects.filter(id=existing_session_id, agent_name="orchestrator").first()
        if existing is not None and _has_investigation_child(str(existing.id)):
            return redirect("dashboard:session", session_id=existing.id)

    session_id = start_investigation_from_triage(run)
    meta = dict(run.metadata or {})
    review["investigation_session_id"] = session_id
    meta["review"] = review
    run.metadata = meta
    run.save(update_fields=["metadata", "updated_at"])
    messages.success(request, "Investigation session started from the approved triage report.")
    return redirect("dashboard:session", session_id=session_id)


@csrf_exempt
@require_POST
def run_restart(request, run_id):
    source = AgentRun.objects.filter(id=str(run_id)).first()
    if source is None:
        messages.error(request, "Run not found.")
        return redirect("dashboard:runs")
    if not can_restart_from_prior_run(source):
        messages.error(request, "Only budget-exhausted triage and investigation runs can be restarted.")
        return _redirect_back(request)
    try:
        new_run = restart_from_prior_run(source)
    except Exception as exc:
        messages.error(request, f"Restart failed: {exc}")
        return _redirect_back(request)

    messages.success(
        request,
        f"Restarted {source.agent_name} from prior run {str(source.id)[:8]} "
        f"as {str(new_run.id)[:8]}.",
    )
    session_id = (new_run.metadata or {}).get("session_id")
    if session_id:
        return redirect("dashboard:session", session_id=session_id)
    return _redirect_back(request)


@csrf_exempt
@require_POST
def run_stop(request, run_id):
    run = AgentRun.objects.filter(id=str(run_id)).first()
    if run is None:
        messages.error(request, "Run not found.")
    elif run.status not in ACTIVE_STATES:
        messages.info(request, "Run already finished.")
    else:
        stop_run(run)
        messages.success(request, "Stop requested.")
    return _redirect_back(request)


@csrf_exempt
@require_POST
def run_delete(request, run_id):
    run = AgentRun.objects.filter(id=str(run_id)).first()
    if run is None:
        messages.error(request, "Run not found.")
    else:
        delete_run(run)
        messages.success(request, "Run deleted.")
    return _redirect_back(request)


@csrf_exempt
@require_POST
def runs_stop_all(request):
    f = _filters_from(request.POST)
    count = 0
    for run in _visible_runs(f["seg"], f["query"], f["verdict"]):
        if is_inferring(run):
            stop_run(run)
            count += 1
    messages.success(request, f"Stop requested for {count} run(s).")
    return _redirect_back(request)


@csrf_exempt
@require_POST
def runs_delete_all(request):
    f = _filters_from(request.POST)
    count = 0
    for run in _visible_runs(f["seg"], f["query"], f["verdict"]):
        delete_run(run)
        count += 1
    messages.success(request, f"Deleted {count} run(s).")
    return _redirect_back(request)


@csrf_exempt
@require_POST
def runs_delete_selected(request):
    """Delete just the runs whose ids were checked in the table."""
    count = 0
    for rid in request.POST.getlist("ids"):
        run = AgentRun.objects.filter(id=rid).first()
        if run is not None:
            delete_run(run)
            count += 1
    messages.success(request, f"Deleted {count} selected run(s).")
    return _redirect_back(request)
