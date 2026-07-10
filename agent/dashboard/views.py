"""Dashboard HTTP views (local console, no auth).

The page renders the initial state server-side (history, queue, status); live
updates arrive over the WebSocket. Follow-up questions are sent via WS action
{"action": "ask", "question": "..."} so no page reload is needed.
"""
from __future__ import annotations

from datetime import datetime, timezone

from django.core.paginator import Paginator
from django.urls import reverse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from agent.models import AgentEvent, AgentRun

from .consumers import _snapshot
from .run_actions import (
    ACTIVE_STATES,
    delete_run,
    humanize_age,
    is_inferring,
    is_orchestrator_session,
    is_orphaned_interactive_child,
)
from .runner import start_session, send_message
from .runs_views import review_rows

_SESSIONS_PER_PAGE = 8
_ACTIVE_PER_PAGE = 8
_SCAN_LIMIT = 500


def _search_runs(runs, query, fields):
    """Keyword filter over a run list — matches any of `fields(run)` (id, question…)."""
    ql = query.strip().lower()
    return [r for r in runs if ql in " ".join(str(f or "") for f in fields(r)).lower()]


def _verdict_totals() -> dict:
    """Running tally of each verdict value (analyst-corrected where available)."""
    from agent.runtime.analysis.verdict import VERDICT_ORDER
    from agent.stats import load_verdict_runs, _verdict_of

    runs, feedback_map = load_verdict_runs(36500)  # effectively all-time
    totals = {v: 0 for v in VERDICT_ORDER}
    for run in runs:
        v = _verdict_of(run, feedback_map)
        if v in totals:
            totals[v] += 1
    return totals


def _active_run_rows(runs) -> list[dict]:
    now = datetime.now(timezone.utc)
    return [
        {
            "short_id": str(r.id)[:8],
            "agent_name": r.agent_name,
            "question": r.question,
            "case_id": r.case_id,
            "age": humanize_age(int((now - r.created_at).total_seconds())),
            "open_url": reverse("dashboard:session", args=[r.id]) if is_orchestrator_session(r) else reverse("dashboard:run_detail", args=[r.id]),
        }
        for r in runs
    ]


def index(request):
    sessions_q = (request.GET.get("sq") or "").strip()
    active_q = (request.GET.get("rq") or "").strip()

    sessions = list(AgentRun.objects.filter(agent_name="orchestrator").order_by("-created_at")[:_SCAN_LIMIT])
    if sessions_q:
        sessions = _search_runs(sessions, sessions_q, lambda r: (r.id, r.question, r.case_id))
    sessions_page = Paginator(sessions, _SESSIONS_PER_PAGE).get_page(request.GET.get("sp"))

    # Active = currently awaiting an agent inference, not merely a non-terminal row
    # (idle sessions sit at RUNNING but aren't inferring).
    active = [
        r for r in AgentRun.objects.filter(status__in=ACTIVE_STATES).order_by("-updated_at")[:_SCAN_LIMIT]
        if is_inferring(r) and not is_orphaned_interactive_child(r)
    ]
    if active_q:
        active = _search_runs(active, active_q, lambda r: (r.id, r.agent_name, r.question, r.case_id))
    active_page = Paginator(active, _ACTIVE_PER_PAGE).get_page(request.GET.get("rp"))

    return render(request, "dashboard/index.html", {
        "sessions_page": sessions_page,
        "active_page": active_page,
        "active_runs": _active_run_rows(active_page.object_list),
        "verdict_totals": _verdict_totals(),
        "review_runs": review_rows(),
        "sessions_q": sessions_q,
        "active_q": active_q,
    })


@csrf_exempt  # local no-login console
@require_POST
def ask(request):
    question = (request.POST.get("question") or "").strip()
    if not question:
        return redirect("dashboard:index")
    session_id = start_session(question)
    return redirect("dashboard:session", session_id=session_id)


@csrf_exempt
@require_POST
def ask_followup(request, session_id):
    """Send a follow-up message to an existing session (used by test drivers and CLI)."""
    from django.http import JsonResponse

    question = (request.POST.get("question") or "").strip()
    if not question:
        return JsonResponse({"error": "empty question"}, status=400)
    sent = send_message(str(session_id), question)
    return JsonResponse({"sent": sent, "session_id": str(session_id)})


@csrf_exempt
@require_POST
def delete_session(request, session_id):
    session_id = str(session_id)
    run = AgentRun.objects.filter(id=session_id).first()
    if run is not None:
        delete_run(run)
    else:  # row already gone — still purge any stray events
        AgentEvent.objects.filter(session_id=session_id).delete()
    return redirect("dashboard:index")


@csrf_exempt
@require_POST
def delete_sessions_selected(request):
    """Delete just the sessions whose ids were checked in the live-sessions list."""
    from django.contrib import messages

    count = 0
    for sid in request.POST.getlist("ids"):
        sid = str(sid)
        run = AgentRun.objects.filter(id=sid).first()
        if run is not None:
            delete_run(run)
        else:  # row already gone — still purge any stray events
            AgentEvent.objects.filter(session_id=sid).delete()
        count += 1
    messages.success(request, f"Deleted {count} selected session(s).")
    return redirect("dashboard:index")


def session_view(request, session_id):
    session_id = str(session_id)
    orch = AgentRun.objects.filter(id=session_id).first()
    events = list(AgentEvent.objects.filter(session_id=session_id).order_by("id"))
    snap = _snapshot(session_id)
    # The WebSocket resumes from the last event already rendered server-side, so
    # the live stream does not re-push (and visually duplicate) the initial events.
    last_event_id = events[-1].id if events else 0
    return render(
        request,
        "dashboard/session.html",
        {
            "session_id": session_id,
            "orch": orch,
            "events": events,
            "snap": snap,
            "last_event_id": last_event_id,
        },
    )
