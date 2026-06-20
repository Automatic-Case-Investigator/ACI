"""Dashboard HTTP views (local console, no auth).

The page renders the initial state server-side (history, queue, status); live
updates arrive over the WebSocket. Follow-up questions are sent via WS action
{"action": "ask", "question": "..."} so no page reload is needed.
"""
from __future__ import annotations

from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from agent.models import AgentEvent, AgentRun

from .consumers import _snapshot
from .runner import start_session, stop_session, send_message


def index(request):
    sessions = AgentRun.objects.filter(agent_name="orchestrator").order_by("-created_at")[:20]
    return render(request, "dashboard/index.html", {"sessions": sessions})


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
    stop_session(session_id)
    AgentEvent.objects.filter(session_id=session_id).delete()
    AgentRun.objects.filter(id=session_id).delete()
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
