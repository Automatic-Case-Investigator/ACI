from __future__ import annotations

import asyncio
import queue
import threading

from agent.models import AgentEvent, AgentRun
from agent.runtime.infra import logbus

from .session_state import load_session_state as _load_session_state, publish_specialist_result_to_session, save_session_state as _save_session_state, set_session_status as _set_status


_active_sessions: dict[str, queue.Queue] = {}       # session_id → message queue
_loops: dict[str, asyncio.AbstractEventLoop] = {}   # session_id → running event loop
_processing: set[str] = set()                       # sessions currently inside run_orchestrator
_lock = threading.Lock()
_RESTARTABLE_AGENTS = {"triage", "investigation"}
_RESTART_CONTEXT_LIMIT = 70000
_EVENT_DETAIL_LIMIT = 6000
_ACTIVE_SPECIALIST_STATES = (
    AgentRun.STATUS_CREATED,
    AgentRun.STATUS_QUEUED,
    AgentRun.STATUS_RUNNING,
    AgentRun.STATUS_WAITING,
)


def _events_for_run(run: AgentRun) -> list[AgentEvent]:
    rid = str(run.id)
    events = list(AgentEvent.objects.filter(run_id=rid).order_by("id"))
    if events:
        return events
    return list(AgentEvent.objects.filter(session_id=rid).order_by("id"))


def _clip(text: str, limit: int) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "\n[event detail clipped for restart prompt]"


def _append_with_limit(lines: list[str], block: str, used: int) -> int:
    if used >= _RESTART_CONTEXT_LIMIT:
        return used
    remaining = _RESTART_CONTEXT_LIMIT - used
    if len(block) > remaining:
        lines.append(block[:remaining].rstrip())
        lines.append(
            "\n[restart context clipped; source AgentEvent rows still contain the full transcript]"
        )
        return _RESTART_CONTEXT_LIMIT
    lines.append(block)
    return used + len(block)


def _prior_tasks(run: AgentRun) -> list[dict]:
    try:
        from aci_taskqueue import store

        return store.list_tasks(run.case_id, str(run.id), run.agent_name)
    except Exception:
        return []


def _prior_board_entries(run: AgentRun) -> list[dict]:
    try:
        from aci_board import store

        return store.list_entries(run.case_id, str(run.id), run.agent_name)
    except Exception:
        return []


def _current_context_run(session_id: str) -> AgentRun | None:
    """Return the run whose context usage should be shown in the dashboard.

    Prefer the currently running specialist agent; fall back to the orchestrator
    session. This makes the context ring represent the active model caller rather
    than always showing orchestration state.
    """
    try:
        runs = list(AgentRun.objects.filter(metadata__session_id=session_id))
    except Exception:
        runs = []
    if not runs:
        runs = [
            run for run in AgentRun.objects.exclude(agent_name="orchestrator").order_by("-updated_at")[:200]
            if (run.metadata or {}).get("session_id") == session_id
        ]
    running_specialists = [
        run for run in runs
        if run.status == AgentRun.STATUS_RUNNING and run.agent_name != "orchestrator"
    ]
    if running_specialists:
        return max(running_specialists, key=lambda r: r.updated_at)
    return AgentRun.objects.filter(id=session_id).first()

# ── internal ───────────────────────────────────────────────────────────────────

