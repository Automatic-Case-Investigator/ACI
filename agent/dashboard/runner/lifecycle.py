from __future__ import annotations

import asyncio
import queue
import threading
import traceback
from typing import Optional

from agent.models import AgentEvent, AgentRun
from agent.agents.base import Handoff
from agent.runtime.engine.dispatch import dispatch_run
from agent.runtime.infra import logbus
from agent.runtime.engine.run import run_agent_sync
from agent.runtime.orchestrator import OrchestratorSession, run_orchestrator

from ._base import _ACTIVE_SPECIALIST_STATES, _RESTARTABLE_AGENTS, _active_sessions, _current_context_run, _load_session_state, _lock, _loops, _processing, _save_session_state, _set_status



# ── public API ─────────────────────────────────────────────────────────────────

def start_session(question: str, case_id: str = "", *, orch_state: dict | None = None) -> str:
    """Create a new analyst session and enqueue the opening question."""
    metadata = {}
    if orch_state:
        metadata["orch_session"] = orch_state
    run = AgentRun.objects.create(
        agent_name="orchestrator",
        case_id=case_id or "",
        question=question,
        status=AgentRun.STATUS_RUNNING,
        metadata=metadata,
    )
    session_id = str(run.id)
    q: queue.Queue = queue.Queue()
    with _lock:
        _active_sessions[session_id] = q
    threading.Thread(
        target=_session_loop,
        args=(session_id, q),
        name=f"aci-orch-{session_id[:8]}",
        daemon=True,
    ).start()
    q.put(question)
    return session_id


def start_investigation_from_triage(source_run: AgentRun) -> str:
    """Start an analyst session that proceeds from an approved triage report."""
    case_id = source_run.case_id or ""
    question = (
        f"Investigate case {case_id} using the approved triage report from workflow "
        f"{str(source_run.id)[:8]}."
    ).strip()
    orch_state = {
        "case_id": case_id,
        "last_triage_case_id": case_id,
        "last_triage_report": source_run.result or "",
        "last_triage_run_id": str(source_run.id),
        "review_auto_investigate": True,
    }
    return start_session(question, case_id=case_id, orch_state=orch_state)


def send_message(session_id: str, question: str) -> bool:
    """Enqueue a follow-up question. Respawns the thread if it died (e.g. restart)."""
    with _lock:
        q = _active_sessions.get(session_id)
        if q is None:
            q = queue.Queue()
            _active_sessions[session_id] = q
            threading.Thread(
                target=_session_loop,
                args=(session_id, q),
                name=f"aci-orch-{session_id[:8]}",
                daemon=True,
            ).start()
    q.put(question)
    return True


def stop_processing(session_id: str) -> None:
    """Cancel the active turn or restarted specialist (does not kill the session)."""
    with _lock:
        loop = _loops.get(session_id)
    if loop is not None:
        def _cancel_all():
            for task in asyncio.all_tasks(loop):
                task.cancel()
        loop.call_soon_threadsafe(_cancel_all)
    try:
        runs = AgentRun.objects.filter(
            metadata__session_id=session_id,
            agent_name__in=_RESTARTABLE_AGENTS,
            status__in=_ACTIVE_SPECIALIST_STATES,
        )
        for run in runs:
            meta = dict(run.metadata or {})
            meta["cancel_requested"] = True
            run.status = AgentRun.STATUS_CANCELLED
            run.metadata = meta
            run.save(update_fields=["status", "metadata", "updated_at"])
    except Exception:
        pass


def stop_session(session_id: str) -> None:
    """Stop processing and terminate the session thread (used before deletion)."""
    stop_processing(session_id)
    with _lock:
        q = _active_sessions.get(session_id)
    if q is not None:
        q.put(None)  # shutdown sentinel


def is_processing(session_id: str) -> bool:
    with _lock:
        return session_id in _processing


def active_specialist_for_session(session_id: str) -> AgentRun | None:
    """Newest queued/running triage or investigation child for a live session."""
    try:
        runs = AgentRun.objects.filter(
            metadata__session_id=session_id,
            agent_name__in=_RESTARTABLE_AGENTS,
            status__in=_ACTIVE_SPECIALIST_STATES,
        ).order_by("-updated_at", "-created_at")
    except Exception:
        runs = [
            run for run in AgentRun.objects.order_by("-updated_at")[:200]
            if (run.metadata or {}).get("session_id") == session_id
            and run.agent_name in _RESTARTABLE_AGENTS
            and run.status in _ACTIVE_SPECIALIST_STATES
        ]
    return runs.first() if hasattr(runs, "first") else (runs[0] if runs else None)


def is_active(session_id: str) -> bool:
    with _lock:
        return session_id in _active_sessions


def get_ctx(session_id: str) -> dict:
    from agent.runtime.infra import logbus
    from agent.runtime.engine.model_client import model_context_length_sync

    run = _current_context_run(session_id)
    ctx = logbus.get_context_usage(str(run.id)) if run else None
    # A just-started specialist may be the active model caller before its first
    # usage payload arrives. Show the freshest session reading until that run
    # reports tokens, instead of resetting the wheel to an empty context window.
    if ctx is None:
        ctx = logbus.get_context_usage(session_id) or logbus.get_latest_context_usage(session_id)
    if ctx is None:
        state = _load_session_state(session_id) or {}
        persisted_tokens = int(state.get("ctx_tokens") or 0)
        if persisted_tokens:
            ctx = {
                "tokens": persisted_tokens,
                "run_id": session_id,
                "source": "orch",
                "ts": None,
            }
    tokens = int((ctx or {}).get("tokens") or 0)
    return {
        "tokens": tokens,
        "limit": model_context_length_sync(),
        "run_id": (ctx or {}).get("run_id") or (str(run.id) if run else session_id),
        "source": (ctx or {}).get("source") or (run.agent_name if run else "orch"),
        # Epoch seconds of the model call that produced this usage (None until a
        # sub-agent records one). Lets the dashboard show how fresh the reading is.
        "ts": (ctx or {}).get("ts"),
    }


def _session_loop(session_id: str, q: queue.Queue) -> None:
    """Long-lived thread: process one analyst question at a time."""
    logbus.bind_session(session_id)
    sess = OrchestratorSession()
    loaded_state = _load_session_state(session_id) or {}
    # Rehydrate triage/handoff context if this thread is a respawn after a restart.
    sess.load_state(loaded_state)
    direct_review_investigation = bool(loaded_state.get("review_auto_investigate"))

    try:
        while True:
            question: Optional[str] = q.get()
            if question is None:  # shutdown sentinel
                break

            logbus.emit("cli", "note", f"analyst: {question}")
            _set_status(session_id, status=AgentRun.STATUS_RUNNING)

            # Create a fresh event loop so we can cancel tasks from another thread.
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            with _lock:
                _loops[session_id] = loop
                _processing.add(session_id)
            answer = "(stopped)"
            try:
                if direct_review_investigation:
                    direct_review_investigation = False
                    answer = loop.run_until_complete(
                        _run_review_investigation(session_id, sess, question)
                    )
                else:
                    answer = loop.run_until_complete(run_orchestrator(sess, question))
            except asyncio.CancelledError:
                answer = "Stopped by analyst. Ask a follow-up to continue from here."
                logbus.emit(
                    "orch", "note",
                    "stopped by analyst — ask a follow-up to continue",
                    detail="resumable", expand=True,
                )
            except Exception as exc:
                answer = f"orchestrator error: {exc}"
                traceback.print_exc()
                logbus.emit("orch", "error", "orchestrator crashed", detail=str(exc))
            else:
                logbus.emit(
                    "orch", "answer",
                    logbus.summarize_think(answer) or "answer",
                    detail=answer,
                    expand=True,
                )
            finally:
                with _lock:
                    _loops.pop(session_id, None)
                    _processing.discard(session_id)
                loop.close()

            _set_status(
                session_id,
                unless_cancelled=True,
                status=AgentRun.STATUS_RUNNING,
                result=answer,
                case_id=sess.case_id or "",
            )
            _save_session_state(session_id, sess)
    finally:
        with _lock:
            _active_sessions.pop(session_id, None)
            _processing.discard(session_id)
            _loops.pop(session_id, None)


async def _run_review_investigation(
    session_id: str,
    sess: OrchestratorSession,
    question: str,
) -> str:
    """Deterministically continue a held workflow triage report into investigation."""
    case_id = sess.last_triage_case_id or sess.case_id or ""
    triage_report = (sess.last_triage_report or "").strip()
    if not case_id or not triage_report:
        msg = "Cannot start investigation: the approved workflow triage report was not available."
        logbus.emit("orch", "error", msg)
        return msg

    sess.case_id = case_id
    handoff = Handoff(
        analyst_request=question,
        triage_report=triage_report,
        source_run_id=sess.last_triage_run_id or "",
    )
    logbus.emit(
        "orch",
        "route",
        f"investigation(case={case_id})",
        detail=(
            "approved workflow triage handoff; "
            f"source_run={sess.last_triage_run_id or 'unknown'}; "
            f"report_chars={len(triage_report)}"
        ),
    )
    logbus.emit(
        "orch",
        "call",
        f"investigation(case_id={case_id}, triage_report=workflow:{(sess.last_triage_run_id or '')[:8]})",
    )
    run = await dispatch_run(
        "investigation",
        case_id,
        question,
        session_id=session_id,
        trigger=AgentRun.TRIGGER_INTERACTIVE,
        handoff=handoff,
    )
    sess.investigation_run_id = str(run.id)
    sess.last_investigation_report = run.result or ""

    if sess.last_investigation_report.strip():
        answer = "The investigation is complete. Full report below:\n\n" + sess.last_investigation_report.strip()
    else:
        answer = (
            f"Investigation run {str(run.id)[:8]} finished with status {run.status}, "
            "but did not return a report."
        )
    logbus.emit("orch", "result", f"investigation: status={run.status}", detail=answer)
    return answer

