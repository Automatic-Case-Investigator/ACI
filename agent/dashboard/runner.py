"""Drive analyst questions from the web dashboard.

Each analyst-initiated session maps to one AgentRun (agent_name="orchestrator")
whose id is the session_id. A persistent daemon thread manages a manual asyncio
event loop per question, so we can cancel mid-run when the analyst clicks stop.
Sessions are NEVER marked completed — there is no inherent completion signal.
"""
from __future__ import annotations

import asyncio
import queue
import threading
from typing import Optional

from agent.models import AgentRun
from agent.runtime import logbus
from agent.runtime.orchestrator import OrchestratorSession, run_orchestrator

_active_sessions: dict[str, queue.Queue] = {}       # session_id → message queue
_loops: dict[str, asyncio.AbstractEventLoop] = {}   # session_id → running event loop
_processing: set[str] = set()                       # sessions currently inside run_orchestrator
_lock = threading.Lock()


# ── public API ─────────────────────────────────────────────────────────────────

def start_session(question: str, case_id: str = "") -> str:
    """Create a new analyst session and enqueue the opening question."""
    run = AgentRun.objects.create(
        agent_name="orchestrator",
        case_id=case_id or "",
        question=question,
        status=AgentRun.STATUS_RUNNING,
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
    """Cancel the currently running orchestrator turn (does not kill the session)."""
    with _lock:
        loop = _loops.get(session_id)
    if loop is not None:
        def _cancel_all():
            for task in asyncio.all_tasks(loop):
                task.cancel()
        loop.call_soon_threadsafe(_cancel_all)


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


def is_active(session_id: str) -> bool:
    with _lock:
        return session_id in _active_sessions


def get_ctx(session_id: str) -> dict:
    from django.conf import settings
    from agent.runtime import logbus

    run = _current_context_run(session_id)
    ctx = logbus.get_context_usage(str(run.id)) if run else None
    active_specialist = bool(
        run and run.agent_name != "orchestrator" and run.status == AgentRun.STATUS_RUNNING
    )
    if ctx is None and not active_specialist:
        ctx = logbus.get_context_usage(session_id) or logbus.get_latest_context_usage(session_id)
    tokens = int((ctx or {}).get("tokens") or 0)
    return {
        "tokens": tokens,
        "limit": getattr(settings, "LLM_CONTEXT_LENGTH", 131072),
        "run_id": (ctx or {}).get("run_id") or (str(run.id) if run else session_id),
        "source": (ctx or {}).get("source") or (run.agent_name if run else "orch"),
    }


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

def _set_status(session_id: str, **fields) -> None:
    try:
        AgentRun.objects.filter(id=session_id).update(**fields)
    except Exception:
        pass


def _load_session_state(session_id: str) -> dict | None:
    """A3: durable orchestrator-session state persisted in the run's metadata."""
    try:
        run = AgentRun.objects.filter(id=session_id).first()
        if run and isinstance(run.metadata, dict):
            return run.metadata.get("orch_session")
    except Exception:
        pass
    return None


def _save_session_state(session_id: str, sess: OrchestratorSession) -> None:
    """Merge the orchestrator session essentials into the run's metadata (A3)."""
    try:
        run = AgentRun.objects.filter(id=session_id).first()
        if run is None:
            return
        meta = dict(run.metadata or {})
        meta["orch_session"] = sess.to_state()
        run.metadata = meta
        run.save(update_fields=["metadata", "updated_at"])
    except Exception:
        pass


def _session_loop(session_id: str, q: queue.Queue) -> None:
    """Long-lived thread: process one analyst question at a time."""
    logbus.bind_session(session_id)
    sess = OrchestratorSession()
    # Rehydrate triage/handoff context if this thread is a respawn after a restart.
    sess.load_state(_load_session_state(session_id))

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
