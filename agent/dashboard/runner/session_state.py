from __future__ import annotations

from langchain_core.messages import AIMessage

from agent.models import AgentRun
from agent.runtime.infra import logbus
from agent.runtime.orchestrator import OrchestratorSession, _append_visible
from agent.runtime.orchestrator.specialist_sync import (
    apply_specialist_run_to_session,
    transcript_entry_for_answer,
)


_TERMINAL_RUN_STATUSES = {
    AgentRun.STATUS_COMPLETED,
    AgentRun.STATUS_INCOMPLETE_BUDGET,
    AgentRun.STATUS_CANCELLED,
    AgentRun.STATUS_BLOCKED,
    AgentRun.STATUS_FAILED,
}


def set_session_status(session_id: str, *, unless_cancelled: bool = False, **fields) -> None:
    try:
        qs = AgentRun.objects.filter(id=session_id)
        if unless_cancelled:
            qs = qs.exclude(status=AgentRun.STATUS_CANCELLED)
        qs.update(**fields)
    except Exception:
        pass


def load_session_state(session_id: str) -> dict | None:
    try:
        run = AgentRun.objects.filter(id=session_id).first()
        if run and isinstance(run.metadata, dict):
            return run.metadata.get("orch_session")
    except Exception:
        pass
    return None


def save_session_state(session_id: str, sess: OrchestratorSession) -> None:
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


def publish_specialist_result_to_session(session_id: str, run_id: str, *, reason: str) -> None:
    if not session_id or not run_id:
        return
    run = AgentRun.objects.filter(id=run_id).first()
    if run is None:
        return

    sess = OrchestratorSession()
    sess.load_state(load_session_state(session_id) or {})
    answer = apply_specialist_run_to_session(sess, run, reason=reason)
    if not answer:
        return

    sess.messages.append(AIMessage(content=answer))
    _append_visible(
        sess.visible_transcript,
        "assistant",
        transcript_entry_for_answer(answer, run.result or ""),
    )
    save_session_state(session_id, sess)
    status_update = {}
    if run.status in _TERMINAL_RUN_STATUSES:
        status_update["status"] = AgentRun.STATUS_COMPLETED
    set_session_status(
        session_id,
        unless_cancelled=True,
        result=answer,
        case_id=sess.src_entity_id or "",
        **status_update,
    )
    logbus.emit(
        "orch",
        "answer",
        logbus.summarize_think(answer) or "answer",
        detail=answer,
        expand=True,
        metadata={
            "reason": reason,
            "specialist_run_id": str(run.id),
            "agent_name": run.agent_name,
            "status": run.status,
        },
    )
