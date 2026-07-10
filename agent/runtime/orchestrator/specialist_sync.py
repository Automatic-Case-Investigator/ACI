from __future__ import annotations

import logging

from ...models import AgentRun

log = logging.getLogger(__name__)


def apply_specialist_run_to_session(session, run: AgentRun, *, reason: str = "updated") -> str | None:
    """Mutate orchestrator session state from a completed specialist run.

    Returns the analyst-facing update text when the run should be surfaced as an
    explicit session update, or `None` if the run type is unsupported.
    """
    if run.case_id:
        session.src_entity_id = run.case_id
    source_entity_type = (run.metadata or {}).get("source_entity_type")
    if source_entity_type:
        session.source_entity_type = source_entity_type

    prefix = {
        "resume": "Resumed",
        "restart": "Restarted",
    }.get(reason, "Updated")

    if run.agent_name == "investigation":
        session.investigation_run_id = str(run.id)
        session.last_investigation_report = run.result or ""
        session.last_investigation_status = run.status
        if (run.result or "").strip():
            return f"{prefix} investigation run finished. Updated report below:\n\n{run.result.strip()}"
        return (
            f"{prefix} investigation run {str(run.id)[:8]} finished with status {run.status}, "
            "but did not return a report."
        )

    if run.agent_name == "triage":
        session.last_triage_src_entity_id = run.case_id or session.last_triage_src_entity_id
        session.last_triage_source_entity_type = source_entity_type or session.source_entity_type
        session.last_triage_run_id = str(run.id)
        session.last_triage_status = run.status
        if isinstance(run.verdict, dict):
            session.last_triage_verdict = run.verdict
        if run.status == AgentRun.STATUS_COMPLETED and (run.result or "").strip():
            session.last_triage_report = run.result or ""
            return f"{prefix} triage run finished. Updated report below:\n\n{run.result.strip()}"
        else:
            # Budget-exhausted / failed triage output is not a valid handoff.
            session.last_triage_report = None
        return (
            f"{prefix} triage run {str(run.id)[:8]} finished with status {run.status}, "
            "and did not produce a durable triage report."
        )

    return None


def transcript_entry_for_answer(answer: str, report_text: str = "", *, limit: int = 3000) -> str:
    if len(report_text or "") > limit:
        return (
            answer[:limit]
            + "\n\n...[report truncated for context management - full report is preserved in session state]"
        )
    return answer


async def propagate_verdict_to_current_session(verdict: dict | None, *, current_session_id: str | None) -> None:
    """Copy a durable specialist verdict onto the session row counted by dashboard stats."""
    if not isinstance(verdict, dict) or not current_session_id:
        return
    try:
        session_run = await AgentRun.objects.aget(id=current_session_id)
        session_run.verdict = verdict
        await session_run.asave(update_fields=["verdict", "updated_at"])
    except Exception as exc:
        log.warning("Could not propagate verdict to session %s: %s", current_session_id, exc)
