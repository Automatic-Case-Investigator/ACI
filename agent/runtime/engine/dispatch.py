"""Transport-agnostic run dispatcher.

The single way to launch a specialist agent run, independent of *who* triggers it:
the interactive orchestrator (a sub-agent tool call), a workflow binding firing on a
new case/alert, or a future scheduler. It creates the `AgentRun` row, records the
trigger provenance and any structured `Handoff`, runs the agent to completion, and
returns the refreshed run.

No Channels / threading / event-loop assumptions live here — `runner.py` owns the
interactive event-loop plumbing and calls into this; headless callers can use
`dispatch_run_sync`.
"""
from __future__ import annotations

import asyncio
from typing import Optional

from asgiref.sync import sync_to_async

from ...agents.base import Handoff
from ...models import AgentRun
from .run import run_agent


async def _refresh_run_or_none(run: AgentRun, stage: str) -> AgentRun | None:
    """Refresh a run, returning None if an operator deleted it mid-dispatch."""
    try:
        await run.arefresh_from_db()
        return run
    except AgentRun.DoesNotExist:
        from ..infra.logbus import emit

        emit(
            "workflow",
            "note",
            f"run {str(run.id)[:8]} deleted during {stage}; skipping remaining workflow steps",
        )
        return None


async def dispatch_run(
    agent_name: str,
    case_id: str,
    question: str,
    *,
    session_id: Optional[str] = None,
    trigger: str = AgentRun.TRIGGER_INTERACTIVE,
    handoff: Optional[Handoff] = None,
    orchestrator_context: Optional[str] = None,
    metadata: Optional[dict] = None,
    dedupe_window: int = 0,
) -> AgentRun:
    """Create and run one agent run to completion; return the refreshed AgentRun.

    When `dedupe_window` > 0, an already-active run for the same case+agent within
    that many seconds short-circuits this call: no new run is spawned and the
    existing run is returned (with a `deduped` audit event). Used by automatic
    workflows so a burst of identical triggers can't fan out into duplicate work.
    """
    if dedupe_window > 0:
        from ..policy.workflow import find_duplicate_run, AUDIT_DEDUPED
        from ..infra.logbus import emit

        existing = await sync_to_async(find_duplicate_run, thread_sensitive=True)(
            case_id, agent_name, dedupe_window
        )
        if existing is not None:
            emit("workflow", AUDIT_DEDUPED,
                 f"case {case_id}: {agent_name} already active ({str(existing.id)[:8]}), skipped")
            return existing

    meta = dict(metadata or {})
    if session_id:
        meta["session_id"] = session_id
    if handoff is not None:
        meta["handoff"] = handoff.to_dict()
    if orchestrator_context:
        meta["orchestrator_context"] = orchestrator_context

    run = await AgentRun.objects.acreate(
        case_id=case_id,
        agent_name=agent_name,
        question=question,
        trigger=trigger,
        metadata=meta,
    )
    await run_agent(str(run.id), agent_name, case_id, question)
    refreshed = await _refresh_run_or_none(run, "agent execution")
    if refreshed is None:
        return run
    run = refreshed

    # Always record the escalation decision for completed runs so the routing
    # action is visible in run.metadata regardless of how the run was triggered.
    if run.status == AgentRun.STATUS_COMPLETED:
        from ..policy.workflow import apply_escalation_policy

        await sync_to_async(apply_escalation_policy, thread_sensitive=True)(run)
        refreshed = await _refresh_run_or_none(run, "escalation policy")
        if refreshed is None:
            return run
        run = refreshed

    # Execute the TheHive side-effect (case update, comment) only for automatic
    # runs — interactive sessions let the analyst decide whether to act.
    if trigger != AgentRun.TRIGGER_INTERACTIVE and run.status == AgentRun.STATUS_COMPLETED:
        from ..policy.escalation import execute_escalation

        await sync_to_async(execute_escalation, thread_sensitive=True)(run)
        refreshed = await _refresh_run_or_none(run, "escalation execution")
        if refreshed is None:
            return run
        run = refreshed

    return run


def dispatch_run_sync(
    agent_name: str,
    case_id: str,
    question: str,
    *,
    trigger: str = AgentRun.TRIGGER_AUTO,
    handoff: Optional[Handoff] = None,
    metadata: Optional[dict] = None,
) -> AgentRun:
    """Blocking entry for headless callers (management commands, workflow bindings)."""
    return asyncio.run(
        dispatch_run(
            agent_name,
            case_id,
            question,
            trigger=trigger,
            handoff=handoff,
            metadata=metadata,
        )
    )
