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

from ..agents.base import Handoff
from ..models import AgentRun
from .run import run_agent


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
) -> AgentRun:
    """Create and run one agent run to completion; return the refreshed AgentRun."""
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
    await run.arefresh_from_db()
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
