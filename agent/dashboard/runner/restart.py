from __future__ import annotations

import asyncio
import queue
import threading
from typing import Optional

from agent.models import AgentEvent, AgentRun
from agent.agents.base import Handoff
from agent.runtime.engine.dispatch import dispatch_run
from agent.runtime.infra import logbus
from agent.runtime.engine.run import run_agent_sync
from agent.runtime.orchestrator import OrchestratorSession, run_orchestrator

from ._base import _EVENT_DETAIL_LIMIT, _RESTARTABLE_AGENTS, _RESTART_CONTEXT_LIMIT, _append_with_limit, _clip, _events_for_run, _prior_board_entries, _prior_tasks



def can_restart_from_prior_run(run: AgentRun | None) -> bool:
    """Only budget-exhausted triage/investigation runs get a successor restart."""
    return bool(
        run
        and run.status == AgentRun.STATUS_INCOMPLETE_BUDGET
        and run.agent_name in _RESTARTABLE_AGENTS
    )


def restart_from_prior_run(source_run: AgentRun) -> AgentRun:
    """Create and start a fresh run that inherits a budget-exhausted prior run.

    This is intentionally separate from the legacy "resume" endpoint: the source
    row remains immutable evidence of the budget failure, while the successor gets
    an explicit restart context built from the prior event transcript, task queue,
    and findings board.
    """
    if not can_restart_from_prior_run(source_run):
        raise ValueError(
            f"Run cannot be restarted from status {getattr(source_run, 'status', 'unknown')}"
        )

    restart_context = _build_restart_context(source_run)
    source_meta = dict(source_run.metadata or {})
    session_id = source_meta.get("session_id") or ""
    metadata = {
        "restart": {
            "source_run_id": str(source_run.id),
            "source_status": source_run.status,
            "source_agent": source_run.agent_name,
        },
        "restart_context": restart_context,
    }
    for key in ("handoff", "orchestrator_context"):
        if key in source_meta:
            metadata[key] = source_meta[key]
    if session_id:
        metadata["session_id"] = session_id

    run = AgentRun.objects.create(
        case_id=source_run.case_id,
        agent_name=source_run.agent_name,
        question=_restart_question(source_run),
        status=AgentRun.STATUS_QUEUED,
        trigger=source_run.trigger,
        metadata=metadata,
    )

    if source_run.agent_name == "investigation":
        _copy_investigation_restart_state(source_run, run)

    _start_agent_thread(run, session_id=session_id)
    return run


def _restart_question(source_run: AgentRun) -> str:
    short_id = str(source_run.id)[:8]
    if source_run.agent_name == "triage":
        return (
            f"Restart triage for case {source_run.case_id} by inheriting prior "
            f"budget-exhausted triage run {short_id}. Continue from the prior work "
            "in the restart context and produce a complete triage report with the "
            "required verdict JSON."
        )
    return (
        f"Restart investigation for case {source_run.case_id} by inheriting prior "
        f"budget-exhausted investigation run {short_id}. Continue from the prior "
        "tasks, findings, and transcript in the restart context; avoid repeating "
        "completed work unless needed to verify evidence."
    )


def _start_agent_thread(run: AgentRun, *, session_id: str = "") -> None:
    def _target() -> None:
        token = logbus.bind_session(session_id) if session_id else None
        try:
            run_agent_sync(str(run.id), run.agent_name, run.case_id, run.question)
        finally:
            if token is not None:
                logbus.reset_session(token)

    threading.Thread(
        target=_target,
        name=f"aci-restart-{str(run.id)[:8]}",
        daemon=True,
    ).start()


def _build_restart_context(run: AgentRun) -> str:
    lines: list[str] = [
        "## Restart Source",
        f"- Source run: `{run.id}`",
        f"- Agent: `{run.agent_name}`",
        f"- Case: `{run.case_id}`",
        f"- Prior status: `{run.status}`",
        f"- Original question: {run.question}",
    ]
    if run.result:
        lines.extend(["", "## Stored Result", run.result])
    if run.error:
        lines.extend(["", "## Stored Error", run.error])

    tasks = _prior_tasks(run)
    if tasks:
        lines.extend(["", "## Prior Task Queue"])
        for task in tasks:
            lines.append(
                f"- [{task.get('status', '?')}] P{task.get('priority', '?')} "
                f"{task.get('title', '(untitled)')}"
            )
            if task.get("summary"):
                lines.append(f"  Summary: {_clip(task.get('summary', ''), 2500)}")
            if task.get("description"):
                lines.append(f"  Description: {_clip(task.get('description', ''), 1200)}")

    board_entries = _prior_board_entries(run)
    if board_entries:
        lines.extend(["", "## Prior Findings Board"])
        for entry in board_entries:
            lines.append(
                f"- {entry.get('kind', 'entry')} [{entry.get('status', 'open')}] "
                f"{entry.get('content', '')}"
            )
            if entry.get("source"):
                lines.append(f"  Source: {entry.get('source')}")

    lines.extend(["", "## Prior Event Transcript"])
    used = sum(len(line) + 1 for line in lines)
    for ev in _events_for_run(run):
        body = ev.detail or ev.summary or ""
        if ev.kind != "intent":
            body = _clip(body, _EVENT_DETAIL_LIMIT)
        block = (
            f"\n### event {ev.id} / seq {ev.seq} / {ev.source}.{ev.kind}\n"
            f"summary: {ev.summary}\n"
            f"detail:\n{body}\n"
        )
        used = _append_with_limit(lines, block, used)
        if used >= _RESTART_CONTEXT_LIMIT:
            break
    return "\n".join(lines)


def _copy_investigation_restart_state(source_run: AgentRun, new_run: AgentRun) -> None:
    """Carry unfinished queue work and board entries onto an investigation successor."""
    pending_copied = 0
    try:
        from aci_taskqueue import store as task_store

        for task in _prior_tasks(source_run):
            if task.get("status") == "completed":
                continue
            description = (task.get("description") or "").strip()
            restart_note = (
                f"\n\n## Restart inheritance\n"
                f"Copied from prior run `{source_run.id}` where this task was "
                f"`{task.get('status', 'unknown')}`. Consult the restart context "
                "before repeating tool calls."
            )
            task_store.create_task(
                new_run.case_id,
                str(new_run.id),
                new_run.agent_name,
                title=task.get("title") or "Continue inherited investigation task",
                description=description + restart_note,
                priority=int(task.get("priority") or 50),
                origin="restart",
            )
            pending_copied += 1
        if pending_copied == 0:
            task_store.create_task(
                new_run.case_id,
                str(new_run.id),
                new_run.agent_name,
                title="Synthesize investigation from inherited budget-exhausted run",
                description=(
                    f"Prior investigation run `{source_run.id}` exhausted its budget "
                    "after completing all visible queue tasks. Use the restart context, "
                    "prior findings board, and event transcript to produce the final "
                    "investigation report. Only run additional tool calls for concrete "
                    "evidence gaps."
                ),
                priority=100,
                origin="restart",
            )
    except Exception:
        pass

    try:
        from aci_board import store as board_store

        for entry in _prior_board_entries(source_run):
            board_store.add_entry(
                new_run.case_id,
                str(new_run.id),
                new_run.agent_name,
                entry.get("kind") or "fact",
                entry.get("content") or "",
                source=(
                    f"restart from {str(source_run.id)[:8]}"
                    + (f"; {entry.get('source')}" if entry.get("source") else "")
                ),
                confidence=entry.get("confidence") or "high",
                status=entry.get("status") or "open",
            )
    except Exception:
        pass

