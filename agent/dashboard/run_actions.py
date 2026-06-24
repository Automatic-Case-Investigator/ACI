"""Unified stop/delete lifecycle for agent runs.

A run is stopped/deleted differently depending on what kind it is:

- An **orchestrator live session** is driven by an in-process daemon thread
  (`runner.py`), so stopping it means cancelling that thread's asyncio loop.
- A **specialist / automatic-workflow run** executes inside the LangGraph loop,
  which cannot be pre-empted from outside; stopping it sets a cooperative
  `cancel_requested` flag that the graph polls at its guard points.

`stop_run` / `delete_run` hide that split so callers (the runs management page and
the index-page session delete) don't have to special-case it. This lives in its own
module to avoid a circular import between `runner.py` and `views.py`.
"""
from __future__ import annotations

from agent.models import AgentEvent, AgentRun, FeedbackEntry

# Non-terminal statuses — a run in any of these is still "in progress". Mirrors
# `agent.views.ActiveRunsView.ACTIVE_STATES`; redefined here so the dashboard path
# doesn't import the DRF view layer.
ACTIVE_STATES = (
    AgentRun.STATUS_CREATED,
    AgentRun.STATUS_QUEUED,
    AgentRun.STATUS_RUNNING,
    AgentRun.STATUS_WAITING,
)


def humanize_age(seconds: int) -> str:
    """Compact human age, e.g. 45s / 12m / 3h / 2d. Shared by the runs + index views."""
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"


def is_orchestrator_session(run: AgentRun) -> bool:
    """True for an interactive live session (the chatbox), whose id is its own
    session_id and whose lifecycle is owned by `runner.py`."""
    return run.agent_name == "orchestrator" and run.trigger == AgentRun.TRIGGER_INTERACTIVE


def is_orphaned_interactive_child(run: AgentRun) -> bool:
    """True for a specialist run whose live-session parent has been deleted."""
    if run.trigger != AgentRun.TRIGGER_INTERACTIVE or run.agent_name == "orchestrator":
        return False
    session_id = (run.metadata or {}).get("session_id")
    return bool(session_id) and not AgentRun.objects.filter(id=session_id).exists()


# Real terminal outcomes we keep showing verbatim (rather than collapsing to
# "completed") because the distinction matters to an analyst.
_TERMINAL_DISTINCT = (
    AgentRun.STATUS_FAILED,
    AgentRun.STATUS_BLOCKED,
    AgentRun.STATUS_CANCELLED,
    AgentRun.STATUS_INCOMPLETE_BUDGET,
)


def is_inferring(run: AgentRun) -> bool:
    """True only while the run is actively awaiting an agent inference.

    Orchestrator sessions idle at RUNNING between turns, so we ask the runner
    whether a turn is currently in flight; specialist / automatic runs are
    inferring exactly while their graph executes (status RUNNING).
    """
    if is_orchestrator_session(run):
        from .runner import is_processing
        return is_processing(str(run.id))
    return run.status == AgentRun.STATUS_RUNNING


def display_status(run: AgentRun) -> str:
    """Status to show in the UI: ``running`` only while inferring, otherwise the
    real terminal outcome, otherwise ``completed``. Idle sessions and queued/waiting
    runs read as completed — they are not occupying an inference slot."""
    if is_inferring(run):
        return AgentRun.STATUS_RUNNING
    if run.status in _TERMINAL_DISTINCT:
        return run.status
    return AgentRun.STATUS_COMPLETED


def stop_run(run: AgentRun) -> None:
    """Stop an in-progress run, dispatching to the correct mechanism for its kind.

    Best-effort for specialists (cooperative flag, applied at the next graph guard
    point); a hard asyncio cancel for orchestrator sessions.
    """
    if is_orchestrator_session(run):
        # Local import: runner.py imports this module transitively via views.
        from .runner import stop_session
        stop_session(str(run.id))

    if run.status in ACTIVE_STATES:
        run.status = AgentRun.STATUS_CANCELLED
        run.metadata = {**(run.metadata or {}), "cancel_requested": True}
        run.save(update_fields=["status", "metadata", "updated_at"])


def delete_run(run: AgentRun) -> None:
    """Stop the run if it's still active, then remove it and all of its artifacts.

    AgentEvents are keyed by `session_id`, which equals the run id for both
    orchestrator sessions and standalone auto runs, so one filtered delete covers
    every row type (a session's child-specialist events live under the same
    session_id and are purged here too).
    """
    rid = str(run.id)
    runs = [run]
    session_id = rid
    if is_orchestrator_session(run):
        children = list(AgentRun.objects.filter(metadata__session_id=rid))
        runs.extend(children)
    elif run.trigger == AgentRun.TRIGGER_INTERACTIVE:
        parent_id = (run.metadata or {}).get("session_id")
        if parent_id:
            session_id = str(parent_id)

    for item in runs:
        if item.status in ACTIVE_STATES:
            stop_run(item)

    run_ids = [str(item.id) for item in runs]
    AgentEvent.objects.filter(session_id=session_id).delete()
    FeedbackEntry.objects.filter(run_id__in=run_ids).delete()
    AgentRun.objects.filter(id__in=run_ids).delete()
