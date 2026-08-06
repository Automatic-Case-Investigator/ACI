"""Apply analyst-editable DB overrides over the code-defined registries.

The agent and workflow registries supply defaults; the settings UI lets an analyst
override budget, tool policy, dedupe windows, and the response matrix. These
resolvers merge the DB rows over the defaults and are read by the runtime
(`run.py`, `dispatch_trigger`, `apply_response_policy`). All are defensive: a
missing table (pre-migration / tests) degrades silently to the code defaults.
"""
from __future__ import annotations

import dataclasses
import logging

log = logging.getLogger(__name__)


def resolve_agent_definition(agent_def):
    """Return a copy of `agent_def` with AgentConfig overrides applied (or the
    original if there is no row / the DB is unavailable)."""
    if agent_def is None:
        return None
    try:
        from agent.models import AgentConfig

        row = AgentConfig.objects.filter(agent_name=agent_def.name).first()
    except Exception as exc:
        log.debug("AgentConfig lookup for %s unavailable: %s", agent_def.name, exc)
        return agent_def
    if row is None:
        return agent_def

    budget = dataclasses.replace(
        agent_def.budget,
        max_steps=row.max_steps if row.max_steps else agent_def.budget.max_steps,
        max_tool_calls=row.max_tool_calls if row.max_tool_calls else agent_def.budget.max_tool_calls,
    )
    tool_policy = agent_def.tool_policy
    if isinstance(row.tool_policy, list) and row.tool_policy:
        tool_policy = list(row.tool_policy)
    stream_intent = agent_def.stream_intent if row.stream_intent is None else bool(row.stream_intent)
    vicinity_window_hours = (
        row.vicinity_window_hours
        if row.vicinity_window_hours
        else agent_def.default_vicinity_window_hours
    )

    return dataclasses.replace(
        agent_def,
        budget=budget,
        tool_policy=tool_policy,
        stream_intent=stream_intent,
        default_vicinity_window_hours=vicinity_window_hours,
    )


def resolve_workflow(event_type: str, *, default_enabled: bool, default_window: int):
    """Return (enabled, dedupe_window) for a workflow event, DB row winning."""
    try:
        from agent.models import WorkflowConfig

        row = WorkflowConfig.objects.filter(event_type=event_type).first()
    except Exception as exc:
        log.debug("WorkflowConfig lookup for %s unavailable: %s", event_type, exc)
        return default_enabled, default_window
    if row is None:
        return default_enabled, default_window
    return bool(row.enabled), int(row.dedupe_window)


def resolve_response_policy() -> dict:
    """Return the ``(verdict, subject) -> action`` matrix, DB rows over code defaults.

    Rows naming a cell or action the matrix no longer offers are ignored rather than
    trusted: the code matrix is the authority on what is offerable, so a stale row
    left behind by a matrix change cannot resurrect a retired action.

    Rows saved under a retired subject (`soar_alert` / `siem_alert`, from before the
    two were merged into one `alert`) are remapped rather than dropped, so the merge
    does not silently reset an operator's configuration. A row already stored under
    the current subject always wins over a remapped legacy one.
    """
    from ..response_policy import policy

    out = dict(policy.DEFAULT_ACTIONS)
    try:
        from agent.models import ResponsePolicy

        rows = list(ResponsePolicy.objects.all())
        # Legacy first, so a current-subject row overwrites anything remapped onto it.
        rows.sort(key=lambda r: r.subject in policy.LEGACY_SUBJECTS, reverse=True)
        for row in rows:
            subject = policy.LEGACY_SUBJECTS.get(row.subject, row.subject)
            key = (row.verdict, subject)
            if key in policy.ALLOWED_ACTIONS and policy.is_allowed(*key, row.action):
                out[key] = row.action
    except Exception as exc:
        log.debug("ResponsePolicy lookup unavailable: %s", exc)
    return out
