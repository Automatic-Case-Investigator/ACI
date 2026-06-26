"""Apply analyst-editable DB overrides over the code-defined registries.

The agent and workflow registries supply defaults; the settings UI lets an analyst
override budget, tool policy, dedupe windows, and the escalation map. These
resolvers merge the DB rows over the defaults and are read by the runtime
(`run.py`, `dispatch_trigger`, `apply_escalation_policy`). All are defensive: a
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


# Code defaults, used when no EscalationRule row exists for a verdict.
DEFAULT_ESCALATION = {
    "tp": "auto_escalate",
    "fp": "auto_close",
    "inconclusive": "hold",
    "needs_investigation": "hold",
}


def resolve_escalation_map() -> dict:
    """Return the verdict → action map, DB rows overriding the code defaults."""
    out = dict(DEFAULT_ESCALATION)
    try:
        from agent.models import EscalationRule

        for row in EscalationRule.objects.all():
            out[row.verdict] = row.action
    except Exception as exc:
        log.debug("EscalationRule lookup unavailable: %s", exc)
    return out
