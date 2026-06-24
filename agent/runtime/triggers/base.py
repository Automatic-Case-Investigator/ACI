"""Workflow trigger seam (foundation only — no event ingestion yet).

Defines the *interface* an automatic workflow uses: an event (`Trigger`) maps to an
agent run via a `WorkflowBinding`. The real event sources (TheHive/Wazuh webhooks or
pollers) land next sprint; today a binding is invoked manually (management command)
to prove the path that ingestion will reuse — every binding ultimately calls
`runtime.dispatch.dispatch_run`, the same headless entry used elsewhere.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

# Canonical event types a future event source can emit.
EVENT_NEW_CASE = "new_case"
EVENT_NEW_ALERT = "new_alert"


@dataclass(frozen=True)
class Trigger:
    """A single occurrence the platform reacts to."""
    event_type: str
    case_id: str
    payload: dict


async def dispatch_trigger(
    trigger: "Trigger",
    *,
    emit_triggered: bool = True,
    dedupe_window_override: int | None = None,
    metadata_extra: dict | None = None,
):
    """Resolve a trigger's binding and launch its run (with dedup + escalation).

    Returns the AgentRun (which may be a pre-existing one if deduplicated), or None
    if no enabled binding handles the event type. The single automatic entry point
    a webhook/poller calls.
    """
    from .registry import get_binding
    from ..engine.dispatch import dispatch_run
    from ...models import AgentRun
    from ..infra.logbus import emit

    binding = get_binding(trigger.event_type)
    if binding is None:
        return None

    from asgiref.sync import sync_to_async
    from ..config.runtime_config import workflows_enabled

    if not await sync_to_async(workflows_enabled, thread_sensitive=True)():
        return None

    # Apply analyst-editable workflow overrides (enabled / dedupe window).
    from ..config.overrides import resolve_workflow

    enabled, dedupe_window = await sync_to_async(resolve_workflow, thread_sensitive=True)(
        trigger.event_type,
        default_enabled=binding.enabled,
        default_window=binding.dedupe_window,
    )
    if not enabled:
        return None
    if dedupe_window_override is not None:
        dedupe_window = max(0, int(dedupe_window_override))

    if emit_triggered:
        emit("workflow", "triggered",
             f"{trigger.event_type} → {binding.agent_name} (case {trigger.case_id})")

    return await dispatch_run(
        binding.agent_name,
        trigger.case_id,
        binding.build_question(trigger),
        trigger=AgentRun.TRIGGER_AUTO,
        dedupe_window=dedupe_window,
        metadata={
            "trigger_event": trigger.event_type,
            "trigger_payload": trigger.payload,
            **(metadata_extra or {}),
        },
    )


@dataclass(frozen=True)
class WorkflowBinding:
    """Binds an event type to an agent run.

    `build_question(trigger) -> str` produces the run's question/objective from the
    event. `agent_name` must name a registered agent. `dedupe_window` (seconds)
    suppresses duplicate runs for the same case+agent within the window; 0 disables.
    """
    event_type: str
    agent_name: str
    build_question: Callable[[Trigger], str]
    enabled: bool = True
    dedupe_window: int = 600
