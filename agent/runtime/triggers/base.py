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


@dataclass(frozen=True)
class WorkflowBinding:
    """Binds an event type to an agent run.

    `build_question(trigger) -> str` produces the run's question/objective from the
    event. `agent_name` must name a registered agent.
    """
    event_type: str
    agent_name: str
    build_question: Callable[[Trigger], str]
    enabled: bool = True
