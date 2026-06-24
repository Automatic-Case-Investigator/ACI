"""Reference workflow bindings.

One binding today — "new TheHive case → triage" — to demonstrate the seam. Add more
here as event sources come online; the dispatch path stays identical.
"""
from __future__ import annotations

from .base import EVENT_NEW_ALERT, EVENT_NEW_CASE, Trigger, WorkflowBinding
from .registry import register


def _triage_question(trigger: Trigger) -> str:
    return (
        f"A new case ({trigger.case_id}) was created. Triage it: read the case and "
        "linked alerts, diagnose the incident, and produce a prioritized investigation plan."
    )


def _alert_triage_question(trigger: Trigger) -> str:
    return (
        f"A new alert ({trigger.case_id}) was received. Triage it: inspect the alert, "
        "correlate related evidence, and decide whether it needs investigation."
    )


register(WorkflowBinding(
    event_type=EVENT_NEW_CASE,
    agent_name="triage",
    build_question=_triage_question,
))


register(WorkflowBinding(
    event_type=EVENT_NEW_ALERT,
    agent_name="triage",
    build_question=_alert_triage_question,
))
