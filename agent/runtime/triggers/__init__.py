"""Workflow trigger seam. Import `registry` to access registered bindings."""
from .base import EVENT_NEW_ALERT, EVENT_NEW_CASE, Trigger, WorkflowBinding  # noqa: F401
from .registry import get_binding, list_bindings, register  # noqa: F401


def fire(trigger: Trigger):
    """Run the binding for `trigger.event_type` headlessly, returning the AgentRun.

    Returns None if no enabled binding matches. This is the single function a future
    event source (webhook/poller) will call; it intentionally has no transport
    assumptions of its own.
    """
    from ..dispatch import dispatch_run_sync
    from ...models import AgentRun

    binding = get_binding(trigger.event_type)
    if binding is None or not binding.enabled:
        return None
    question = binding.build_question(trigger)
    return dispatch_run_sync(
        binding.agent_name,
        trigger.case_id,
        question,
        trigger=AgentRun.TRIGGER_AUTO,
        metadata={"workflow_event": trigger.event_type, "workflow_payload": trigger.payload},
    )
