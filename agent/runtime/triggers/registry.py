"""Self-registering workflow-binding registry."""
from __future__ import annotations

from .base import WorkflowBinding

_BINDINGS: dict[str, WorkflowBinding] = {}


def register(binding: WorkflowBinding) -> WorkflowBinding:
    _BINDINGS[binding.event_type] = binding
    return binding


def get_binding(event_type: str) -> WorkflowBinding | None:
    return _BINDINGS.get(event_type)


def list_bindings() -> list[WorkflowBinding]:
    return list(_BINDINGS.values())


# Import bindings so they self-register.
from . import bindings  # noqa: E402, F401
