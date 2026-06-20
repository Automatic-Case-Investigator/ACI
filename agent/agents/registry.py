from __future__ import annotations

from .base import AgentDefinition

_REGISTRY: dict[str, AgentDefinition] = {}


def register(agent: AgentDefinition) -> AgentDefinition:
    if agent.name in _REGISTRY:
        raise ValueError(f"Agent already registered: {agent.name}")
    _REGISTRY[agent.name] = agent
    return agent


def get_agent(name: str) -> AgentDefinition | None:
    return _REGISTRY.get(name)


def list_agents() -> list[str]:
    return list(_REGISTRY.keys())


# Import agents so they self-register.
from . import investigation  # noqa: E402, F401
from . import triage  # noqa: E402, F401
