"""Self-registering provider registry (same pattern as agents/registry.py)."""
from __future__ import annotations

from .base import MCPProvider

_REGISTRY: dict[str, MCPProvider] = {}


def register(provider: MCPProvider) -> MCPProvider:
    _REGISTRY[provider.key] = provider
    return provider


def get_provider(key: str) -> MCPProvider | None:
    return _REGISTRY.get(key)


def list_providers() -> list[MCPProvider]:
    return list(_REGISTRY.values())


# Import provider modules so they self-register.
from . import avfs       # noqa: E402, F401
from . import board      # noqa: E402, F401
from . import thehive    # noqa: E402, F401
from . import wazuh      # noqa: E402, F401
from . import taskqueue  # noqa: E402, F401
from . import memory     # noqa: E402, F401
