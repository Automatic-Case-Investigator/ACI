"""Registry for baseline SIEM adapters.

Adapters register a factory (a zero-arg callable returning an adapter instance)
under a stable name, optionally with UI metadata (e.g. how an operator should
phrase a subject ID for that SIEM). The active adapter is selected by the
`BASELINE_SIEM_ADAPTER` setting (default: "wazuh"). Adding support for a new
SIEM = drop a module in this package that calls `register_adapter` and import it
from `__init__`.
"""
from __future__ import annotations

from typing import Callable

from .base import BaselineSIEMAdapter

_FACTORIES: dict[str, Callable[[], BaselineSIEMAdapter]] = {}
_META: dict[str, dict] = {}


def register_adapter(
    name: str,
    factory: Callable[[], BaselineSIEMAdapter],
    *,
    subject_id_hint: str = "",
) -> None:
    _FACTORIES[name] = factory
    _META[name] = {"subject_id_hint": subject_id_hint}


def list_adapters() -> list[str]:
    return sorted(_FACTORIES)


def adapter_meta(name: str) -> dict:
    """Return UI metadata for an adapter without instantiating it (no SIEM call)."""
    return _META.get(name, {})


def active_adapter_name() -> str:
    from ...config.runtime_config import baseline_adapter_name

    return baseline_adapter_name()


def get_adapter(name: str) -> BaselineSIEMAdapter:
    factory = _FACTORIES.get(name)
    if factory is None:
        raise ValueError(
            f"Unknown baseline SIEM adapter: {name!r}. Registered: {sorted(_FACTORIES)}"
        )
    return factory()


def get_active_adapter() -> BaselineSIEMAdapter:
    """Return an instance of the adapter named by BASELINE_SIEM_ADAPTER."""
    return get_adapter(active_adapter_name())
