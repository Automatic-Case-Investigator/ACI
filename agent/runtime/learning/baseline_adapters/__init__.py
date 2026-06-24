"""Baseline SIEM adapters.

Importing this package registers the built-in adapters. To add a SIEM backend,
create a module here that calls `register_adapter(...)` and import it below.
"""
from . import wazuh  # noqa: F401  (registers the "wazuh" adapter)

from .base import BaselineSIEMAdapter, FeatureResult
from .registry import (
    active_adapter_name,
    adapter_meta,
    get_active_adapter,
    get_adapter,
    list_adapters,
    register_adapter,
)

__all__ = [
    "BaselineSIEMAdapter",
    "FeatureResult",
    "active_adapter_name",
    "adapter_meta",
    "get_active_adapter",
    "get_adapter",
    "list_adapters",
    "register_adapter",
]
