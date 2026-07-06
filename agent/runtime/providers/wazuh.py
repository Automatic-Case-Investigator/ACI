"""Wazuh SIEM provider (stdio subprocess)."""
from __future__ import annotations

import sys

from .base import KIND_SIEM, MCPProvider
from .registry import register

# settings key -> env var the aci_wazuh subprocess expects
_ENV_MAP = {
    "url": "WAZUH_URL",
    "host": "WAZUH_HOST",
    "port": "WAZUH_PORT",
    "user": "WAZUH_USER",
    "password": "WAZUH_PASSWORD",
    "verify_tls": "WAZUH_VERIFY_TLS",
    "index_pattern": "WAZUH_INDEX_PATTERN",
}


def _defaults() -> dict:
    return {
        "url": "",
        "host": "",
        "port": "9200",
        "user": "admin",
        "password": "",
        "verify_tls": "false",
        "index_pattern": "wazuh-alerts-*",
    }


def _build(resolved: dict, run_ctx: dict | None = None) -> dict:
    return {
        "command": sys.executable,
        "args": ["-m", "aci_wazuh.server"],
        "transport": "stdio",
        "env": {env: str(resolved[key]) for key, env in _ENV_MAP.items()},
    }


register(MCPProvider(
    key="aci-wazuh",
    kind=KIND_SIEM,
    setting_defaults=_defaults,
    build_config=_build,
    capabilities={
        "search_events": ("search",),
        "fetch_event": ("get_event",),
        "inspect_schema": ("get_index_schema", "list_indices"),
        "profile_field_values": ("profile_field",),
        "quick_search": ("search_keyword",),
        "correlate_entity": ("correlate_entity", "correlate_techniques"),
        "summarize_volume": ("get_event_volume",),
    },
))
