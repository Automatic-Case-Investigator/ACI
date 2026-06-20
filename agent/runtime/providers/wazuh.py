"""Wazuh SIEM provider (stdio subprocess)."""
from __future__ import annotations

import sys

from django.conf import settings

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
        "url": settings.WAZUH_URL,
        "host": settings.WAZUH_HOST,
        "port": settings.WAZUH_PORT,
        "user": settings.WAZUH_USER,
        "password": settings.WAZUH_PASSWORD,
        "verify_tls": settings.WAZUH_VERIFY_TLS,
        "index_pattern": settings.WAZUH_INDEX_PATTERN,
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
))
