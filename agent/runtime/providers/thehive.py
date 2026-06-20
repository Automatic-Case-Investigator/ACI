"""TheHive SOAR provider (stdio subprocess)."""
from __future__ import annotations

import sys

from django.conf import settings

from .base import KIND_SOAR, MCPProvider
from .registry import register

# settings key -> env var the aci_thehive subprocess expects
_ENV_MAP = {
    "host": "THEHIVE_HOST",
    "port": "THEHIVE_PORT",
    "api_key": "THEHIVE_API_KEY",
    "verify_tls": "THEHIVE_VERIFY_TLS",
}


def _defaults() -> dict:
    return {
        "host": settings.THEHIVE_HOST,
        "port": settings.THEHIVE_PORT,
        "api_key": settings.THEHIVE_API_KEY,
        "verify_tls": settings.THEHIVE_VERIFY_TLS,
    }


def _build(resolved: dict, run_ctx: dict | None = None) -> dict:
    return {
        "command": sys.executable,
        "args": ["-m", "aci_thehive.server"],
        "transport": "stdio",
        "env": {env: str(resolved[key]) for key, env in _ENV_MAP.items()},
    }


register(MCPProvider(
    key="aci-thehive",
    kind=KIND_SOAR,
    setting_defaults=_defaults,
    build_config=_build,
))
