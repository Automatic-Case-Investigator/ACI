"""TheHive SOAR provider (stdio subprocess)."""
from __future__ import annotations

import sys

from .base import KIND_SOAR, MCPProvider
from .registry import register

def _defaults() -> dict:
    return {
        "base_url": "",
        "api_key": "",
        "verify_tls": "true",
    }


def _build(resolved: dict, run_ctx: dict | None = None) -> dict:
    # The connection is a single base_url now; derive it from a legacy host/port
    # row when base_url is absent so pre-existing configs keep working.
    base_url = str(resolved.get("base_url") or "").strip()
    if not base_url and resolved.get("host"):
        host = str(resolved.get("host") or "").rstrip("/")
        base_url = f"{host}:{resolved.get('port', '9000')}" if host else ""
    return {
        "command": sys.executable,
        "args": ["-m", "aci_thehive.server"],
        "transport": "stdio",
        "env": {
            "THEHIVE_URL": base_url,
            "THEHIVE_API_KEY": str(resolved.get("api_key", "")),
            "THEHIVE_VERIFY_TLS": str(resolved.get("verify_tls", "true")),
        },
    }


register(MCPProvider(
    key="aci-thehive",
    kind=KIND_SOAR,
    setting_defaults=_defaults,
    build_config=_build,
    capabilities={
        "read_case": ("get_case",),
        "list_case_alerts": ("list_case_alerts",),
        "read_alert": ("get_alert",),
        "publish_case_report": ("post_case_report",),
        "find_related_cases": ("get_similar_cases",),
        "update_case_fields": ("update_case",),
        "post_case_note": ("post_case_comment",),
    },
))
