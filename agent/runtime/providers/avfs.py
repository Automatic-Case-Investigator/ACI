"""AVFS filesystem provider (streamable HTTP)."""
from __future__ import annotations

from django.conf import settings

from .base import KIND_FILESYSTEM, MCPProvider
from .registry import register


def _defaults() -> dict:
    return {
        "url": settings.AVFS_URL,
        "auth_token": settings.AVFS_AUTH_TOKEN,
        "agent_id": settings.AVFS_AGENT_ID,
    }


def _build(resolved: dict, run_ctx: dict | None = None) -> dict:
    return {
        "transport": "streamable_http",
        "url": resolved["url"],
        "headers": {"Authorization": f"Bearer {resolved['auth_token']}"},
    }


def resolved_agent_id() -> str:
    """The effective AVFS agent id (DB override over the AVFS_AGENT_ID setting)."""
    from ..config import resolve_settings

    return resolve_settings("avfs", _defaults()).get("agent_id") or settings.AVFS_AGENT_ID


register(MCPProvider(
    key="avfs",
    kind=KIND_FILESYSTEM,
    setting_defaults=_defaults,
    build_config=_build,
))
