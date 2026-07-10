"""AVFS filesystem provider (streamable HTTP)."""
from __future__ import annotations

import asyncio
import logging

from django.conf import settings

from .base import KIND_FILESYSTEM, MCPProvider
from .registry import register

log = logging.getLogger(__name__)
_AGENT_ID_CACHE: str | None = None


def _defaults() -> dict:
    return {
        "url": settings.AVFS_URL,
        "auth_token": settings.AVFS_AUTH_TOKEN,
        "agent_id": settings.AVFS_AGENT_ID,
    }


def _build(resolved: dict, run_ctx: dict | None = None) -> dict:
    url = str(resolved.get("url") or "").strip()
    token = str(resolved.get("auth_token") or "").strip()
    # The placeholder token is the documented "disable AVFS" switch.
    if not url or not token or token == "change-me-avfs-token":
        log.info("AVFS is not configured; skipping workspace MCP provider")
        return {}
    return {
        "transport": "streamable_http",
        "url": url,
        "headers": {"Authorization": f"Bearer {token}"},
    }


def cache_agent_id(agent_id: str) -> str:
    """Remember a sync-resolved agent id for async contexts that cannot use ORM."""
    global _AGENT_ID_CACHE
    _AGENT_ID_CACHE = agent_id
    return agent_id


def _in_async_context() -> bool:
    try:
        asyncio.get_running_loop()
        return True
    except RuntimeError:
        return False


def resolved_agent_id() -> str:
    """The effective AVFS agent id (DB override over the AVFS_AGENT_ID setting)."""
    if _in_async_context():
        return _AGENT_ID_CACHE or settings.AVFS_AGENT_ID

    from ..config import resolve_settings

    return cache_agent_id(resolve_settings("avfs", _defaults()).get("agent_id") or settings.AVFS_AGENT_ID)


register(MCPProvider(
    key="avfs",
    kind=KIND_FILESYSTEM,
    setting_defaults=_defaults,
    build_config=_build,
    capabilities={
        "workspace_read_write": ("whoami", "ls", "read", "cat", "mkdir", "write"),
    },
    instructions_required=False,
))
