"""AVFS filesystem provider (streamable HTTP)."""
from __future__ import annotations

import logging

from django.conf import settings

from .base import KIND_FILESYSTEM, MCPProvider
from .registry import register

log = logging.getLogger(__name__)


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


def resolved_agent_id() -> str:
    """The effective AVFS agent id (DB override over the AVFS_AGENT_ID setting)."""
    from ..config import resolve_settings

    return resolve_settings("avfs", _defaults()).get("agent_id") or settings.AVFS_AGENT_ID


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
