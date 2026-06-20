"""AVFS filesystem provider (streamable HTTP)."""
from __future__ import annotations

from django.conf import settings

from .base import KIND_FILESYSTEM, MCPProvider
from .registry import register


def _defaults() -> dict:
    return {
        "url": settings.AVFS_URL,
        "auth_token": settings.AVFS_AUTH_TOKEN,
    }


def _build(resolved: dict, run_ctx: dict | None = None) -> dict:
    return {
        "transport": "streamable_http",
        "url": resolved["url"],
        "headers": {"Authorization": f"Bearer {resolved['auth_token']}"},
    }


register(MCPProvider(
    key="avfs",
    kind=KIND_FILESYSTEM,
    setting_defaults=_defaults,
    build_config=_build,
))
