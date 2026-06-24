"""Settings resolver: DB-backed provider config with env/settings fallback.

Providers (runtime/providers) describe *which* connection fields they need and how
to turn them into an MCP server config. This module answers *what the values are*:
it prefers a `ProviderConfig` row from the database (editable in Django admin / a
future settings UI) and falls back to the env-backed values in `settings.py` so
existing `.env`-only deployments keep working untouched.

Everything here is defensive: the DB may not be migrated yet (early boot, tests),
so DB access is wrapped and silently yields to the env defaults.
"""
from __future__ import annotations

import logging

log = logging.getLogger(__name__)

# Provider categories that drive what the settings UI lets an analyst do.
#
# - INTERNAL: platform plumbing (queue, board, memory, workspace). Always enabled,
#   never user-configurable or deletable — the runtime depends on them.
# - DEFAULT: the bundled SIEM/SOAR implementations. Configurable and replaceable
#   (enable/disable, edit connection settings) but not deletable.
# Anything else is a user-added custom MCP server (MCPServerConfig) with full CRUD.
INTERNAL_PROVIDERS = frozenset({"aci-taskqueue", "aci-board", "aci-memory", "avfs"})
DEFAULT_PROVIDERS = frozenset({"aci-thehive", "aci-wazuh"})


def provider_category(key: str) -> str:
    if key in INTERNAL_PROVIDERS:
        return "internal"
    if key in DEFAULT_PROVIDERS:
        return "default"
    return "custom"


def _db_row(key: str):
    """Return the ProviderConfig row for `key`, or None if unavailable.

    Never raises: a missing table (pre-migration), app-registry timing, or any DB
    error degrades to None so callers fall back to env defaults.
    """
    try:
        from agent.models import ProviderConfig

        return ProviderConfig.objects.filter(key=key).first()
    except Exception as exc:  # table missing, apps not ready, etc.
        log.warning("ProviderConfig lookup for %s unavailable: %s", key, exc)
        return None


def resolve_settings(key: str, defaults: dict) -> dict:
    """Merge the DB row's `settings` JSON over the provider's env-backed defaults.

    `defaults` comes from the provider (pulled from django settings). DB values win
    when present and non-empty so an admin can override a single field without
    re-specifying the rest.
    """
    resolved = dict(defaults)
    row = _db_row(key)
    if row and isinstance(row.settings, dict):
        for field, value in row.settings.items():
            if value not in (None, ""):
                resolved[field] = value
    return resolved


def is_enabled(key: str, default: bool = True) -> bool:
    """Whether a provider is enabled. DB row wins; absent row uses `default`.

    Internal providers are platform plumbing and are ALWAYS enabled — a DB row can
    never disable them, so the runtime can rely on the queue/board/memory/workspace.
    """
    if key in INTERNAL_PROVIDERS:
        return True
    row = _db_row(key)
    if row is None:
        return default
    return bool(row.enabled)
