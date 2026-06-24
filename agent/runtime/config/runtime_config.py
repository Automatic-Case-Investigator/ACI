"""Resolver for global runtime toggles that used to be env-only.

Same DB-over-env pattern as `runtime/config.py`: the `RuntimeConfig` singleton row
wins when it has an explicit value; otherwise we fall back to the env-backed Django
setting so `.env`-only deployments keep working. All DB access is defensive (the
table may not be migrated yet during early boot or tests).
"""
from __future__ import annotations

import logging

log = logging.getLogger(__name__)


def _row():
    try:
        from agent.models import RuntimeConfig

        return RuntimeConfig.objects.first()
    except Exception as exc:  # table missing, apps not ready, etc.
        log.debug("RuntimeConfig lookup unavailable: %s", exc)
        return None


def workflows_enabled() -> bool:
    """Global automatic-workflows kill switch. DB override wins over WORKFLOWS_ENABLED."""
    from django.conf import settings

    row = _row()
    if row is not None and row.workflows_enabled is not None:
        return bool(row.workflows_enabled)
    return bool(getattr(settings, "WORKFLOWS_ENABLED", False))


def baseline_adapter_name() -> str:
    """Active baseline SIEM adapter. DB override wins over BASELINE_SIEM_ADAPTER."""
    from django.conf import settings

    row = _row()
    if row is not None and row.baseline_siem_adapter:
        return row.baseline_siem_adapter
    return getattr(settings, "BASELINE_SIEM_ADAPTER", "wazuh")


def baseline_interval_hours() -> int:
    """Baseline scheduler cadence. DB override wins; applied on next server start."""
    from django.conf import settings

    row = _row()
    if row is not None and row.baseline_interval_hours:
        return int(row.baseline_interval_hours)
    return int(getattr(settings, "BASELINE_COMPUTE_INTERVAL_HOURS", 24))


def debug_mode() -> bool:
    """Debug mode: surface all internal graph tool calls and node-transition events."""
    row = _row()
    if row is not None and row.debug_mode is not None:
        return bool(row.debug_mode)
    return False


def ti_cache_ttl_hours() -> int:
    """Shared TI cache entry lifetime. DB override wins over TI_CACHE_TTL_HOURS."""
    from django.conf import settings

    row = _row()
    if row is not None and row.ti_cache_ttl_hours:
        return int(row.ti_cache_ttl_hours)
    return int(getattr(settings, "TI_CACHE_TTL_HOURS", 24))
