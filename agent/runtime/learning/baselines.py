"""Behavioral baseline computation — SIEM-agnostic orchestration.

This module owns only the SIEM-independent policy:
- subject-selection precedence (explicit arg → operator-configured → discovery),
- the health gate (how many events make a baseline fresh / low_data / skipped),
- persistence to BaselineSnapshot.

Everything SIEM-specific (connection, field names, query language, which
features a subject yields) lives behind a baseline SIEM adapter — see
`agent/runtime/baseline_adapters/`. The active adapter is chosen by the
`BASELINE_SIEM_ADAPTER` setting.

Called from:
- agent/apps.py — nightly background thread (in-process scheduler)
- agent/management/commands/compute_baselines.py — manual one-off
- dashboard "Recompute now" — background thread
"""
from __future__ import annotations

import logging

log = logging.getLogger(__name__)

# Minimum events required to write a baseline row.
_MIN_EVENTS_LOW = 10
_MIN_EVENTS_FRESH = 50


def get_window_days() -> int:
    """Resolve the active lookback window: operator config over the setting default."""
    from django.conf import settings

    from agent.models import BaselineComputeConfig

    cfg = BaselineComputeConfig.objects.first()
    if cfg and cfg.window_days:
        return cfg.window_days
    return getattr(settings, "BASELINE_WINDOW_DAYS", 30)


def set_window_days(days: int) -> int:
    """Persist the operator-chosen lookback window. Returns the stored value."""
    from agent.models import BaselineComputeConfig

    days = max(1, int(days))
    BaselineComputeConfig.objects.update_or_create(
        id=BaselineComputeConfig.SINGLETON_ID,
        defaults={"window_days": days},
    )
    return days


def _health(event_count: int) -> str | None:
    if event_count >= _MIN_EVENTS_FRESH:
        return "fresh"
    if event_count >= _MIN_EVENTS_LOW:
        return "low_data"
    return None  # skip


def _upsert(subject_type: str, subject_id: str, feature: str, value: dict, days: int, health: str) -> None:
    from agent.models import BaselineSnapshot

    BaselineSnapshot.objects.update_or_create(
        subject_type=subject_type,
        subject_id=subject_id,
        feature=feature,
        defaults={"value": value, "window_days": days, "health": health},
    )


def _configured_subjects(subject_type: str) -> list[tuple[str, str]]:
    """Return operator-configured (subject_type, subject_id) pairs, or []."""
    from agent.models import BaselineSubjectConfig

    qs = BaselineSubjectConfig.objects.filter(enabled=True)
    if subject_type in ("user", "endpoint"):
        qs = qs.filter(subject_type=subject_type)
    return [(c.subject_type, c.subject_id) for c in qs]


def _types_for(subject_type: str) -> list[str]:
    return [subject_type] if subject_type in ("user", "endpoint") else ["user", "endpoint"]


def _process_subject(adapter, subject_type: str, subject_id: str, days: int) -> tuple[int, int]:
    """Compute, health-gate, and persist one subject's features. Returns (written, skipped)."""
    try:
        results = adapter.compute_features(subject_type, subject_id, days)
    except Exception as exc:
        log.warning("baselines: compute_features failed for %s:%s: %s", subject_type, subject_id, exc)
        return 0, 0

    written = skipped = 0
    for r in results:
        health = _health(r.event_count)
        if health and r.value:
            _upsert(subject_type, subject_id, r.feature, r.value, days, health)
            written += 1
        else:
            skipped += 1
    return written, skipped


def compute_all_baselines(
    days: int = 30,
    subject_type: str = "all",
    subject_id: str | None = None,
) -> tuple[int, int]:
    """Compute behavioral baselines and write them to BaselineSnapshot.

    Subject selection precedence:
    1. An explicit `subject_id` argument (single-subject mode).
    2. Operator-configured subjects (BaselineSubjectConfig), when any are enabled.
    3. SIEM-wide auto-discovery via the active adapter (fallback).

    Returns (written, skipped) feature counts.
    """
    from .baseline_adapters import get_active_adapter

    try:
        adapter = get_active_adapter()
    except Exception as exc:
        log.error("baselines: failed to init SIEM adapter: %s", exc)
        return 0, 0

    total_written = total_skipped = 0

    # 1. Single-subject mode
    if subject_id is not None:
        for st in _types_for(subject_type):
            w, s = _process_subject(adapter, st, subject_id, days)
            total_written += w
            total_skipped += s
        return total_written, total_skipped

    # 2. Operator-configured subjects
    configured = _configured_subjects(subject_type)
    if configured:
        for st, sid in configured:
            w, s = _process_subject(adapter, st, sid, days)
            total_written += w
            total_skipped += s
        log.info("baselines: complete (configured) — %d written, %d skipped", total_written, total_skipped)
        return total_written, total_skipped

    # 3. Auto-discovery via the adapter
    for st in _types_for(subject_type):
        try:
            subjects = adapter.discover_subjects(st, days)
        except Exception as exc:
            log.error("baselines: %s discovery failed: %s", st, exc)
            subjects = []
        for sid in subjects:
            w, s = _process_subject(adapter, st, sid, days)
            total_written += w
            total_skipped += s

    log.info("baselines: complete (discovery) — %d written, %d skipped", total_written, total_skipped)
    return total_written, total_skipped
