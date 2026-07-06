"""Small, pure time/pivot helpers shared across the graph nodes.

These were copy-pasted (and had begun to drift) across ``nodes_loop``, ``observation``,
and ``nodes_flow``. They live here so there is a single definition each node imports.

Scope note: this owns the UTC-normalizing ``_parse_dt``. It deliberately does NOT absorb
``nodes_flow._parse_iso``, which is a distinct contract — that one parses ISO timestamps
*without* forcing them to UTC and is used where naive/local comparisons are intended.
"""
from __future__ import annotations

from datetime import datetime, timezone


def _parse_dt(value) -> datetime | None:
    """Parse an ISO-8601 string into a timezone-aware UTC ``datetime`` (or ``None``).

    Accepts a trailing ``Z``; backfills UTC for naive inputs so all downstream
    comparisons are apples-to-apples in UTC.
    """
    text = str(value or "").strip()
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _format_dt(dt: datetime) -> str:
    """Render a ``datetime`` as a second-precision UTC ISO string ending in ``Z``."""
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _find_timestamp_range(obj) -> tuple[str | None, str | None]:
    """Recursively locate a ``@timestamp``/``timestamp`` range ``(gte, lte)`` inside a
    structured query DSL. Returns ``(None, None)`` when none is present.

    Checks both ``@timestamp`` (Wazuh/OpenSearch) and the bare ``timestamp`` key — the
    superset of the three former copies — so a range filter is found regardless of which
    spelling the query used.
    """
    if isinstance(obj, dict):
        timestamp_range = obj.get("@timestamp") or obj.get("timestamp")
        if isinstance(timestamp_range, dict):
            return timestamp_range.get("gte"), timestamp_range.get("lte")
        for value in obj.values():
            found = _find_timestamp_range(value)
            if found != (None, None):
                return found
    elif isinstance(obj, list):
        for value in obj:
            found = _find_timestamp_range(value)
            if found != (None, None):
                return found
    return None, None


def _pivot_key(field: str, value: str) -> str:
    """Canonical dedup key for a pivot: lowercased field + verbatim value.

    Canonical signature is ``(field, value)``; dict-holding callers unwrap with
    ``_pivot_key(p.get("field") or "", p.get("value") or "")``.
    """
    return f"{str(field or '').strip().lower()}::{str(value or '').strip()}"
