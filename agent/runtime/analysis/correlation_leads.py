"""Auto-correlation helpers (Fix 1).

Structural expansion of a confirmed entity — mapping its relationship
neighborhood and, for IPs, both network roles — is mechanical and must be
near-guaranteed. Leaving it to the model's tool choice failed: even handed a task
that named `correlate_entity` with exact args, the model substituted manual
search/profile queries.

So the graph performs the correlation itself (see `nodes_loop._auto_correlate_entities`),
exactly like TI enrichment: when a high-value entity is confirmed in retrieved
events, the graph calls the correlation tool, writes the grounded neighborhood to
the findings board, and the model reasons over the result instead of choosing to
produce it. This module holds the pure, testable pieces of that step.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

# Entity kinds worth auto-correlating, in priority order (attacker IPs first — the
# both-role view is the key initial-access/C2 link; then accounts).
#
# `host` is deliberately excluded: auto-correlating the monitored host returns the
# entire dataset (every event is on it), which is noise and burns a slot. The model
# can still correlate a specific discovered host manually.
_CORRELATABLE_KINDS = ("ip", "user")

# Primary/label field per kind (used to label the entity).
_FIELD = {"ip": "data.srcip", "user": "data.srcuser"}

# Fields a value may occupy for each kind. Auto-correlation matches the value in ANY
# of these (role-agnostic), so an entity is found regardless of which field holds it
# — e.g. an audit user that appears as `data.dstuser`, or an IP seen only as a
# destination. A single hardcoded field guessed wrong and produced 0-event misses.
_MATCH_FIELDS = {
    "ip": ["data.srcip", "data.dstip"],
    "user": ["data.srcuser", "data.dstuser", "data.user"],
}

# Bounds so a noisy broad sweep cannot trigger unbounded SIEM correlation work.
MAX_CORRELATIONS = 10  # per run (raised slightly to accommodate hop-2 discoveries)
MAX_PER_BATCH = 3      # seed entities per tool result
# Multi-hop expansion (Fix #2): when correlating an entity surfaces NEW high-value
# entities among its neighbors, correlate those too — a bounded breadth-first walk
# that assembles the connected incident graph instead of isolated 1-hop cards.
# Depth 0 = entities from the tool result; depth 1 = entities discovered via a
# correlation. Kept shallow so the run-wide cap, not depth, is the real bound.
MAX_HOP_DEPTH = 2

# Neighbor field -> entity kind, for discovering correlatable entities inside a
# correlation result (so a brute-force srcip whose neighbor is a dstuser expands to
# that user). Hosts are intentionally absent (see _CORRELATABLE_KINDS).
_NEIGHBOR_FIELD_KIND = {
    "data.srcip": "ip", "data.dstip": "ip",
    "data.srcuser": "user", "data.dstuser": "user", "data.user": "user",
}

# Values that are never useful correlation targets.
_JUNK_ENTITY_VALUES = {"", "?", "-", "(none)", "none", "null", "n/a", "unknown"}

_ISO_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
)
# Audit id suffix on usernames (`root(uid=0)`); neighbor-derived users carry the raw
# field value, so normalize the same way artifact extraction does.
_UID_SUFFIX_RE = re.compile(r"\s*\((?:[a-z]*uid)=\d+\)\s*$", re.IGNORECASE)


def normalize_entity_value(kind: str, value: str) -> str:
    """Normalize a neighbor-derived entity value (strip audit uid suffix for users)."""
    text = (value or "").strip()
    if kind == "user":
        text = _UID_SUFFIX_RE.sub("", text).strip()
    return text


def entities_from_neighbors(result_raw) -> list[tuple[str, str]]:
    """Extract correlatable (kind, value) entities from a correlation result.

    Walks both the primary `neighbors` and any `cross_role.neighbors`, maps each
    neighbor field to an entity kind, normalizes the value, and drops junk. These
    become the next hop of the breadth-first correlation walk (Fix #2).
    """
    if isinstance(result_raw, str):
        try:
            result = json.loads(result_raw)
        except (TypeError, ValueError):
            return []
    elif isinstance(result_raw, dict):
        result = result_raw
    else:
        return []

    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    blocks = [result.get("neighbors") or {}]
    cross = result.get("cross_role") or {}
    if isinstance(cross, dict):
        blocks.append(cross.get("neighbors") or {})
    for block in blocks:
        if not isinstance(block, dict):
            continue
        for field, entries in block.items():
            kind = _NEIGHBOR_FIELD_KIND.get(field)
            if not kind or not isinstance(entries, list):
                continue
            for e in entries:
                value = normalize_entity_value(kind, str((e or {}).get("value", "")))
                if value.lower() in _JUNK_ENTITY_VALUES:
                    continue
                key = (kind, value.lower())
                if key in seen:
                    continue
                seen.add(key)
                out.append((kind, value))
    return out


def field_for(kind: str) -> str:
    return _FIELD.get(kind, kind)


def match_fields_for(kind: str) -> list[str]:
    """Candidate fields a value of this kind may occupy (role-agnostic pin)."""
    return _MATCH_FIELDS.get(kind, [field_for(kind)])


def corr_dedup_key(kind: str, value: str) -> str:
    """Stable per-entity key so each entity is correlated at most once per run."""
    return f"corr:{kind}:{value.lower()}"


def select_targets(artifacts, *, covered: set[str], remaining_budget: int,
                   max_per_batch: int = MAX_PER_BATCH) -> list[tuple[str, str, str]]:
    """Pick (kind, value, field) entities to correlate from a batch of artifacts.

    Deduped within the batch, skips entities already covered this run, ordered by
    kind priority, and clamped to the remaining run budget and per-batch cap.
    """
    if remaining_budget <= 0:
        return []
    order = {k: i for i, k in enumerate(_CORRELATABLE_KINDS)}
    candidates = []
    for a in artifacts:
        kind = getattr(a, "kind", None)
        value = getattr(a, "value", None)
        if kind in _FIELD and value:
            candidates.append((kind, value))
    candidates.sort(key=lambda kv: order.get(kv[0], 99))

    seen: set[tuple[str, str]] = set()
    picked: list[tuple[str, str, str]] = []
    limit = min(remaining_budget, max_per_batch)
    for kind, value in candidates:
        key = (kind, value.lower())
        if key in seen:
            continue
        seen.add(key)
        if corr_dedup_key(kind, value) in covered:
            continue
        picked.append((kind, value, field_for(kind)))
        if len(picked) >= limit:
            break
    return picked


def _parse_iso(text: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    # Normalize to tz-aware UTC: Wazuh events mix timestamps with and without an
    # offset, and naive/aware datetimes cannot be compared (min/max would raise).
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def derive_window(raw: str, vicinity_hours: int) -> tuple[str | None, str | None]:
    """Bound the correlation window to the timestamps in the producing events.

    Scans the raw tool result for ISO timestamps, takes their min/max, and pads
    each side by `vicinity_hours`. Returns (None, None) when no timestamp is found
    so the correlation runs over all history rather than failing.
    """
    stamps = []
    for m in _ISO_RE.findall(raw or ""):
        dt = _parse_iso(m)
        if dt is not None:
            stamps.append(dt)
    if not stamps:
        return None, None
    pad = timedelta(hours=max(1, vicinity_hours))
    lo = (min(stamps) - pad).astimezone(timezone.utc)
    hi = (max(stamps) + pad).astimezone(timezone.utc)
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    return lo.strftime(fmt), hi.strftime(fmt)


def _render_neighbors(neighbors: dict, max_fields: int = 6, max_vals: int = 3) -> str:
    parts = []
    for field, entries in list(neighbors.items())[:max_fields]:
        vals = []
        for e in entries[:max_vals]:
            ev = (e.get("event_ids") or [])
            anchor = f"[{ev[0]}]" if ev else ""
            vals.append(f"{e.get('value')}×{e.get('count')}{anchor}")
        if vals:
            parts.append(f"{field}=" + ",".join(vals))
    return "; ".join(parts)


def summarize_correlation(kind: str, value: str, result_raw: str,
                          via: str | None = None) -> tuple[str, int, bool]:
    """Render a correlate_entity result into a compact board line.

    `via` records how this entity was discovered (the parent entity in the
    multi-hop walk), so the board reads as a connected graph rather than isolated
    cards. Returns (board_content, neighbor_field_count, has_cross_role). On an
    unparseable/error result, returns a minimal note with count 0.
    """
    try:
        r = json.loads(result_raw)
    except (TypeError, ValueError):
        r = None
    provenance = f" (via {via})" if via else ""
    if not isinstance(r, dict) or "neighbors" not in r:
        return (f"correlation[{field_for(kind)} {value}]{provenance}: no neighborhood returned", 0, False)

    neighbors = r.get("neighbors") or {}
    total = r.get("total_events", 0)
    first = (r.get("first_seen") or "")[:19]
    last = (r.get("last_seen") or "")[:19]
    span = f" ({first}→{last})" if first or last else ""
    body = _render_neighbors(neighbors)
    content = f"correlation[{field_for(kind)} {value}]{provenance} {total} ev{span}: {body}"

    cross = r.get("cross_role") or {}
    has_cross = bool(cross.get("neighbors"))
    if has_cross:
        content += (
            f" || cross_role[{cross.get('field')}] {cross.get('total_events', 0)} ev: "
            + _render_neighbors(cross.get("neighbors") or {})
        )
    if r.get("too_connected"):
        content += " [too_connected — narrow window before relying]"
    return content[:800], len(neighbors), has_cross
