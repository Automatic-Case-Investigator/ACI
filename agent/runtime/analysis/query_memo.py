"""Query + schema memoization (Phase 1 #13/#18).

A diagnosed run issued the same over-broad SIEM query shape
(`"wazuh-client 172.17.130.196"`) in five separate tasks, each returning 1.2M+ hits,
and each task independently re-derived "that query is useless, narrow it." This module
turns that into a once-per-run board fact:

- **Query memo** — when a `search`/`search_keyword` returns at/near the result ceiling,
  record the normalized query SHAPE (terms / filter fields, time range excluded) plus
  the hit count, so later tasks see "this shape returned N hits — add a discriminator"
  instead of re-paying the broad-query tax.
- **Schema fields** — when `get_index_schema` returns the field mapping, record the
  field vocabulary once so later tasks reuse it instead of re-deriving field names.

Pure and deterministic; the graph (use_tools) records these to the findings board and
`_format_board_context` surfaces them at task start.
"""
from __future__ import annotations

import json

# A search/search_keyword result at or above this many hits is too broad to be useful
# as evidence — it matches a large slice of the dataset. (OpenSearch also commonly caps
# returned totals at 10000.) Recording the shape steers later tasks to narrow first.
BROAD_HIT_THRESHOLD = 10000

# Tools whose results carry a hit count worth memoizing as a query shape.
_SEARCH_TOOLS = frozenset({"search", "search_keyword"})

# Fields whose VALUES are volatile/irrelevant to a query's identity (time bounds).
_VOLATILE_FIELDS = frozenset({"@timestamp", "timestamp"})


def _load(raw) -> dict | None:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            obj = json.loads(raw)
        except (TypeError, ValueError):
            return None
        return obj if isinstance(obj, dict) else None
    return None


def extract_hit_count(raw) -> int | None:
    """Return the hit count of a SIEM result, mirroring summarize_result's logic.

    Uses max(reported total, len(events)) because OpenSearch short-circuits total
    counting (track_total_hits=False) and can report 0 while returning events.
    Returns None when the result is not a search-shaped payload.
    """
    obj = _load(raw)
    if obj is None or ("total" not in obj and "events" not in obj):
        return None
    events = obj.get("events") or []
    n_total = obj.get("total")
    if n_total is None:
        n_total = len(events)
    try:
        n_total = int(n_total)
    except (TypeError, ValueError):
        n_total = 0
    return max(n_total, len(events) if isinstance(events, list) else 0)


def _collect_dsl_terms(node, out: list[str]) -> None:
    """Recursively collect `field=value` / `field` identity tokens from a query DSL,
    excluding volatile time fields and request-level keys."""
    if isinstance(node, dict):
        for key, val in node.items():
            if key in ("term", "match", "match_phrase", "term_set"):
                if isinstance(val, dict):
                    for field, spec in val.items():
                        if field in _VOLATILE_FIELDS:
                            continue
                        value = spec.get("value") if isinstance(spec, dict) else spec
                        out.append(f"{field}={str(value).lower()}" if value is not None else field)
                continue
            if key in ("terms", "range", "exists", "wildcard", "prefix"):
                if isinstance(val, dict):
                    for field in val:
                        if field not in _VOLATILE_FIELDS:
                            out.append(field)
                continue
            _collect_dsl_terms(val, out)
    elif isinstance(node, list):
        for item in node:
            _collect_dsl_terms(item, out)


def normalize_query_shape(tool_name: str, args: dict) -> str | None:
    """Return a stable, time-range-independent signature of a search query, or None.

    For `search_keyword` the shape is its sorted keyword terms; for `search` it is the
    sorted set of filter `field=value` / `field` tokens from the DSL. Two queries that
    differ only by time window or result limit get the same shape, so a broad shape is
    recognized regardless of which task issued it.
    """
    if tool_name not in _SEARCH_TOOLS or not isinstance(args, dict):
        return None
    if tool_name == "search_keyword":
        query = args.get("query")
        if not isinstance(query, str) or not query.strip():
            return None
        terms = sorted({t.lower() for t in query.split() if t.strip()})
        return "kw:" + ",".join(terms) if terms else None
    # search: structural DSL
    query = args.get("query")
    tokens: list[str] = []
    _collect_dsl_terms(query, tokens)
    uniq = sorted(set(tokens))
    return "dsl:" + ",".join(uniq) if uniq else None


def broad_query_memo(tool_name: str, args: dict, raw) -> tuple[str, str] | None:
    """If a search returned at/above the broad threshold, return (dedup_key, content)
    for a board query-memo entry; else None."""
    shape = normalize_query_shape(tool_name, args)
    if shape is None:
        return None
    hits = extract_hit_count(raw)
    if hits is None or hits < BROAD_HIT_THRESHOLD:
        return None
    content = (
        f"query shape `{shape}` via {tool_name} returned {hits:,}+ hits — too broad to "
        f"cite. Add a discriminator before reusing it: rule.id, an exact path/command "
        f"fragment, a file hash, or a tight time window."
    )
    return f"qmemo:{shape}", content


def extract_schema_fields(tool_name: str, raw, *, limit: int = 60) -> list[str] | None:
    """Return field names from a get_index_schema result, or None.

    Accepts the common shapes: {"fields": [...]}, {"fields": {name: type}}, or
    {"mappings": {... "properties": {...}}}.
    """
    if tool_name != "get_index_schema":
        return None
    obj = _load(raw)
    if obj is None:
        return None
    fields = obj.get("fields")
    names: list[str] = []
    if isinstance(fields, dict):
        names = list(fields.keys())
    elif isinstance(fields, list):
        for f in fields:
            if isinstance(f, str):
                names.append(f)
            elif isinstance(f, dict):
                name = f.get("name") or f.get("field")
                if name:
                    names.append(str(name))
    if not names:
        props = (((obj.get("mappings") or {}).get("properties")) or {})
        if isinstance(props, dict):
            names = list(props.keys())
    if not names:
        return None
    return sorted(set(names))[:limit]
