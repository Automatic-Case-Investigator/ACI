from __future__ import annotations

"""Event extraction: pull event dicts / ids / fields out of tool-result JSON."""

import json

from .trials import _EVENT_CONTAINER_KEYS, _EVENT_ID_KEYS


# ── Event extraction: pull event dicts / ids / fields out of tool-result JSON ──
def _flatten(value, prefix: str = ""):
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            yield from _flatten(child, path)
    elif isinstance(value, list):
        for child in value:
            yield from _flatten(child, prefix)
    else:
        yield prefix.lower(), value


def _source_id(event: dict) -> str:
    flattened = dict(_flatten(event))
    for key in _EVENT_ID_KEYS:
        value = flattened.get(key)
        if value not in (None, ""):
            return str(value)
        for path, nested_value in flattened.items():
            if path.endswith(f".{key}") and nested_value not in (None, ""):
                return str(nested_value)
    return ""


def _event_dicts(obj) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()

    def add(event: dict) -> None:
        source = _source_id(event)
        if source:
            key = f"id:{source}"
        else:
            try:
                key = "raw:" + json.dumps(event, sort_keys=True, default=str)
            except TypeError:
                key = f"obj:{id(event)}"
        if key in seen:
            return
        seen.add(key)
        out.append(event)

    def add_items(items) -> None:
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    add(item)

    def walk(value) -> None:
        if isinstance(value, list):
            add_items(value)
            return
        if not isinstance(value, dict):
            return

        found_container = False
        for key in _EVENT_CONTAINER_KEYS:
            items = value.get(key)
            if isinstance(items, list):
                found_container = True
                add_items(items)
            elif key == "hits" and isinstance(items, dict):
                nested_hits = items.get("hits")
                if isinstance(nested_hits, list):
                    found_container = True
                    add_items(nested_hits)

        data = value.get("data")
        if isinstance(data, (dict, list)):
            walk(data)

        if not found_container and _source_id(value):
            add(value)

    walk(obj)
    return out


def _event_fields(event: dict) -> dict:
    flattened = dict(_flatten(event))
    source = event.get("_source") if isinstance(event, dict) else None
    if isinstance(source, dict):
        for key, value in _flatten(source):
            flattened.setdefault(key, value)
    return flattened


def _event_ids(obj) -> list[str]:
    out: list[str] = []
    for event in _event_dicts(obj):
        value = _source_id(event)
        if value:
            out.append(str(value))
    return out[:8]


def _first_present(event: dict, names: tuple[str, ...]) -> str:
    for name in names:
        value = event.get(name)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _clip(value: object, limit: int = 320) -> str:
    text = " ".join(str(value or "").split())
    if len(text) > limit:
        return text[: limit - 3].rstrip() + "..."
    return text
