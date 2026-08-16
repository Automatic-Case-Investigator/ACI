from __future__ import annotations

"""Signals, recommended moves, and error recovery."""

from ...analysis.query_memo import extract_hit_count

from .events import _clip
from .trials import _INVALID_TIME_RE, _PROFILE_TOOLS, _SEARCH_TOOLS, _TASK_WINDOW_RE, _load


# ── Signals, recommended moves, and error recovery ──
def _error_recovery(tool_name: str, raw) -> dict | None:
    text = ""
    if isinstance(raw, str):
        stripped = raw.strip()
        if stripped.startswith("Error:"):
            text = stripped
    else:
        obj = _load(raw)
        if isinstance(obj, dict) and obj.get("error"):
            text = str(obj.get("error") or "").strip()
    if not text:
        return None

    recovery = {
        "tool": tool_name,
        "error": _clip(text, 500),
        "signal": "TOOL_ERROR",
    }
    invalid = _INVALID_TIME_RE.search(text)
    if invalid:
        recovery["signal"] = "INVALID_TIME_WINDOW"
        recovery["requested_window"] = {
            "from": invalid.group(1),
            "to": invalid.group(2),
        }
    task_window = _TASK_WINDOW_RE.search(text)
    if task_window:
        recovery["required_window"] = {
            "from": task_window.group(1),
            "to": task_window.group(2),
        }
    return recovery


def _recommended_moves(signals: list[str]) -> list[str]:
    mapping = {
        "TRUNCATED": "narrow the query before trusting the sample",
        "SATURATED": "shrink the time window instead of changing the profile interval",
        "MULTI_REGIME": "compare candidate regimes against the alert anchor before narrowing",
        "FLOODED": "scope the search by rule.groups or a more specific discriminator",
        "EMPTY": "widen or pivot only after confirming the searched artifact and window were correct",
        "NO_NEW_EVIDENCE": "change the angle instead of repeating the same query shape",
        "ORIENTATION_ONLY": "run a concrete SIEM evidence query for this task objective",
        "WRONG_REPRESENTATION": "retrieve raw events after profiling instead of concluding from aggregates",
        "INVALID_TIME_WINDOW": "repeat the intended SIEM query inside the claimed task's absolute time window",
        "TOOL_ERROR": "recover from the concrete tool error before changing investigative direction",
    }
    return [mapping[s] for s in signals if s in mapping]


def _signals_for_result(
    tool_name: str, raw, obj, *, evidence_tools_used: set[str]
) -> list[str]:
    signals: list[str] = []
    if tool_name in _SEARCH_TOOLS and isinstance(obj, dict):
        hits = extract_hit_count(raw)
        if obj.get("truncated") or obj.get("total_relation") == "gte":
            signals.append("TRUNCATED")
        if obj.get("rule_groups_breakdown"):
            signals.append("FLOODED")
        if hits == 0:
            signals.append("EMPTY")
    if tool_name == "get_event_volume" and isinstance(obj, dict):
        bursts = obj.get("bursts") or []
        if len(bursts) > 1:
            signals.append("MULTI_REGIME")
        elif obj.get("saturated"):
            signals.append("SATURATED")
        if int(obj.get("total") or 0) == 0:
            signals.append("EMPTY")
    if tool_name == "profile_field" and isinstance(obj, dict):
        values = obj.get("values") or obj.get("top_values") or []
        if not values:
            signals.append("EMPTY")
    if evidence_tools_used and evidence_tools_used.issubset(_PROFILE_TOOLS):
        signals.append("WRONG_REPRESENTATION")
    return signals


def _discriminator_from_result(obj) -> dict | None:
    """Extract the selectivity discriminator from a flooded search result: the field the
    events vary along, its dominant flood value, the available minority candidates, and
    any returned sample event ids. None if the result carries no usable discriminator.
    This is how the flood-deviation axis reaches `interpret`, which then routes the raw
    sample into the next-step instruction the agent actually obeys."""
    if not isinstance(obj, dict):
        return None
    smap = obj.get("selectivity_map") or []
    disc = next(
        (e for e in smap if e.get("role") == "discriminator" and e.get("minorities")),
        None,
    )
    if not disc:
        return None
    minorities = disc.get("minorities") or []
    rarest = minorities[-1].get("value") if minorities else None
    minority_values = [
        item.get("value")
        for item in minorities
        if isinstance(item, dict) and item.get("value") is not None
    ]
    sample = obj.get("minority_sample") or []
    sample_ids = [h.get("_id") for h in sample if isinstance(h, dict) and h.get("_id")]
    return {
        "field": disc.get("field"),
        "dominant": disc.get("dominant"),
        "minority": rarest,
        "minority_values": minority_values[:8],
        "sample_event_ids": sample_ids[:8],
    }
