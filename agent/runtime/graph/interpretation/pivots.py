"""Pivot state machine: candidate scoring, selection, broadening, and update."""
from __future__ import annotations

from ..parsing import _PIVOT_CONF_SCORE, _PIVOT_ROLE_SCORE, _PIVOT_SOURCE_SCORE
from ..timeutil import _pivot_key

from ._const import _ADJACENCY_KEYS, _CONTINUE_ACTIONS, _PIVOT_FAILURE_SIGNALS, _PIVOT_KEYS


def _coerce_adjacency(value) -> dict:
    if not isinstance(value, dict):
        return {}
    out: dict = {}
    for key in _ADJACENCY_KEYS:
        text = " ".join(str(value.get(key) or "").split())
        if text:
            out[key] = text[:300]
    return out
def _coerce_pivot(value) -> dict:
    if not isinstance(value, dict):
        return {}
    out: dict = {}
    for key in _PIVOT_KEYS:
        raw = value.get(key)
        if key == "failure_count":
            try:
                count = int(raw or 0)
            except (TypeError, ValueError):
                count = 0
            out[key] = max(0, min(count, 99))
            continue
        text = " ".join(str(raw or "").split())
        if text:
            out[key] = text[:320]
    out.setdefault("status", "active")
    out.setdefault("failure_count", 0)
    out.setdefault("last_failure_reason", "")
    return out if out.get("field") and out.get("value") else {}
def _coerce_pivots(value, *, limit: int = 12) -> list[dict]:
    if not isinstance(value, list):
        return []
    out: list[dict] = []
    for item in value:
        pivot = _coerce_pivot(item)
        if pivot:
            out.append(pivot)
    return out[:limit]
def _pivot_dict_key(pivot: dict) -> str:
    """Dedup key for a pivot held as a dict — unwraps to the shared ``_pivot_key``."""
    return _pivot_key(pivot.get("field") or "", pivot.get("value") or "")
def _merge_pivots(existing, new, *, limit: int = 12) -> list[dict]:
    merged: dict[str, dict] = {}
    for pivot in _coerce_pivots(existing, limit=limit) + _coerce_pivots(new, limit=limit):
        key = _pivot_dict_key(pivot)
        if not key:
            continue
        current = merged.get(key)
        if current is None:
            merged[key] = pivot
            continue
        score = _pivot_score(pivot)
        if score > _pivot_score(current):
            replacement = dict(current)
            replacement.update(pivot)
            replacement["failure_count"] = max(
                int(current.get("failure_count") or 0),
                int(pivot.get("failure_count") or 0),
            )
            replacement["last_failure_reason"] = (
                pivot.get("last_failure_reason") or current.get("last_failure_reason") or ""
            )
            merged[key] = replacement
        else:
            current["failure_count"] = max(
                int(current.get("failure_count") or 0),
                int(pivot.get("failure_count") or 0),
            )
            if not current.get("broader_alternative") and pivot.get("broader_alternative"):
                current["broader_alternative"] = pivot.get("broader_alternative")
    return list(merged.values())[:limit]
def _pivot_score(pivot: dict) -> tuple[int, int, int, int]:
    status = str(pivot.get("status") or "active")
    status_score = {"confirmed": 3, "active": 2, "demoted": 1, "exhausted": 0}.get(status, 1)
    return (
        status_score,
        _PIVOT_SOURCE_SCORE.get(str(pivot.get("source_level") or ""), 0),
        _PIVOT_ROLE_SCORE.get(str(pivot.get("role") or ""), 0),
        _PIVOT_CONF_SCORE.get(str(pivot.get("confidence") or ""), 0) - int(pivot.get("failure_count") or 0),
    )
def _select_primary_pivot(pivots: list[dict]) -> dict:
    if not pivots:
        return {}
    ranked = sorted(_coerce_pivots(pivots), key=_pivot_score, reverse=True)
    for pivot in ranked:
        if str(pivot.get("status") or "active") != "exhausted":
            return pivot
    return ranked[0] if ranked else {}
def _observation_failure_reason(observation: dict) -> str:
    signals = set(observation.get("signals") or [])
    for signal, reason in _PIVOT_FAILURE_SIGNALS:
        if signal in signals:
            return reason
    return ""
def _broadened_pivot(pivot: dict) -> dict:
    broader = " ".join(str(pivot.get("broader_alternative") or "").split())
    if not broader or broader == str(pivot.get("value") or "").strip():
        return {}
    return {
        "field": str(pivot.get("field") or "").strip(),
        "value": broader[:320],
        "source_level": str(pivot.get("source_level") or "").strip() or "board_inference",
        "role": "hypothesis" if str(pivot.get("role") or "") == "exemplar" else "anchor",
        "confidence": "medium",
        "status": "active",
        "failure_count": 0,
        "last_failure_reason": "",
        "broader_alternative": "",
    }
def _update_pivot_state(ledger: dict, observation: dict, action: str, *, parsed: dict | None = None) -> tuple[list[dict], dict, str, str]:
    pivots = _merge_pivots(ledger.get("active_pivots"), observation.get("pivot_candidates"))
    primary = _coerce_pivot((parsed or {}).get("primary_pivot")) or _coerce_pivot(ledger.get("primary_pivot"))
    if primary:
        pivots = _merge_pivots(pivots, [primary])
    primary = _select_primary_pivot([primary] + pivots if primary else pivots)
    strategy = str((parsed or {}).get("next_pivot_strategy") or "keep").strip() or "keep"
    why_failed = " ".join(str((parsed or {}).get("why_current_pivot_failed") or "").split())
    failure_reason = _observation_failure_reason(observation)

    if primary:
        for pivot in pivots:
            if _pivot_dict_key(pivot) == _pivot_dict_key(primary):
                primary = pivot
                break
        should_penalize = (
            not observation.get("advanced_objective")
            and action in _CONTINUE_ACTIONS
            and failure_reason
        )
        if should_penalize:
            primary["failure_count"] = int(primary.get("failure_count") or 0) + 1
            primary["last_failure_reason"] = failure_reason
            if not why_failed:
                why_failed = f"Current pivot failed because the latest batch was {failure_reason.replace('_', ' ')}."
        elif observation.get("advanced_objective") and str(primary.get("status") or "") != "exhausted":
            primary["status"] = "confirmed"

        if int(primary.get("failure_count") or 0) >= 2 and str(primary.get("broader_alternative") or "").strip():
            primary["status"] = "exhausted"
            broader = _broadened_pivot(primary)
            if broader:
                pivots = _merge_pivots(pivots, [broader])
                primary = _select_primary_pivot([broader] + pivots)
                strategy = "broaden"
                if not why_failed:
                    why_failed = (
                        "The current pivot has stalled repeatedly, so the next turn should use "
                        "the broader behavior/entity pivot instead of the exact artifact."
                    )
        elif should_penalize and not why_failed:
            why_failed = "The current pivot did not materially narrow to the evidence needed."

    pivots = _merge_pivots(pivots, [primary] if primary else [])
    return pivots, primary, strategy, why_failed[:320]
def _pivot_instruction_fragment(ledger: dict) -> str:
    pivot = _coerce_pivot(ledger.get("primary_pivot"))
    if not pivot:
        return ""
    value = str(pivot.get("value") or "")
    field = str(pivot.get("field") or "")
    source_level = str(pivot.get("source_level") or "")
    role = str(pivot.get("role") or "")
    failures = int(pivot.get("failure_count") or 0)
    broader = str(pivot.get("broader_alternative") or "")
    if failures >= 2 and broader:
        return (
            f" The prior exact pivot `{field}={value}` is exhausted; broaden to `{broader}` "
            "instead of reusing the same exact discriminator."
        )
    if role == "exemplar" or source_level in {"case", "alert_aggregate"}:
        broader_hint = f" Prefer `{broader}` plus entity/time scope." if broader else ""
        return (
            f" Treat `{field}={value}` as a provisional example from {source_level}, not a "
            f"required exact-match discriminator.{broader_hint}"
        )
    if role == "discriminator" and source_level in {"raw_event", "decoded_payload"}:
        return f" Use `{field}={value}` as an exact discriminator because raw evidence supports it."
    return ""
