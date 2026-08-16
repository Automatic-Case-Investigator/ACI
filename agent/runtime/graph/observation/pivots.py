from __future__ import annotations

"""Pivot candidate derivation, scoring, and dedup."""

from ..parsing import _PIVOT_CONF_SCORE
from ..parsing import _PIVOT_ROLE_SCORE
from ..parsing import _PIVOT_SOURCE_SCORE
from ..timeutil import _pivot_key

from .digest import _path_family
from .trials import _CASE_URL_EXEMPLAR_RULE_IDS


# ── Pivot candidate derivation, scoring, and dedup ──
def _broader_alternative(field: str, value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    lowered_field = str(field or "").strip().lower()
    if lowered_field == "url":
        return _path_family(text)
    if lowered_field == "command":
        first = text.split()[0] if text.split() else ""
        if first:
            return f"same command family as `{first}` in the same scoped window"
    if lowered_field == "rule_id":
        return "same detection family or raw-event representation in the same scoped window"
    if lowered_field in {"src_ip", "dst_ip"}:
        return f"same {lowered_field} with tighter time/behavior scope"
    if lowered_field in {"agent", "host", "host_ip"}:
        return f"same {lowered_field} in the adjacent time window"
    return ""


def _pivot_candidate(
    *,
    field: str,
    value: str,
    source_level: str,
    role: str,
    confidence: str,
) -> dict | None:
    text = str(value or "").strip()
    if not field or not text:
        return None
    pivot = {
        "field": field,
        "value": text[:320],
        "source_level": source_level,
        "role": role,
        "confidence": confidence,
        "status": "active",
        "failure_count": 0,
        "last_failure_reason": "",
        "broader_alternative": _broader_alternative(field, text),
    }
    return pivot


def _pivot_candidates_from_orientation(fact: dict) -> list[dict]:
    if not isinstance(fact, dict):
        return []
    source_level = "case" if fact.get("source") == "case" else "alert_aggregate"
    rule_id = str(fact.get("rule_id") or "").strip()
    out: list[dict] = []
    for field in ("src_ip", "host", "host_ip", "rule_id"):
        candidate = _pivot_candidate(
            field=field,
            value=str(fact.get(field) or ""),
            source_level=source_level,
            role="anchor",
            confidence="medium",
        )
        if candidate:
            out.append(candidate)
    url_value = str(fact.get("url") or "").strip()
    if url_value:
        role = (
            "exemplar"
            if source_level == "case" or rule_id in _CASE_URL_EXEMPLAR_RULE_IDS
            else "hypothesis"
        )
        out.append(
            _pivot_candidate(
                field="url",
                value=url_value,
                source_level=source_level,
                role=role,
                confidence="low" if role == "exemplar" else "medium",
            )
        )
    return [candidate for candidate in out if isinstance(candidate, dict)]


def _pivot_candidates_from_snapshot(snapshot: dict) -> list[dict]:
    if not isinstance(snapshot, dict):
        return []
    out: list[dict] = []
    field_roles = {
        "src_ip": ("anchor", "high"),
        "dst_ip": ("anchor", "high"),
        "agent": ("anchor", "high"),
        "rule_id": ("hypothesis", "medium"),
        "user": ("hypothesis", "medium"),
        "url": ("discriminator", "high"),
        "command": ("discriminator", "high"),
    }
    for field, (role, confidence) in field_roles.items():
        candidate = _pivot_candidate(
            field=field,
            value=str(snapshot.get(field) or ""),
            source_level="raw_event",
            role=role,
            confidence=confidence,
        )
        if candidate:
            out.append(candidate)
    return out


def _dedupe_pivots(pivots: list[dict]) -> list[dict]:
    best_by_key: dict[str, dict] = {}
    for pivot in pivots:
        if not isinstance(pivot, dict):
            continue
        key = _pivot_key(pivot.get("field") or "", pivot.get("value") or "")
        if not key:
            continue
        current = best_by_key.get(key)
        score = (
            _PIVOT_SOURCE_SCORE.get(str(pivot.get("source_level") or ""), 0),
            _PIVOT_ROLE_SCORE.get(str(pivot.get("role") or ""), 0),
            _PIVOT_CONF_SCORE.get(str(pivot.get("confidence") or ""), 0),
        )
        if current is None:
            best_by_key[key] = pivot
            continue
        current_score = (
            _PIVOT_SOURCE_SCORE.get(str(current.get("source_level") or ""), 0),
            _PIVOT_ROLE_SCORE.get(str(current.get("role") or ""), 0),
            _PIVOT_CONF_SCORE.get(str(current.get("confidence") or ""), 0),
        )
        if score > current_score:
            best_by_key[key] = pivot
    return list(best_by_key.values())[:12]


def _dedupe(seq: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in seq:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out
