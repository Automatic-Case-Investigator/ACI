"""Deterministic FP/TP pattern matching — no LLM.

Given normalized alert/case metadata, evaluate it against the curated
`PatternEntry` rows and report which patterns apply. The matcher is intentionally
conservative: a pattern only *matches* when **every** condition it specifies is
satisfied AND none of its invalidators fire. A condition that cannot be evaluated
(its field is absent from the metadata) counts as NOT satisfied, so a known-FP
pattern is never applied on partial information.

The output feeds the `matched_patterns` field of the diagnosis verdict and the
fast-triage decision. A matched FP pattern is a *reason to suspect benign*, never
proof on its own — the caller must still confirm `required_evidence`.

## alert_metadata contract

```
{
  "rule_ids":    ["2832", ...],   # Wazuh/SIEM rule IDs on the alert
  "users":       ["backup", ...], # users referenced by the alert
  "paths":       ["/var/spool/cron/crontabs/backup", ...],
  "time_windows":["maintenance_hours", ...],  # named windows the event falls in
  "signals":     ["external source ip", ...],  # normalized tokens for invalidators
}
```

`signals` is the deterministic substrate for invalidator evaluation: an
invalidator fires when its normalized text appears in `signals`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class PatternMatch:
    name: str
    verdict: str           # "tp" | "fp"
    confidence: str        # "low" | "medium" | "high"
    matched: bool          # conditions satisfied AND no invalidator fired
    matched_conditions: list[str] = field(default_factory=list)
    unmet_conditions: list[str] = field(default_factory=list)
    invalidators_triggered: list[str] = field(default_factory=list)
    required_evidence: list[str] = field(default_factory=list)

    def to_contract(self) -> str:
        """A one-line summary for the verdict's `matched_patterns` array."""
        if self.matched:
            return (
                f"{self.name} [{self.verdict}/{self.confidence}] — conditions met: "
                f"{', '.join(self.matched_conditions) or 'n/a'}; "
                f"confirm: {', '.join(self.required_evidence) or 'n/a'}"
            )
        reason = (
            f"invalidated by {', '.join(self.invalidators_triggered)}"
            if self.invalidators_triggered
            else f"unmet conditions: {', '.join(self.unmet_conditions) or 'n/a'}"
        )
        return f"{self.name} [{self.verdict}] — NOT applied ({reason})"


def _as_str_set(values) -> set[str]:
    if values is None:
        return set()
    if isinstance(values, (str, bytes)):
        values = [values]
    return {str(v).strip().lower() for v in values if str(v).strip()}


def _match_conditions(conditions: dict, meta: dict) -> tuple[list[str], list[str]]:
    """Return (matched_condition_keys, unmet_condition_keys).

    Supported condition keys: rule_ids, users, path_prefixes, time_window.
    A condition with an empty/blank spec is ignored (neither matched nor unmet).
    """
    matched: list[str] = []
    unmet: list[str] = []

    rule_ids = _as_str_set(conditions.get("rule_ids"))
    if rule_ids:
        if rule_ids & _as_str_set(meta.get("rule_ids")):
            matched.append("rule_ids")
        else:
            unmet.append("rule_ids")

    users = _as_str_set(conditions.get("users"))
    if users:
        if users & _as_str_set(meta.get("users")):
            matched.append("users")
        else:
            unmet.append("users")

    prefixes = [p for p in (conditions.get("path_prefixes") or []) if str(p).strip()]
    if prefixes:
        meta_paths = [str(p).lower() for p in (meta.get("paths") or [])]
        if any(path.startswith(pref.lower()) for pref in prefixes for path in meta_paths):
            matched.append("path_prefixes")
        else:
            unmet.append("path_prefixes")

    window = str(conditions.get("time_window") or "").strip().lower()
    if window:
        if window in _as_str_set(meta.get("time_windows")):
            matched.append("time_window")
        else:
            unmet.append("time_window")

    return matched, unmet


def _triggered_invalidators(invalidators: list, meta: dict) -> list[str]:
    signals = _as_str_set(meta.get("signals"))
    out: list[str] = []
    for inv in invalidators or []:
        token = str(inv).strip().lower()
        if token and token in signals:
            out.append(str(inv))
    return out


def evaluate(pattern: dict, meta: dict) -> PatternMatch:
    """Evaluate one pattern (dict shape, as stored) against alert metadata."""
    conditions = pattern.get("conditions") or {}
    matched_keys, unmet_keys = _match_conditions(conditions, meta)
    invalidators_fired = _triggered_invalidators(pattern.get("invalidators") or [], meta)

    # A pattern is considered "applicable" only when it had at least one matched
    # condition and no unmet ones; it "matches" only if additionally no invalidator
    # fired. Conservative: an empty condition set never matches anything.
    conditions_ok = bool(matched_keys) and not unmet_keys
    matched = conditions_ok and not invalidators_fired

    return PatternMatch(
        name=pattern.get("name", "(unnamed)"),
        verdict=pattern.get("verdict", "fp"),
        confidence=pattern.get("confidence", "medium"),
        matched=matched,
        matched_conditions=matched_keys,
        unmet_conditions=unmet_keys,
        invalidators_triggered=invalidators_fired,
        required_evidence=list(pattern.get("required_evidence") or []),
    )


def _pattern_to_dict(p) -> dict:
    """Normalize a PatternEntry model instance into the dict shape evaluate() wants."""
    return {
        "name": p.name,
        "verdict": p.verdict,
        "confidence": p.confidence,
        "conditions": p.conditions or {},
        "required_evidence": p.required_evidence or [],
        "invalidators": p.invalidators or [],
    }


def _load_active_patterns() -> list[dict]:
    """Load enabled, non-expired PatternEntry rows as dicts (sync ORM)."""
    from django.db.models import Q
    from agent.models import PatternEntry

    now = datetime.now(timezone.utc)
    qs = PatternEntry.objects.filter(enabled=True).filter(
        Q(expires_at__isnull=True) | Q(expires_at__gt=now)
    )
    return [_pattern_to_dict(p) for p in qs]


def match_patterns(alert_metadata: dict, *, only_applicable: bool = True) -> list[PatternMatch]:
    """Evaluate all active patterns against the metadata (sync; uses the ORM).

    By default returns only *applicable* patterns — those whose conditions were
    fully satisfied (whether or not an invalidator then fired), since those are
    the ones a caller cares about. Pass `only_applicable=False` to get a result
    for every active pattern.
    """
    results = [evaluate(p, alert_metadata) for p in _load_active_patterns()]
    if only_applicable:
        results = [r for r in results if r.matched or r.invalidators_triggered]
    # Matches first, then invalidated-but-applicable; higher confidence first.
    _rank = {"high": 3, "medium": 2, "low": 1}
    results.sort(key=lambda r: (r.matched, _rank.get(r.confidence, 0)), reverse=True)
    return results


async def amatch_patterns(alert_metadata: dict, *, only_applicable: bool = True) -> list[PatternMatch]:
    """Async wrapper for use inside the graph's async nodes."""
    from asgiref.sync import sync_to_async

    return await sync_to_async(match_patterns, thread_sensitive=True)(
        alert_metadata, only_applicable=only_applicable
    )
