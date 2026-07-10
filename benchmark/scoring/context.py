"""The shared scoring context: the parsed run plus the scenario ground truth,
built once and handed to every metric.

The expensive/shared work — loading the ground-truth spec, parsing the agent's
report into citable evidence — happens here, so a metric is a thin reader of this
object and never re-implements parsing. Pure stdlib + pyyaml; no Django import, so
metrics stay offline-testable.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

# ─────────────────────────────── ground truth ──────────────────────────────────

_ISO_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
)


def parse_iso(value: Any) -> datetime | None:
    """Parse an ISO-8601 string to a timezone-aware UTC datetime (or None)."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _as_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return str(value)


@dataclass
class Phase:
    """One labelled attack phase (from labels.csv), with optional discriminating
    markers for deterministic matching."""

    name: str
    start: datetime
    end: datetime
    agent_id: str | None = None
    marker_rules: set[str] = field(default_factory=set)       # documentation; not used by phase_recall
    marker_event_ids: set[str] = field(default_factory=set)   # strong, discriminating signal


@dataclass
class EntryPoint:
    """An entry point always resolves, at run time, to a live TheHive ALERT — never a
    Case. Only one alert has ever been promoted to a Case (Fox's recon), and Cases are
    not recreated automatically on re-import, so a case_id would silently go stale
    after every teardown/reload. The anchor_* fields below are matching keys the
    runner uses to find the current live alert with this content signature (rule /
    agent / timestamp / source ref) — not literal identifiers handed to the agent."""

    id: str
    kind: str  # "organic" | "synthetic"
    reasoning_direction: str = ""  # "forward" | "backward" | "bidirectional"
    anchor_event_id: str | None = None
    anchor_source_ref: str | None = None
    anchor_timestamp: str | None = None
    anchor_rule_id: str | None = None
    anchor_agent_id: str | None = None


@dataclass
class ScenarioSpec:
    name: str
    phases: list[Phase]
    entry_points: list[EntryPoint] = field(default_factory=list)
    expected_verdict: dict = field(default_factory=dict)
    host_map: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict) -> "ScenarioSpec":
        phases = [
            Phase(
                name=p["name"],
                start=parse_iso(p["start"]),
                end=parse_iso(p["end"]),
                agent_id=str(p["agent_id"]) if p.get("agent_id") is not None else None,
                marker_rules={str(r) for r in (p.get("marker_rules") or [])},
                marker_event_ids={str(e) for e in (p.get("marker_event_ids") or [])},
            )
            for p in d.get("phases", [])
        ]
        entry_points = [
            EntryPoint(
                id=e["id"],
                kind=e.get("kind", "organic"),
                reasoning_direction=e.get("reasoning_direction", ""),
                anchor_event_id=e.get("anchor_event_id"),
                anchor_source_ref=e.get("anchor_source_ref"),
                anchor_timestamp=_as_text(e.get("anchor_timestamp")),
                anchor_rule_id=str(e["anchor_rule_id"]) if e.get("anchor_rule_id") is not None else None,
                anchor_agent_id=str(e["anchor_agent_id"]) if e.get("anchor_agent_id") is not None else None,
            )
            for e in d.get("entry_points", [])
        ]
        return cls(
            name=d["name"],
            phases=phases,
            entry_points=entry_points,
            expected_verdict=d.get("expected_verdict", {}),
            host_map=d.get("host_map", {}),
        )

    @classmethod
    def from_yaml(cls, path: str | Path) -> "ScenarioSpec":
        return cls.from_dict(yaml.safe_load(Path(path).read_text(encoding="utf-8")))


# ──────────────────────────────── parsed run ───────────────────────────────────

# Backtick-wrapped tokens that look like native event IDs: long opaque tokens
# (`w2X30PYVatKFcWqVUjiG`), dotted-numeric ids (`1700000000.110408`), or case ids
# (`~449101824`). Field names / hostnames (`wazuh-client`, `rule.id`) are excluded
# by the length / shape rules.
_BACKTICK_RE = re.compile(r"`([^`]+)`")
_OPAQUE_ID_RE = re.compile(r"^[A-Za-z0-9_\-]{16,}$")
_DOTTED_ID_RE = re.compile(r"^\d{6,}\.\d+$")
_CASE_ID_RE = re.compile(r"^~\d+$")


def _looks_like_event_id(token: str) -> bool:
    t = token.strip()
    if _DOTTED_ID_RE.match(t) or _CASE_ID_RE.match(t):
        return True
    # opaque id: long, alphanumeric, and not a pure timestamp
    return bool(_OPAQUE_ID_RE.match(t)) and not _ISO_RE.fullmatch(t)


@dataclass
class ParsedReport:
    """The agent's final report reduced to citable evidence: the timestamps and
    native event IDs it referenced. This is the scoring surface an analyst reads."""

    text: str
    timestamps: list[datetime] = field(default_factory=list)
    event_ids: set[str] = field(default_factory=set)

    @classmethod
    def from_text(cls, text: str, anchor_iso: str | None = None) -> "ParsedReport":
        """Reduce the report to citable evidence.

        `anchor_iso` is the incident timestamp the benchmark harness hands the agent in
        its question. A *bare* restatement of it — the anchor value on a line carrying no
        event id, e.g. the echoed "…activity observed around <ts>." question — is context
        the harness supplied, not evidence the agent retrieved. Because that value lands
        inside the anchor phase's window, counting it would credit phase_recall for a
        phase the agent never actually reached (a hollow pass). So the anchor instant is
        dropped *only* when it appears with no event id on its line; a genuine citation of
        the anchor event (timestamp alongside its event id) is kept, as is every other
        timestamp. Event-id matching is unaffected.
        """
        text = text or ""
        anchor_dt = parse_iso(anchor_iso) if anchor_iso else None
        timestamps: list[datetime] = []
        for line in text.splitlines():
            line_has_event_id = any(
                _looks_like_event_id(m.group(1).strip()) for m in _BACKTICK_RE.finditer(line)
            )
            for m in _ISO_RE.finditer(line):
                dt = parse_iso(m.group(0))
                if dt is None:
                    continue
                if anchor_dt is not None and dt == anchor_dt and not line_has_event_id:
                    continue
                timestamps.append(dt)
        event_ids = {tok for m in _BACKTICK_RE.finditer(text)
                     for tok in [m.group(1).strip()] if _looks_like_event_id(tok)}
        return cls(text=text, timestamps=timestamps, event_ids=event_ids)

    def covers(self, phase: Phase) -> bool:
        """Deterministic 'phase reached' test: the report cites a known marker event
        for this phase, OR a timestamp inside the phase window. Rule numbers are NOT
        used here — they are shared across phases and non-discriminating; stricter
        technique attribution is a separate judge-based metric."""
        if phase.marker_event_ids & self.event_ids:
            return True
        if phase.start and phase.end:
            return any(phase.start <= ts <= phase.end for ts in self.timestamps)
        return False


# ─────────────────────────────── scoring context ───────────────────────────────

@dataclass
class ScoringContext:
    """Everything a metric needs to grade one run/trial."""

    scenario: ScenarioSpec
    report: ParsedReport
    entry_point: str = ""
    verdict: dict = field(default_factory=dict)   # parsed diagnosis verdict block
    events: list = field(default_factory=list)    # AgentEvents (cost, termination)
    meta: dict = field(default_factory=dict)      # run metadata (status, tokens, run_id)
    judge: Any = None                             # LLMJudge, supplied only if a metric needs it

    @classmethod
    def build(
        cls,
        scenario: ScenarioSpec,
        report_text: str,
        *,
        entry_point: str = "",
        verdict: dict | None = None,
        events: list | None = None,
        meta: dict | None = None,
        judge: Any = None,
    ) -> "ScoringContext":
        return cls(
            scenario=scenario,
            report=ParsedReport.from_text(report_text, anchor_iso=(meta or {}).get("anchor_timestamp")),
            entry_point=entry_point,
            verdict=verdict or {},
            events=events or [],
            meta=meta or {},
            judge=judge,
        )
