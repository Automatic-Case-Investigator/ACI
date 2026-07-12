"""The shared scoring context: the parsed run plus the scenario ground truth,
built once and handed to every metric.

The expensive/shared work — loading the ground-truth spec, parsing the agent's
report into citable evidence — happens here, so a metric is a thin reader of this
object and never re-implements parsing. Pure stdlib + pyyaml; no Django import, so
metrics stay offline-testable.
"""
from __future__ import annotations

import re
import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import yaml

# ─────────────────────────────── ground truth ──────────────────────────────────

_ISO_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
)
_COMPACT_RANGE_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
    r"\s*(?:/|–|-|to)\s*"
    r"\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
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
    """One labelled attack phase (from labels.csv), with an optional textual
    signature used to recognize the phase on timestamped report lines."""

    name: str
    start: datetime
    end: datetime
    agent_id: str | None = None
    scorable: bool = True                                     # False → no distinguishing event exists; excluded from recall
    marker_rules: set[str] = field(default_factory=set)       # documentation of the real detecting rule(s)
    marker_event_ids: set[str] = field(default_factory=set)   # legacy-only; phase_recall does not score by ids
    content_signature: dict[str, list[str]] = field(default_factory=dict)


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
                scorable=bool(p.get("scorable", True)),
                marker_rules={str(r) for r in (p.get("marker_rules") or [])},
                marker_event_ids={str(e) for e in (p.get("marker_event_ids") or [])},
                content_signature={
                    key: [str(v) for v in (p.get("content_signature") or {}).get(key, [])]
                    for key in ("all", "any", "none")
                    if (p.get("content_signature") or {}).get(key)
                },
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
# The report also cites source event ids in square brackets in its structured
# `## Found Artifacts` / findings sections, e.g. `command: [decoded] … [qDqTUjp7_4q5yqmXwtAG]`
# or a comma-list `[X744…, 5F5M…, phopkins]`. These carry the SAME evidentiary weight as a
# backtick citation but were previously invisible to the parser (which read only backticks),
# causing false-negative phase misses (e.g. recon/2's reverse_shell, cited only in brackets).
_BRACKET_RE = re.compile(r"\[([^\]]+)\]")
_OPAQUE_ID_RE = re.compile(r"^[A-Za-z0-9_\-]{16,}$")
_DOTTED_ID_RE = re.compile(r"^\d{6,}\.\d+$")
_CASE_ID_RE = re.compile(r"^~\d+$")


def _cited_event_ids(text: str) -> set[str]:
    """Every native event id the report cites — in backtick OR square-bracket form."""
    ids = {tok for m in _BACKTICK_RE.finditer(text)
           for tok in [m.group(1).strip()] if _looks_like_event_id(tok)}
    for m in _BRACKET_RE.finditer(text):
        for tok in re.split(r"[,\s]+", m.group(1)):
            tok = tok.strip().strip("`'\"")
            if _looks_like_event_id(tok):
                ids.add(tok)
    return ids


def _looks_like_event_id(token: str) -> bool:
    t = token.strip()
    if _DOTTED_ID_RE.match(t) or _CASE_ID_RE.match(t):
        return True
    # opaque id: long, alphanumeric, and not a pure timestamp
    return bool(_OPAQUE_ID_RE.match(t)) and not _ISO_RE.fullmatch(t)


def _signature_matches(signature: dict[str, list[str]] | None, content: str | None) -> bool:
    """Whether event/report content satisfies an optional phase-specific signature.

    Phase recall is intentionally timestamp-window-based with a textual signature gate.
    Every listed signature term is conjunctive: all listed keywords must be present on
    the same event/report line. The legacy `any` bucket is accepted as an alias for
    additional required terms so old specs continue to parse, but it does NOT apply OR
    semantics. Missing content fails closed only when a phase defines a signature.
    """
    if not signature:
        return True
    haystack = _signature_haystack(content)
    if not haystack:
        return False
    all_terms = [
        str(v).lower()
        for key in ("all", "any")
        for v in (signature.get(key) or [])
        if str(v).strip()
    ]
    none_terms = [str(v).lower() for v in signature.get("none") or [] if str(v).strip()]
    if any(term not in haystack for term in all_terms):
        return False
    if any(term in haystack for term in none_terms):
        return False
    return True


_WP_META_RE = re.compile(r"wp_meta=([^&\s\"'`]+)", re.IGNORECASE)


def _decode_wp_meta_tokens(content: str) -> str:
    """Return decoded `wp_meta` payload fragments found in arbitrary text.

    Wazuh web logs carry exploit command payloads as URL-encoded/base64 `wp_meta`
    query params. Ground-truth phase signatures are defined on decoded semantics
    (e.g. `wphashcrack`, `/dev/tcp/...`, `wordpress_db`), so match against both the
    raw log text and any decoded payload fragments.
    """
    decoded_parts: list[str] = []
    for token in _WP_META_RE.findall(content):
        try:
            unquoted = unquote(token)
            padded = unquoted + ("=" * ((4 - len(unquoted) % 4) % 4))
            decoded = base64.b64decode(padded, validate=False).decode("utf-8", errors="ignore")
            if decoded.strip():
                decoded_parts.append(decoded)
        except Exception:
            continue
    return "\n".join(decoded_parts)


def _signature_haystack(content: str | None) -> str:
    text = str(content or "")
    if not text:
        return ""
    decoded = _decode_wp_meta_tokens(text)
    return f"{text}\n{decoded}".lower() if decoded else text.lower()


def _is_artifact_line(line: str) -> bool:
    """Inventory lines are surfaced artifacts, not analyst findings.

    They often contain session-local event ids, IPs, files, or commands without any
    interpretive claim, so using them for phase credit over-counts unrelated phases.
    """
    return bool(re.match(
        r"^\s*-\s*(?:ip|file|command|url|host|user|domain|hash|process|pid|srcip|dstip):\s",
        line.strip(),
        flags=re.IGNORECASE,
    ))


@dataclass
class ParsedReport:
    """The agent's final report reduced to citable evidence: the timestamps and
    native event IDs it referenced. This is the scoring surface an analyst reads."""

    text: str
    lines: list[str] = field(default_factory=list)
    # (ts, reporting agent.id, source line). The agent slot is retained for compatibility,
    # but phase_recall itself now scores by timestamped line content only.
    timestamps: list[tuple[datetime, str | None, str]] = field(default_factory=list)
    event_ids: set[str] = field(default_factory=set)
    # Retrieved raw events from the live session. These are matched by timestamp+content;
    # session-local ids are used only to verify that the agent actually surfaced a given
    # retrieved event in its notes/report.
    raw_events: list[tuple[str, datetime, str]] = field(default_factory=list)
    # Legacy fields kept for compatibility with stored artifacts and ad hoc inspection.
    # phase_recall does not credit coverage via event-id resolution.
    event_times: dict[str, datetime] = field(default_factory=dict)
    event_agents: dict[str, str] = field(default_factory=dict)
    event_content: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_text(cls, text: str, anchor_iso: str | None = None,
                  event_times: dict[str, datetime] | None = None,
                  event_agents: dict[str, str] | None = None,
                  event_content: dict[str, str] | None = None,
                  raw_events: list[tuple[str, datetime, str]] | None = None) -> "ParsedReport":
        """Reduce the report to citable evidence.

        `anchor_iso` is the incident timestamp the benchmark harness hands the agent in
        its question. A *bare* restatement of it — the anchor value on a line carrying no
        event id, e.g. the echoed "…activity observed around <ts>." question — is context
        the harness supplied, not evidence the agent retrieved. Because that value lands
        inside the anchor phase's window, counting it would credit phase_recall for a
        phase the agent never actually reached (a hollow pass). So the anchor instant is
        dropped *only* when it appears with no event id on its line; a genuine timestamped
        event citation is kept, as is every other discrete timestamp.
        """
        text = text or ""
        lines = text.splitlines()
        anchor_dt = parse_iso(anchor_iso) if anchor_iso else None
        timestamps: list[tuple[datetime, str | None, str]] = []
        for line in lines:
            # A line carrying two or more ISO timestamps is a RANGE / span / query-window /
            # volume-profile expression (`time=<from>/<to>`, `13:14:31Z–13:14:49Z`, a
            # get_event_volume plateau "begins at X … peaks at Y"), not a discrete event
            # citation. Counting its endpoints credited any phase whose window merely
            # contained a queried boundary or a profiled span the agent never actually
            # reached — the observed failure where a 35-minute `cracking` window scored a
            # full hit off get_event_volume bin labels and query pivots. Phase coverage now
            # requires a single-timestamp, discrete-event citation.
            if len(_ISO_RE.findall(line)) >= 2 or _COMPACT_RANGE_RE.search(line):
                continue
            line_ids = _cited_event_ids(line)
            line_has_event_id = bool(line_ids)
            for m in _ISO_RE.finditer(line):
                dt = parse_iso(m.group(0))
                if dt is None:
                    continue
                if anchor_dt is not None and dt == anchor_dt and not line_has_event_id:
                    continue
                timestamps.append((dt, None, line))
        return cls(text=text, lines=lines, timestamps=timestamps, event_ids=_cited_event_ids(text),
                   raw_events=raw_events or [],
                   event_times=event_times or {}, event_agents=event_agents or {},
                   event_content=event_content or {})

    def covers(self, phase: Phase) -> bool:
        """Deterministic 'phase reached' test.

        A phase is reached only when the report prints a discrete timestamp inside the
        phase window and the same line matches that phase's identifying content signature,
        or when retrieved raw session events contain a matching timestamped event. The
        metric does not credit marker ids alone or run-local event-id→timestamp maps.
        """
        if not (phase.start and phase.end):
            return False
        if any(
            phase.start <= ts <= phase.end
            and _signature_matches(phase.content_signature, line)
            for ts, ag, line in self.timestamps
        ):
            return True

        # Session-evidence bridge: count a phase when the session retrieved a matching
        # raw event. Benchmark recall is computed over what was found in the session,
        # not just what was restated in the final narrative.
        candidates = [
            (event_id, ts, content)
            for event_id, ts, content in self.raw_events
            if phase.start <= ts <= phase.end and _signature_matches(phase.content_signature, content)
        ]
        return bool(candidates)


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
        event_times: dict | None = None,
        raw_events: list[tuple[str, datetime, str]] | None = None,
    ) -> "ScoringContext":
        # event_times entries may be {id: iso} or the richer {id: {"t": iso, "a": agent_id}}.
        times: dict = {}
        agents: dict = {}
        content: dict = {}
        for k, v in (event_times or {}).items():
            if isinstance(v, dict):
                iso = v.get("t")
                agent = v.get("a")
                pieces = [
                    v.get("c"),
                    v.get("content"),
                    v.get("u"),
                    v.get("url"),
                    v.get("r"),
                    v.get("rule_id"),
                ]
            else:
                iso, agent, pieces = v, None, []
            dt = parse_iso(iso)
            if dt is None:
                continue
            times[k] = dt
            if agent is not None:
                agents[k] = str(agent)
            compact = " ".join(str(piece) for piece in pieces if piece)
            if compact:
                content[k] = compact
        return cls(
            scenario=scenario,
            report=ParsedReport.from_text(
                report_text, anchor_iso=(meta or {}).get("anchor_timestamp"),
                event_times=times, event_agents=agents, event_content=content,
                raw_events=raw_events,
            ),
            entry_point=entry_point,
            verdict=verdict or {},
            events=events or [],
            meta=meta or {},
            judge=judge,
        )
