"""Stage 6a — score: grade each stored run against ground truth + rubric.

Walks a runs directory, and for every trial (a dir containing `report.md`) builds a
`ScoringContext` from the run artifacts and applies the selected metrics via
`scoring.run_all`. Writes a `scorecard.json` next to each run and returns the cards.
Decoupled from the runner so runs can be re-scored without re-running agents.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from .. import scoring
from ..scoring.context import parse_iso
from ..scoring import ScenarioSpec, ScoringContext

_CONFIG = Path(__file__).resolve().parent.parent / "config"


def scenario_spec_path(scenario: str) -> Path:
    return _CONFIG / "scenarios" / f"{scenario}.yaml"


def _read(path: Path, default):
    if not path.exists():
        return default
    text = path.read_text(encoding="utf-8")
    return json.loads(text) if path.suffix == ".json" else text


def _flat_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return json.dumps(value, sort_keys=True)


def _detail_columns(detail: dict) -> dict:
    return {f"detail_{k}": _flat_value(v) for k, v in sorted((detail or {}).items())}


def _iter_raw_session_events(obj: Any):
    if isinstance(obj, dict):
        source = obj.get("_source")
        if isinstance(source, dict) and (source.get("@timestamp") or source.get("timestamp")):
            yield (
                str(obj.get("_id") or ""),
                source,
            )
        for value in obj.values():
            yield from _iter_raw_session_events(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from _iter_raw_session_events(value)


def _surface_session_text_rows(rows: list[dict[str, str]]) -> str:
    parts: list[str] = []
    for row in rows:
        kind = row.get("kind", "")
        summary = row.get("summary", "")
        if kind == "think":
            parts.append(row.get("detail", "") or "")
            continue
        if kind != "note":
            continue
        if summary.startswith("completed ") or summary == "interpret: stop_completed (ready_to_assess)":
            parts.append(row.get("detail", "") or "")
    return "\n\n".join(part for part in parts if part)


def _materialize_session_evidence_rows(rows: list[dict[str, str]]) -> tuple[str, list[tuple[str, datetime, str]]]:
    surfaced_text = _surface_session_text_rows(rows)
    raw_events: list[tuple[str, datetime, str]] = []
    for row in rows:
        if row.get("kind") != "result":
            continue
        try:
            payload = json.loads(row.get("detail") or "")
        except json.JSONDecodeError:
            continue
        for event_id, source in _iter_raw_session_events(payload):
            timestamp = parse_iso(source.get("@timestamp") or source.get("timestamp"))
            if timestamp is None:
                continue
            raw_events.append((event_id, timestamp, json.dumps(source, sort_keys=True)))
    return surfaced_text, raw_events


def _load_session_evidence_from_db(session_id: str, db_path: Path) -> tuple[str, list[tuple[str, datetime, str]]]:
    if not session_id or not db_path.exists():
        return "", []
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute(
            "select kind, summary, detail from agent_agentevent where session_id=? order by id",
            (session_id,),
        ).fetchall()
    finally:
        con.close()
    return _materialize_session_evidence_rows([dict(row) for row in rows])


def _load_session_evidence(trial_dir: Path, meta: dict) -> tuple[str, list[tuple[str, datetime, str]]]:
    artifact = _read(trial_dir / "session_evidence.json", {}) or {}
    surfaced_text = str(artifact.get("surfaced_text") or "")
    raw_events: list[tuple[str, datetime, str]] = []
    for row in artifact.get("raw_events") or []:
        if not isinstance(row, dict):
            continue
        timestamp = parse_iso(row.get("timestamp"))
        if timestamp is None:
            continue
        raw_events.append((
            str(row.get("event_id") or ""),
            timestamp,
            str(row.get("content") or ""),
        ))
    if surfaced_text or raw_events:
        return surfaced_text, raw_events
    session_id = str(meta.get("session_id") or "")
    return _load_session_evidence_from_db(session_id, Path("db.sqlite3"))


def metric_rows(card: dict) -> list[dict]:
    """Flatten a scorecard into rectangular rows for pandas/CSV consumers."""
    base = {
        "scenario": card.get("scenario", ""),
        "entry_point": card.get("entry_point", ""),
        "trial": card.get("trial"),
        "status": card.get("status", ""),
    }
    rows: list[dict] = []
    for result in card.get("results", []):
        metric_base = {
            **base,
            "metric": result.get("name", ""),
            "kind": result.get("kind", ""),
        }
        detail = _detail_columns(result.get("detail", {}))
        value = result.get("value")
        if result.get("kind") == "per_key" and isinstance(value, dict):
            for key, key_value in sorted(value.items()):
                rows.append({**metric_base, "key": key, "value": _flat_value(key_value), **detail})
        else:
            rows.append({**metric_base, "key": "", "value": _flat_value(value), **detail})
    return rows


def score_trial(trial_dir: Path, spec: ScenarioSpec, metrics: str | list[str] = "all") -> dict:
    report_text = _read(trial_dir / "report.md", "")
    verdict = _read(trial_dir / "verdict.json", {}) or {}
    meta = _read(trial_dir / "meta.json", {}) or {}
    surfaced_text, raw_events = _load_session_evidence(trial_dir, meta)
    scored_text = report_text if not surfaced_text else f"{report_text}\n\n{surfaced_text}"
    ctx = ScoringContext.build(
        spec, scored_text, entry_point=meta.get("entry_point", ""), verdict=verdict, meta=meta,
        raw_events=raw_events,
    )
    results = [asdict(r) for r in scoring.run_all(ctx, metrics)]
    card = {
        "scenario": spec.name,
        "entry_point": meta.get("entry_point", ""),
        "trial": meta.get("trial"),
        "status": meta.get("status"),
        # Whether the REQUESTED agent produced this trial (default True for legacy meta
        # that predates the flag). Aggregation excludes invalid trials so an infra
        # failure that fell back to triage does not pollute the recall roll-up.
        "trial_valid": meta.get("trial_valid", True),
        "results": results,
    }
    card["rows"] = metric_rows(card)
    (trial_dir / "scorecard.json").write_text(json.dumps(card, indent=2), encoding="utf-8")
    return card


def run(run_dir: str | Path, scenario: str, metrics: str | list[str] = "all") -> list[dict]:
    spec = ScenarioSpec.from_yaml(scenario_spec_path(scenario))
    run_path = Path(run_dir)
    scenario_path = run_path / scenario
    if scenario_path.exists():
        run_path = scenario_path
    cards: list[dict] = []
    for report in sorted(run_path.rglob("report.md")):
        cards.append(score_trial(report.parent, spec, metrics))
    return cards
