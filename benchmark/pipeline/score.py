"""Stage 6a — score: grade each stored run against ground truth + rubric.

Walks a runs directory, and for every trial (a dir containing `report.md`) builds a
`ScoringContext` from the run artifacts and applies the selected metrics via
`scoring.run_all`. Writes a `scorecard.json` next to each run and returns the cards.
Decoupled from the runner so runs can be re-scored without re-running agents.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .. import scoring
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
    ctx = ScoringContext.build(
        spec, report_text, entry_point=meta.get("entry_point", ""), verdict=verdict, meta=meta
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
    cards: list[dict] = []
    for report in sorted(Path(run_dir).rglob("report.md")):
        cards.append(score_trial(report.parent, spec, metrics))
    return cards
