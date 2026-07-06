"""Stage 6b — report: aggregate per-run scorecards across trials into a result.

Groups scorecards by (scenario, entry_point), rolls each metric up across trials via
`scoring.aggregate`, and writes data/results/<scenario>.{json,md,csv}.
"""
from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path

from .. import scoring
from ..scoring import MetricResult
from .score import metric_rows


def _results_from_card(card: dict) -> list[MetricResult]:
    return [MetricResult(**r) for r in card.get("results", [])]


def aggregate_cards(cards: list[dict]) -> dict:
    """Return {scenario: {entry_point: {metric: rollup}}}."""
    groups: dict[tuple[str, str], list[list[MetricResult]]] = defaultdict(list)
    for card in cards:
        key = (card.get("scenario", ""), card.get("entry_point", ""))
        groups[key].append(_results_from_card(card))

    out: dict[str, dict] = defaultdict(dict)
    for (scenario, entry_point), trials in groups.items():
        out[scenario][entry_point] = {
            "trials": len(trials),
            "metrics": scoring.aggregate(trials),
        }
    return dict(out)


def _to_markdown(scenario: str, per_entry: dict) -> str:
    lines = [f"# Benchmark results — {scenario}", ""]
    for entry_point, block in per_entry.items():
        lines.append(f"## Entry point: {entry_point} ({block['trials']} trials)")
        pr = block["metrics"].get("phase_recall", {}).get("per_key")
        if pr:
            lines += ["", "| phase | hit-rate over trials |", "|---|---|"]
            lines += [f"| {name} | {rate:.2f} |" for name, rate in pr.items()]
        lines.append("")
    return "\n".join(lines)


def _rows_from_cards(cards: list[dict], scenario: str) -> list[dict]:
    rows: list[dict] = []
    for card in cards:
        if card.get("scenario") != scenario:
            continue
        rows.extend(card.get("rows") or metric_rows(card))
    return rows


def _write_csv(path: Path, rows: list[dict]) -> None:
    fieldnames = sorted({k for row in rows for k in row})
    if not fieldnames:
        fieldnames = ["scenario", "entry_point", "trial", "status", "metric", "kind", "key", "value"]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def run(cards: list[dict], out_dir: str | Path) -> dict:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    aggregated = aggregate_cards(cards)
    for scenario, per_entry in aggregated.items():
        (out_dir / f"{scenario}.json").write_text(
            json.dumps(per_entry, indent=2), encoding="utf-8"
        )
        (out_dir / f"{scenario}.md").write_text(
            _to_markdown(scenario, per_entry), encoding="utf-8"
        )
        _write_csv(out_dir / f"{scenario}.csv", _rows_from_cards(cards, scenario))
    return aggregated
