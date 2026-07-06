"""Metric-agnostic roll-up across N trials.

Groups per-trial `MetricResult`s by metric name and reduces each group by its
declared `kind` — so a new metric aggregates correctly without any edit here. A
metric may override `Metric.aggregate` for bespoke behavior; this module honors
that hook and otherwise applies the `kind` default.
"""
from __future__ import annotations

import statistics
from collections import defaultdict

from .base import MetricResult
from .registry import _REGISTRY


def _default_rollup(kind: str, values: list) -> dict:
    if kind == "scalar" or kind == "count":
        nums = [float(v) for v in values]
        return {
            "mean": statistics.fmean(nums) if nums else 0.0,
            "stdev": statistics.pstdev(nums) if len(nums) > 1 else 0.0,
            "n": len(nums),
        }
    if kind == "rate":
        bools = [1.0 if v else 0.0 for v in values]
        return {"rate": statistics.fmean(bools) if bools else 0.0, "n": len(bools)}
    if kind == "per_key":
        # values are per-trial dicts {key: bool|float}; report per-key mean over trials
        per_key: dict[str, list[float]] = defaultdict(list)
        for d in values:
            for k, v in (d or {}).items():
                per_key[k].append(1.0 if v is True else (0.0 if v is False else float(v)))
        rollup = {k: statistics.fmean(vs) for k, vs in per_key.items()}
        return {"per_key": rollup, "n": len(values)}
    raise ValueError(f"unknown MetricResult.kind: {kind!r}")


def aggregate(trials: list[list[MetricResult]]) -> dict:
    """`trials` is a list (one per run) of that run's MetricResults.
    Returns {metric_name: {rollup...}} across all trials."""
    by_name: dict[str, list[MetricResult]] = defaultdict(list)
    for run_results in trials:
        for r in run_results:
            by_name[r.name].append(r)

    out: dict[str, dict] = {}
    for name, results in by_name.items():
        metric = _REGISTRY.get(name)
        custom = metric.aggregate(results) if metric is not None else None
        if custom is not None:
            out[name] = custom
        else:
            out[name] = _default_rollup(results[0].kind, [r.value for r in results])
    return out
