"""Metric registry: metrics self-register via `@register`, and the scorer iterates
the registry rather than a hardcoded list. Adding a metric touches no code here.
"""
from __future__ import annotations

from .base import Metric, MetricResult
from .context import ScoringContext

_REGISTRY: dict[str, Metric] = {}


def register(cls: type[Metric]) -> type[Metric]:
    """Class decorator: instantiate the metric and add it to the registry by `name`."""
    if not getattr(cls, "name", ""):
        raise ValueError(f"{cls.__name__} must set a non-empty `name`")
    if cls.name in _REGISTRY:
        raise ValueError(f"duplicate metric name: {cls.name!r}")
    _REGISTRY[cls.name] = cls()
    return cls


def available() -> list[str]:
    return sorted(_REGISTRY)


def selected(names: str | list[str] = "all") -> list[Metric]:
    """Resolve metric instances by name, or all of them when names == 'all'."""
    if names == "all":
        return [_REGISTRY[n] for n in sorted(_REGISTRY)]
    missing = [n for n in names if n not in _REGISTRY]
    if missing:
        raise KeyError(f"unknown metric(s): {missing}; available: {available()}")
    return [_REGISTRY[n] for n in names]


def run_all(ctx: ScoringContext, names: str | list[str] = "all") -> list[MetricResult]:
    """Score one run with the selected metrics, flattening multi-result metrics."""
    out: list[MetricResult] = []
    for metric in selected(names):
        result = metric.score(ctx)
        out.extend(result if isinstance(result, list) else [result])
    return out
