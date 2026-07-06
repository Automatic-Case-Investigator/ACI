"""Metric scoring package.

Public surface: the `Metric`/`MetricResult` contracts, the `ScoringContext` a metric
reads, and the registry (`register`, `selected`, `run_all`). Importing this package
discovers all metric plugins under `metrics/`.
"""
from .base import Metric, MetricResult, MetricKind  # noqa: F401
from .context import ScenarioSpec, ScoringContext, ParsedReport, Phase  # noqa: F401
from .registry import register, selected, available, run_all  # noqa: F401
from .aggregate import aggregate  # noqa: F401
from . import metrics  # noqa: F401  # triggers plugin discovery
