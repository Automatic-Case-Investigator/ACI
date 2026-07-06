"""Core scoring contracts: every metric conforms to these two types.

A metric is a small, self-contained unit that reads a shared `ScoringContext`
(the parsed run + the scenario ground truth, built once) and returns one or more
`MetricResult`s. `MetricResult.kind` tells the aggregator how to roll the metric up
across trials, so adding a metric never requires editing the aggregator.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal, Union

if TYPE_CHECKING:  # avoid an import cycle; context imports nothing from here
    from .context import ScoringContext

# How the aggregator rolls a metric up across N trials:
#   scalar  -> mean + variance of a float
#   rate    -> hit-rate of a boolean over trials
#   count   -> mean of an integer count
#   per_key -> hit-rate/mean per key (e.g. per-phase) over trials
MetricKind = Literal["scalar", "rate", "count", "per_key"]

MetricValue = Union[float, int, bool, dict]


@dataclass
class MetricResult:
    """One metric's output for one run/trial."""

    name: str
    kind: MetricKind
    value: MetricValue
    detail: dict = field(default_factory=dict)  # evidence/explanation for the write-up


class Metric(ABC):
    """Base class for a scoring metric. Subclass, set `name`, implement `score`,
    and decorate with `@register` — that is the entire contract."""

    name: str = ""
    needs_judge: bool = False  # True if `score` reads `ctx.judge` (an LLM call)

    @abstractmethod
    def score(self, ctx: "ScoringContext") -> "MetricResult | list[MetricResult]":
        """Grade a single run. Return one result, or several (e.g. rubric axes)."""
        raise NotImplementedError

    def aggregate(self, results: list[MetricResult]) -> dict | None:
        """Optional custom cross-trial roll-up. Return None to use the `kind` default
        in `scoring.aggregate` (mean for scalar, hit-rate for rate/per_key, …).
        Override only when a metric needs bespoke aggregation."""
        return None
