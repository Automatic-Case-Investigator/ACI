"""Attack-chain phase recall — the primary outcome metric.

Of the scenario's ground-truth phases (from labels.csv), how many does the report
actually reach, evidenced by a cited marker event or a timestamp inside the phase
window. This is the deterministic recall floor; whether the citation was attributed
to the *right technique* is refined by a separate judge-based metric.

Reference implementation for the metric plugin contract: subclass `Metric`, set
`name`, implement `score`, decorate with `@register`. Nothing else in the suite
changes when a metric is added.
"""
from __future__ import annotations

from ..base import Metric, MetricResult
from ..context import ScoringContext
from ..registry import register


@register
class PhaseRecall(Metric):
    name = "phase_recall"
    needs_judge = False

    def score(self, ctx: ScoringContext) -> MetricResult:
        hits = {phase.name: ctx.report.covers(phase) for phase in ctx.scenario.phases}
        reached = sum(1 for v in hits.values() if v)
        total = len(hits)
        return MetricResult(
            name=self.name,
            kind="per_key",  # aggregator rolls this up to per-phase hit-rate over trials
            value=hits,
            detail={
                "reached": reached,
                "total": total,
                "recall": (reached / total) if total else 0.0,
                "missed": [name for name, hit in hits.items() if not hit],
                "entry_point": ctx.entry_point,
            },
        )
