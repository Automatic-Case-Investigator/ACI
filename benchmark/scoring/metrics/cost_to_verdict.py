"""cost_to_verdict — the token cost the agent spent to reach its verdict.

Reads the per-run counts the runner captured into `meta.json` (`tokens.input/output/
model_calls`). Emits the raw measurements only — price-agnostic; the dollar figure is a
linear function of these, computed where pricing lives (`run.yaml` → the run summary), so
the metric stays a pure measurement. Aggregates to mean tokens/calls per run over trials,
which lets you correlate cost against quality (phase_recall / verdict_correctness) in the
same result table.
"""
from __future__ import annotations

from ..base import Metric, MetricResult
from ..context import ScoringContext
from ..registry import register


@register
class CostToVerdict(Metric):
    name = "cost_to_verdict"
    needs_judge = False

    def score(self, ctx: ScoringContext) -> MetricResult:
        tokens = ctx.meta.get("tokens") or {}
        return MetricResult(
            name=self.name,
            kind="per_key",  # numeric per-key → mean per run over trials
            value={
                "input_tokens": int(tokens.get("input") or 0),
                "output_tokens": int(tokens.get("output") or 0),
                "model_calls": int(tokens.get("model_calls") or 0),
            },
            detail={"status": ctx.meta.get("status", ""), "entry_point": ctx.entry_point},
        )
