"""verdict_correctness — does the final diagnosis disposition match ground truth?

Compares the parsed verdict block's `verdict` (tp / fp / inconclusive /
needs_investigation) against the scenario's `expected_verdict.verdict`, and separately
flags UNDER-CALLS (expected `tp`, called something weaker) — the exact "compromise
suspected instead of confirmed" failure. Severity/scope are surfaced in `detail` but do
not gate the match: the verdict block carries no severity field, and its `scope_state`
is an enum rather than the host list `expected_verdict.scope` uses.
"""
from __future__ import annotations

from ..base import Metric, MetricResult
from ..context import ScoringContext
from ..registry import register

# Anything weaker than a confirmed true-positive when the ground truth IS a compromise.
_WEAKER_THAN_TP = {"fp", "inconclusive", "needs_investigation", ""}


@register
class VerdictCorrectness(Metric):
    name = "verdict_correctness"
    needs_judge = False

    def score(self, ctx: ScoringContext) -> MetricResult:
        expected = str(ctx.scenario.expected_verdict.get("verdict", "")).strip().lower()
        actual = str(ctx.verdict.get("verdict", "")).strip().lower()
        match = bool(expected) and expected == actual
        under_called = expected == "tp" and actual in _WEAKER_THAN_TP
        return MetricResult(
            name=self.name,
            kind="rate",  # → verdict accuracy over trials
            value=match,
            detail={
                "expected": expected,
                "actual": actual,
                "under_called": under_called,
                "confidence": ctx.verdict.get("confidence", ""),
                "scope_state": ctx.verdict.get("scope_state", ""),
                "expected_severity": ctx.scenario.expected_verdict.get("severity", ""),
                "expected_scope": ctx.scenario.expected_verdict.get("scope", []),
                "entry_point": ctx.entry_point,
            },
        )
