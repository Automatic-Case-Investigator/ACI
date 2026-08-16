from __future__ import annotations

"""Aggregated verdict statistics feeding the dashboard's charts."""

from rest_framework.response import Response

from .._shared import PublicAPIView


class VerdictStatsView(PublicAPIView):
    """Aggregated TP/FP diagnosis stats for the dashboard.

    GET /api/agent/stats/verdicts/?days=7&group_by=agent_name
    Returns a per-day trend and a grouped breakdown.
    """

    def get(self, request):
        from agent.stats import load_verdict_runs, verdict_trend, verdict_breakdown

        try:
            days = int(request.query_params.get("days", 7))
        except (TypeError, ValueError):
            days = 7
        group_by = request.query_params.get("group_by", "agent_name")
        runs, feedback_map = load_verdict_runs(days)
        return Response(
            {
                "days": days,
                "group_by": group_by,
                "trend": verdict_trend(days, runs=runs, feedback_map=feedback_map),
                "breakdown": verdict_breakdown(
                    days, group_by, runs=runs, feedback_map=feedback_map
                ),
            }
        )
