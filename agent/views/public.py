from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone

from django.conf import settings
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from ..agents.registry import get_agent
from ..models import AgentEvent, AgentRun, FeedbackEntry, WorkflowTriggerConfig
from ..runtime.infra.avfs import reports_dir
from ..runtime.engine.run import run_agent_sync

log = logging.getLogger(__name__)



class PublicAPIView(APIView):
    """APIView reachable without authentication.

    The deployment is a local no-login console (see `dashboard/views.py`): the
    server-rendered dashboard and the SIEM/SOAR webhooks call these endpoints with
    no JWT, so they opt out of the global `IsAuthenticated` default. Endpoints that
    are only for authenticated API clients keep the default and subclass `APIView`.
    """

    authentication_classes: list = []
    permission_classes = [AllowAny]


class VerdictStatsView(PublicAPIView):
    """Aggregated TP/FP diagnosis stats for the dashboard.

    GET /api/agent/stats/verdicts/?days=7&group_by=agent_name
    Returns a per-day trend and a grouped breakdown.
    """

    def get(self, request):
        from ..stats import load_verdict_runs, verdict_trend, verdict_breakdown

        try:
            days = int(request.query_params.get("days", 7))
        except (TypeError, ValueError):
            days = 7
        group_by = request.query_params.get("group_by", "agent_name")
        runs, feedback_map = load_verdict_runs(days)
        return Response({
            "days": days,
            "group_by": group_by,
            "trend": verdict_trend(days, runs=runs, feedback_map=feedback_map),
            "breakdown": verdict_breakdown(days, group_by, runs=runs, feedback_map=feedback_map),
        })


class ActiveRunsView(PublicAPIView):
    """In-progress agent runs for the 'active runs' dashboard panel.

    Mirrors the dashboard index definition: a run is active only while it is
    actually awaiting/performing agent inference. Idle live sessions may remain
    RUNNING in storage, but should not keep the Active Runs panel populated.
    """

    def get(self, request):
        from ..dashboard.run_actions import (
            ACTIVE_STATES,
            humanize_age,
            is_inferring,
            is_orphaned_interactive_child,
        )

        candidates = list(
            AgentRun.objects
            .filter(status__in=ACTIVE_STATES)
            .order_by("-updated_at")[:50]
        )
        runs = [
            r for r in candidates
            if is_inferring(r) and not is_orphaned_interactive_child(r)
        ]
        now = datetime.now(timezone.utc)
        return Response({
            "runs": [
                {
                    "run_id": str(r.id),
                    "short_id": str(r.id)[:8],
                    "agent_name": r.agent_name,
                    "case_id": r.case_id,
                    "question": r.question,
                    "trigger": r.trigger,
                    "status": r.status,
                    "age_seconds": int((now - r.created_at).total_seconds()),
                    "age": humanize_age(int((now - r.created_at).total_seconds())),
                    "updated_at": r.updated_at.isoformat(),
                }
                for r in runs
            ]
        })

