from __future__ import annotations

"""The 'active runs' panel feed."""

from datetime import datetime, timezone

from rest_framework.response import Response

from agent.models import AgentRun

from .._shared import PublicAPIView


class ActiveRunsView(PublicAPIView):
    """In-progress agent runs for the 'active runs' dashboard panel.

    Mirrors the dashboard index definition: a run is active only while it is
    actually awaiting/performing agent inference. Idle live sessions may remain
    RUNNING in storage, but should not keep the Active Runs panel populated.
    """

    def get(self, request):
        from .actions import (
            ACTIVE_STATES,
            humanize_age,
            is_inferring,
            is_orphaned_interactive_child,
        )

        candidates = list(
            AgentRun.objects.filter(status__in=ACTIVE_STATES).order_by("-updated_at")[
                :50
            ]
        )
        runs = [
            r
            for r in candidates
            if is_inferring(r) and not is_orphaned_interactive_child(r)
        ]
        now = datetime.now(timezone.utc)
        return Response(
            {
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
            }
        )
