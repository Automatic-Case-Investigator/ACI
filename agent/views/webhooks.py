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

from .public import PublicAPIView



def _request_secret(request) -> str:
    return (
        request.headers.get("X-ACI-Webhook-Secret")
        or request.query_params.get("secret")
        or ""
    )


def _payload_dict(request) -> dict:
    return request.data if isinstance(request.data, dict) else {}


def _trigger_metadata(trigger_config: WorkflowTriggerConfig) -> dict:
    return {
        "workflow_trigger_id": trigger_config.id,
        "workflow_trigger_name": trigger_config.name,
        "workflow_trigger_provider": trigger_config.provider_key,
        "workflow_trigger_event": trigger_config.event_type,
    }


def _start_trigger_dispatch(trigger_config: WorkflowTriggerConfig, case_id: str, body: dict):
    import asyncio

    from ..runtime.triggers.base import Trigger, dispatch_trigger

    trigger = Trigger(event_type=trigger_config.event_type, case_id=str(case_id), payload=body)

    def _run():
        try:
            asyncio.run(dispatch_trigger(
                trigger,
                dedupe_window_override=trigger_config.dedupe_window,
                metadata_extra=_trigger_metadata(trigger_config),
            ))
        except Exception:
            log.exception("workflow dispatch thread crashed for case %s", case_id)

    threading.Thread(
        target=_run,
        daemon=True,
    ).start()


def _handle_configured_webhook(request, trigger_config: WorkflowTriggerConfig):
    from ..runtime.config.overrides import resolve_workflow
    from ..runtime.triggers.registry import get_binding

    if not trigger_config.enabled:
        return Response({"ignored": True, "reason": "trigger disabled"})
    if trigger_config.secret and _request_secret(request) != trigger_config.secret:
        return Response({"error": "invalid webhook secret"}, status=status.HTTP_403_FORBIDDEN)
    from ..runtime.config.runtime_config import workflows_enabled
    if not workflows_enabled():
        return Response({"error": "automatic workflows are disabled"}, status=status.HTTP_503_SERVICE_UNAVAILABLE)

    binding = get_binding(trigger_config.event_type)
    if binding is None:
        return Response({"ignored": True, "reason": f"no workflow binding registered for {trigger_config.event_type!r}"})

    enabled, _window = resolve_workflow(
        trigger_config.event_type,
        default_enabled=binding.enabled,
        default_window=binding.dedupe_window,
    )
    if not enabled:
        return Response({"ignored": True, "reason": "workflow binding disabled"})

    from ..runtime.triggers.providers import parse_trigger_payload

    body = _payload_dict(request)
    case_id, ignored_reason = parse_trigger_payload(trigger_config.provider_key, trigger_config.event_type, body)
    if ignored_reason:
        return Response({"ignored": True, "reason": ignored_reason})

    _start_trigger_dispatch(trigger_config, case_id, body)
    return Response({
        "accepted": True,
        "trigger_id": trigger_config.id,
        "event_type": trigger_config.event_type,
        "case_id": str(case_id),
    }, status=status.HTTP_202_ACCEPTED)


class ConfiguredWebhookView(PublicAPIView):
    """Ingest a configured webhook trigger by stable trigger id."""

    def post(self, request, trigger_id):
        trigger_config = WorkflowTriggerConfig.objects.filter(id=trigger_id).first()
        if trigger_config is None:
            return Response({"error": "trigger not found"}, status=status.HTTP_404_NOT_FOUND)
        return _handle_configured_webhook(request, trigger_config)


class TheHiveWebhookView(PublicAPIView):
    """Compatibility endpoint for configured TheHive workflow triggers.

    The endpoint resolves enabled TheHive webhook trigger configs, then applies
    the same optional-secret and workflow-binding checks as the generic endpoint.
    """

    def post(self, request):
        from ..runtime.triggers.base import EVENT_NEW_ALERT, EVENT_NEW_CASE

        body = _payload_dict(request)
        object_type = str(body.get("objectType") or body.get("object_type") or "").lower()
        if object_type == "case":
            event_type = EVENT_NEW_CASE
        elif object_type == "alert":
            event_type = EVENT_NEW_ALERT
        else:
            return Response({"ignored": True, "reason": f"unhandled objectType {object_type!r}"})

        trigger_config = WorkflowTriggerConfig.objects.filter(
            enabled=True,
            event_type=event_type,
            provider_key__in=("thehive", "aci-thehive"),
        ).first()
        if trigger_config is None:
            return Response({"ignored": True, "reason": "no enabled TheHive webhook trigger configured"})
        return _handle_configured_webhook(request, trigger_config)

