from __future__ import annotations

import json

from django.contrib import messages
from django.shortcuts import redirect, render
from django.utils.text import slugify
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from agent.models import (
    AgentConfig,
    BaselineSnapshot,
    BaselineSubjectConfig,
    EscalationRule,
    MCPServerConfig,
    ModelProviderConfig,
    ProviderConfig,
    RuntimeConfig,
    WorkflowConfig,
    WorkflowTriggerConfig,
)
from django.http import JsonResponse

from .rows import _agent_rows, _baseline_adapter_name, _baseline_snapshot_rows, _baseline_subject_hint, _baseline_subject_rows, _baseline_window_days, _custom_mcp_rows, _escalation_rows, _integration_rows, _provider_options, _provider_rows, _runtime_context, _workflow_event_options, _workflow_rows, _workflow_trigger_rows



def settings_view(request):
    model = ModelProviderConfig.objects.filter(id="default").first()
    edit_trigger_id = (request.GET.get("edit_trigger") or "").strip()
    edit_trigger = None
    if edit_trigger_id:
        edit_trigger = WorkflowTriggerConfig.objects.filter(id=edit_trigger_id).first()
    return render(request, "dashboard/settings.html", {
        "model": model,
        "tool_calling_modes": [c[0] for c in ModelProviderConfig.TOOL_CALLING_CHOICES],
        "providers": _provider_rows(),
        "custom_mcps": _custom_mcp_rows(),
        "transports": [c[0] for c in MCPServerConfig.TRANSPORT_CHOICES],
        "agents": _agent_rows(),
        "workflows": _workflow_rows(),
        "workflow_triggers": _workflow_trigger_rows(request),
        "workflow_event_options": _workflow_event_options(),
        "trigger_provider_options": _provider_options(),
        "edit_trigger": edit_trigger,
        "escalation_rows": _escalation_rows(),
        "baseline_subjects": _baseline_subject_rows(),
        "baseline_snapshots": _baseline_snapshot_rows(),
        "baseline_subject_types": [c[0] for c in BaselineSubjectConfig.SUBJECT_CHOICES],
        "baseline_adapter_name": _baseline_adapter_name(),
        "baseline_subject_hint": _baseline_subject_hint(),
        "baseline_window_days": _baseline_window_days(),
        "integrations": _integration_rows(),
        "runtime": _runtime_context(),
    })

