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

from .rows import _workflow_event_options



@csrf_exempt
@require_POST
def settings_agent_save(request):
    p = request.POST
    name = (p.get("agent_name") or "").strip()
    if not name:
        return redirect("dashboard:settings")

    from agent.agents.registry import get_agent
    from agent.runtime.providers.registry import list_providers

    base = get_agent(name)
    if base is None:
        messages.error(request, f"Unknown agent: {name}")
        return redirect("dashboard:settings")

    def _posint(field):
        v = (p.get(field) or "").strip()
        return int(v) if v.isdigit() and int(v) > 0 else None

    valid_keys = {pr.key for pr in list_providers()}
    valid_keys |= set(MCPServerConfig.objects.values_list("id", flat=True))
    selected = [k for k in p.getlist("tool_policy") if k in valid_keys]
    # Fall back to the code default if the analyst cleared every tool.
    tool_policy = selected if selected else None

    AgentConfig.objects.update_or_create(
        agent_name=name,
        defaults={
            "max_steps": _posint("max_steps"),
            "max_tool_calls": _posint("max_tool_calls"),
            "tool_policy": tool_policy,
            "stream_intent": p.get("stream_intent") == "1",
        },
    )
    messages.success(request, f"Agent '{name}' settings saved.")
    return redirect("dashboard:settings")


@csrf_exempt
@require_POST
def settings_workflow_save(request):
    p = request.POST
    event_type = (p.get("event_type") or "").strip()
    if not event_type:
        return redirect("dashboard:settings")
    window = (p.get("dedupe_window") or "").strip()
    WorkflowConfig.objects.update_or_create(
        event_type=event_type,
        defaults={
            "enabled": p.get("enabled") == "1",
            "dedupe_window": int(window) if window.isdigit() else 600,
        },
    )
    messages.success(request, f"Workflow '{event_type}' saved.")
    return redirect("dashboard:settings")


@csrf_exempt
@require_POST
def settings_trigger_save(request):
    from agent.runtime.triggers.providers import get_trigger_provider, is_supported_trigger_provider, normalize_provider_key

    p = request.POST
    existing_id = (p.get("existing_id") or "").strip()
    trigger_id = existing_id or (p.get("id") or "").strip()
    name = (p.get("name") or "").strip()
    provider_key = normalize_provider_key(p.get("provider_key") or "")
    event_type = (p.get("event_type") or "").strip()
    dedupe = (p.get("dedupe_window") or "").strip()
    secret = (p.get("secret") or "").strip()

    valid_events = {row["event_type"] for row in _workflow_event_options()}
    if not is_supported_trigger_provider(provider_key):
        messages.error(request, f"Unsupported trigger provider: {provider_key}")
        return redirect("dashboard:settings")
    if not provider_key or not event_type:
        messages.error(request, "Provider and workflow event are required for a trigger.")
        return redirect("dashboard:settings")
    if event_type not in valid_events:
        messages.error(request, f"'{event_type}' is not a registered workflow event.")
        return redirect("dashboard:settings")
    trigger_provider = get_trigger_provider(provider_key)
    if trigger_provider and event_type not in trigger_provider.events:
        messages.error(request, f"{trigger_provider.label} does not support workflow event '{event_type}'.")
        return redirect("dashboard:settings")

    if not trigger_id:
        trigger_id = slugify(f"{provider_key}-{event_type}-{name or 'webhook'}")[:64]
    trigger_id = slugify(trigger_id)[:64]
    if not trigger_id:
        messages.error(request, "Trigger ID must contain at least one letter or number.")
        return redirect("dashboard:settings")

    if not name:
        name = f"{provider_key} {event_type}"

    WorkflowTriggerConfig.objects.update_or_create(
        id=trigger_id,
        defaults={
            "name": name,
            "provider_key": provider_key,
            "event_type": event_type,
            "enabled": p.get("enabled") == "1",
            "dedupe_window": int(dedupe) if dedupe.isdigit() else 600,
            "secret": secret,
            "settings": {},
        },
    )
    messages.success(request, f"Trigger '{trigger_id}' saved.")
    return redirect("dashboard:settings")


@csrf_exempt
@require_POST
def settings_trigger_toggle(request):
    trigger_id = (request.POST.get("id") or "").strip()
    enabled = request.POST.get("enabled") == "1"
    updated = WorkflowTriggerConfig.objects.filter(id=trigger_id).update(enabled=enabled)
    if updated:
        messages.success(request, f"Trigger '{trigger_id}' {'enabled' if enabled else 'disabled'}.")
    else:
        messages.error(request, f"Trigger '{trigger_id}' not found.")
    return redirect("dashboard:settings")


@csrf_exempt
@require_POST
def settings_trigger_delete(request):
    trigger_id = (request.POST.get("id") or "").strip()
    deleted, _ = WorkflowTriggerConfig.objects.filter(id=trigger_id).delete()
    if deleted:
        messages.success(request, f"Trigger '{trigger_id}' deleted.")
    else:
        messages.error(request, f"Trigger '{trigger_id}' not found.")
    return redirect("dashboard:settings")


@csrf_exempt
@require_POST
def settings_escalation_save(request):
    from agent.runtime.analysis.verdict import VERDICT_ORDER

    p = request.POST
    valid_actions = {c[0] for c in EscalationRule.ACTION_CHOICES}
    for verdict in VERDICT_ORDER:
        action = p.get(f"action_{verdict}")
        if action in valid_actions:
            EscalationRule.objects.update_or_create(
                verdict=verdict, defaults={"action": action}
            )
    messages.success(request, "Escalation policy saved.")
    return redirect("dashboard:settings")

