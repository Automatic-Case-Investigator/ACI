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

from .rows import _CONNECTION_SCHEMA, _test_connection



@csrf_exempt
@require_POST
def settings_model_save(request):
    p = request.POST
    defaults = {
        "base_url": (p.get("base_url") or "").strip(),
        "model": (p.get("model") or "").strip(),
        "tool_calling_mode": p.get("tool_calling_mode") or "auto",
    }
    # API key now renders its current value in the form, so store exactly what's
    # submitted — a blank field clears the stored key.
    defaults["api_key"] = (p.get("api_key") or "").strip()
    timeout = (p.get("timeout") or "").strip()
    defaults["timeout"] = int(timeout) if timeout.isdigit() else None
    context_length = (p.get("context_length") or "").strip()
    defaults["context_length"] = int(context_length) if context_length.isdigit() else None

    sampling = {}
    temperature = (p.get("temperature") or "").strip()
    if temperature:
        try:
            sampling["temperature"] = float(temperature)
        except ValueError:
            pass
    max_tokens = (p.get("max_tokens") or "").strip()
    if max_tokens.isdigit():
        sampling["max_tokens"] = int(max_tokens)
    if sampling:
        defaults["sampling_params"] = sampling

    ModelProviderConfig.objects.update_or_create(id="default", defaults=defaults)
    messages.success(request, "Model settings saved.")
    return redirect("dashboard:settings")


@csrf_exempt
@require_POST
def settings_provider_toggle(request):
    key = (request.POST.get("key") or "").strip()
    if not key:
        return redirect("dashboard:settings")

    from agent.runtime.config import provider_category
    from agent.runtime.providers.registry import get_provider

    # Internal providers are platform plumbing — they cannot be disabled.
    if provider_category(key) == "internal":
        messages.error(request, f"{key} is an internal provider and is always enabled.")
        return redirect("dashboard:settings")

    provider = get_provider(key)
    kind = provider.kind if provider else ProviderConfig.KIND_UTILITY
    enabled = request.POST.get("enabled") == "1"
    ProviderConfig.objects.update_or_create(
        key=key, defaults={"enabled": enabled, "kind": kind}
    )
    messages.success(request, f"{key} {'enabled' if enabled else 'disabled'}.")
    return redirect("dashboard:settings")


@csrf_exempt
@require_POST
def settings_mcp_save(request):
    """Create or edit a custom MCP server (MCPServerConfig)."""
    from agent.runtime.config import INTERNAL_PROVIDERS, DEFAULT_PROVIDERS

    p = request.POST
    server_id = (p.get("id") or "").strip()
    name = (p.get("name") or "").strip()
    command_or_url = (p.get("command_or_url") or "").strip()
    transport = p.get("transport") or MCPServerConfig.TRANSPORT_STDIO

    if not server_id or not name or not command_or_url:
        messages.error(request, "id, name, and command/URL are required.")
        return redirect("dashboard:settings")
    # A custom server may never shadow a built-in provider key.
    if server_id in INTERNAL_PROVIDERS or server_id in DEFAULT_PROVIDERS:
        messages.error(request, f"'{server_id}' is a reserved built-in provider key.")
        return redirect("dashboard:settings")

    allowed = [a.strip() for a in (p.get("allowed_agents") or "").split(",") if a.strip()]
    MCPServerConfig.objects.update_or_create(
        id=server_id,
        defaults={
            "name": name,
            "transport": transport,
            "command_or_url": command_or_url,
            "enabled": p.get("enabled") == "1",
            "allowed_agents": allowed,
        },
    )
    messages.success(request, f"MCP server '{server_id}' saved.")
    return redirect("dashboard:settings")


@csrf_exempt
@require_POST
def settings_mcp_delete(request):
    """Delete a custom MCP server. Built-in (internal/default) keys are protected."""
    from agent.runtime.config import provider_category

    server_id = (request.POST.get("id") or "").strip()
    if not server_id:
        return redirect("dashboard:settings")
    if provider_category(server_id) in ("internal", "default"):
        messages.error(request, f"'{server_id}' is a built-in provider and cannot be deleted.")
        return redirect("dashboard:settings")

    deleted, _ = MCPServerConfig.objects.filter(id=server_id).delete()
    if deleted:
        messages.success(request, f"MCP server '{server_id}' deleted.")
    else:
        messages.error(request, f"MCP server '{server_id}' not found.")
    return redirect("dashboard:settings")


@csrf_exempt
@require_POST
def settings_connection_save(request):
    """Save a built-in connector's connection settings into ProviderConfig.settings."""
    from agent.runtime.providers.registry import get_provider

    key = (request.POST.get("provider") or "").strip()
    schema = _CONNECTION_SCHEMA.get(key)
    if schema is None:
        messages.error(request, f"Unknown connector: {key}")
        return redirect("dashboard:settings")

    import re

    existing_row = ProviderConfig.objects.filter(key=key).first()
    new_settings = dict(existing_row.settings) if existing_row and isinstance(existing_row.settings, dict) else {}
    for f in schema["fields"]:
        name = f["name"]
        if f["type"] == "secret":
            submitted = (request.POST.get(name) or "").strip()
            if submitted:
                pattern = f.get("pattern")
                if pattern and not re.match(pattern, submitted):
                    hint = f.get("pattern_hint", "the expected format")
                    messages.error(
                        request,
                        f"{schema['label']}: '{f['label']}' must be {hint} — "
                        "the submitted value was rejected and not saved "
                        "(check you pasted the key itself, not other text).",
                    )
                    return redirect("dashboard:settings")
            new_settings[name] = submitted  # blank clears the stored secret
        elif f["type"] == "bool":
            new_settings[name] = "true" if request.POST.get(name) else "false"
        else:
            new_settings[name] = (request.POST.get(name) or "").strip()

    provider = get_provider(key)
    defaults = {"settings": new_settings, "kind": provider.kind if provider else ProviderConfig.KIND_UTILITY}
    # Internal providers (AVFS) can't be disabled; only persist `enabled` for the rest.
    from agent.runtime.config import provider_category
    if provider_category(key) != "internal":
        defaults["enabled"] = request.POST.get("enabled") == "1"
    ProviderConfig.objects.update_or_create(key=key, defaults=defaults)
    messages.success(request, f"{schema['label']} connection saved.")
    return redirect("dashboard:settings")


@csrf_exempt
@require_POST
def settings_connection_test(request):
    """Probe a connector's reachability using its current (DB-over-env) settings."""
    from agent.runtime.config import resolve_settings
    from agent.runtime.providers.registry import get_provider

    key = (request.POST.get("provider") or "").strip()
    schema = _CONNECTION_SCHEMA.get(key)
    if schema is None:
        messages.error(request, f"Unknown connector: {key}")
        return redirect("dashboard:settings")
    provider = get_provider(key)
    resolved = resolve_settings(key, provider.setting_defaults() if provider else {})
    # Let the operator test freshly-typed values without saving first: a non-blank
    # submitted field overrides the stored/env value for this probe only.
    for f in schema["fields"]:
        submitted = (request.POST.get(f["name"]) or "").strip()
        if submitted:
            resolved[f["name"]] = submitted
    ok, detail = _test_connection(key, resolved)
    if ok:
        messages.success(request, f"{schema['label']}: {detail}")
    else:
        messages.error(request, f"{schema['label']}: {detail}")
    return redirect("dashboard:settings")


@csrf_exempt
@require_POST
def settings_runtime_save(request):
    """Persist global runtime toggles (RuntimeConfig singleton)."""
    row, _ = RuntimeConfig.objects.get_or_create(id=RuntimeConfig.SINGLETON_ID)
    section = request.POST.get("section")
    if section == "workflows":
        row.workflows_enabled = request.POST.get("workflows_enabled") == "1"
        row.save()
        messages.success(request, f"Automatic workflows {'enabled' if row.workflows_enabled else 'disabled'}.")
    elif section == "baseline":
        row.baseline_siem_adapter = (request.POST.get("baseline_siem_adapter") or "").strip()
        iv = (request.POST.get("baseline_interval_hours") or "").strip()
        row.baseline_interval_hours = int(iv) if iv.isdigit() and int(iv) > 0 else None
        row.save()
        messages.success(request, "Baseline runtime settings saved (interval applies on next restart).")
    elif section == "debug":
        row.debug_mode = request.POST.get("debug_mode") == "1"
        row.save()
        messages.success(request, f"Debug mode {'enabled' if row.debug_mode else 'disabled'}.")
    elif section == "ti_cache":
        ttl = (request.POST.get("ti_cache_ttl_hours") or "").strip()
        row.ti_cache_ttl_hours = int(ttl) if ttl.isdigit() and int(ttl) > 0 else None
        row.save()
        from agent.ti.enricher import reset_ti_cache
        reset_ti_cache()
        if row.ti_cache_ttl_hours:
            messages.success(request, f"TI cache TTL set to {row.ti_cache_ttl_hours}h.")
        else:
            messages.success(request, "TI cache TTL reset to the default.")
    else:
        messages.error(request, "Unknown runtime settings section.")
    return redirect("dashboard:settings")


def settings_ti_cache_stats(request):
    """GET — return TI cache entry counts as JSON."""
    from agent.ti.enricher import get_ti_cache
    try:
        cache = get_ti_cache()
        if cache is None:
            return JsonResponse({"total": 0, "by_provider": {}})
        return JsonResponse(cache.stats())
    except Exception as exc:
        return JsonResponse({"total": 0, "by_provider": {}, "error": str(exc)})


@csrf_exempt
@require_POST
def settings_ti_cache_clear(request):
    """POST — delete all TI cache entries and redirect back to settings."""
    from agent.ti.enricher import get_ti_cache
    try:
        cache = get_ti_cache()
        deleted = cache.clear_all() if cache else 0
        messages.success(request, f"TI cache cleared ({deleted} entr{'y' if deleted == 1 else 'ies'} removed).")
    except Exception as exc:
        messages.error(request, f"Failed to clear TI cache: {exc}")
    return redirect("dashboard:settings")

