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


def _collect_connection_settings(request, schema, base):
    """Build a settings dict for `schema`'s fields from POST, over `base`.

    Returns (settings, error_message). `error_message` is non-None when a secret
    field fails its `pattern` validation. Mirrors the historic behaviour: a blank
    text/secret field clears that value, a checkbox becomes "true"/"false".
    """
    import re

    settings = dict(base) if isinstance(base, dict) else {}
    for f in schema["fields"]:
        name = f["name"]
        if f["type"] == "secret":
            submitted = (request.POST.get(name) or "").strip()
            if submitted:
                pattern = f.get("pattern")
                if pattern and not re.match(pattern, submitted):
                    hint = f.get("pattern_hint", "the expected format")
                    return None, (
                        f"{schema['label']}: '{f['label']}' must be {hint} — "
                        "the submitted value was rejected and not saved "
                        "(check you pasted the key itself, not other text)."
                    )
            settings[name] = submitted  # blank clears the stored secret
        elif f["type"] == "bool":
            settings[name] = "true" if request.POST.get(name) else "false"
        else:
            settings[name] = (request.POST.get(name) or "").strip()
    return settings, None


@csrf_exempt
@require_POST
def settings_connection_save(request):
    """Create or edit a named IntegrationConnection for a built-in provider.

    A blank `conn_id` creates a new connection; the first connection for a
    provider is auto-activated. Editing keeps the connection's provider fixed.
    """
    from agent.models import IntegrationConnection

    key = (request.POST.get("provider") or "").strip()
    conn_id = (request.POST.get("conn_id") or "").strip()

    conn = None
    if conn_id:
        conn = IntegrationConnection.objects.filter(id=conn_id).first()
        if conn is None:
            messages.error(request, "Connection not found — it may have been deleted.")
            return redirect("dashboard:settings")
        key = conn.provider_key  # provider is immutable after creation

    schema = _CONNECTION_SCHEMA.get(key)
    if schema is None:
        messages.error(request, f"Unknown connector: {key}")
        return redirect("dashboard:settings")

    name = (request.POST.get("name") or "").strip() or schema["label"]
    base = conn.settings if conn else {}
    new_settings, error = _collect_connection_settings(request, schema, base)
    if error:
        messages.error(request, error)
        return redirect("dashboard:settings")

    if conn:
        conn.name = name
        conn.settings = new_settings
        conn.save(update_fields=["name", "settings", "updated_at"])
        messages.success(request, f"Connection '{name}' saved.")
    else:
        first_for_provider = not IntegrationConnection.objects.filter(provider_key=key).exists()
        IntegrationConnection.objects.create(
            name=name, provider_key=key, settings=new_settings, is_active=first_for_provider,
        )
        note = " and set active" if first_for_provider else ""
        messages.success(request, f"{schema['label']} connection '{name}' added{note}.")
    return redirect("dashboard:settings")


@csrf_exempt
@require_POST
def settings_connection_activate(request):
    """Mark one connection active for its provider (clearing the others)."""
    from django.db import transaction

    from agent.models import IntegrationConnection

    conn_id = (request.POST.get("conn_id") or "").strip()
    conn = IntegrationConnection.objects.filter(id=conn_id).first()
    if conn is None:
        messages.error(request, "Connection not found — it may have been deleted.")
        return redirect("dashboard:settings")

    with transaction.atomic():
        IntegrationConnection.objects.filter(provider_key=conn.provider_key).update(is_active=False)
        IntegrationConnection.objects.filter(id=conn.id).update(is_active=True)
    messages.success(request, f"'{conn.name}' is now the active connection.")
    return redirect("dashboard:settings")


@csrf_exempt
@require_POST
def settings_connection_delete(request):
    """Delete one or more connections (accepts multiple `conn_id` for bulk delete).

    For every provider whose active connection is removed, promote a surviving
    sibling so each provider keeps at most one active connection.
    """
    from agent.models import IntegrationConnection

    ids = [i.strip() for i in request.POST.getlist("conn_id") if i.strip()]
    if not ids:
        messages.error(request, "No connection selected.")
        return redirect("dashboard:settings")

    conns = list(IntegrationConnection.objects.filter(id__in=ids))
    if not conns:
        messages.error(request, "Connection(s) not found — they may have been deleted.")
        return redirect("dashboard:settings")

    names = [c.name for c in conns]
    active_removed = {c.provider_key for c in conns if c.is_active}
    IntegrationConnection.objects.filter(id__in=[c.id for c in conns]).delete()

    for provider_key in active_removed:
        if not IntegrationConnection.objects.filter(provider_key=provider_key, is_active=True).exists():
            sibling = IntegrationConnection.objects.filter(provider_key=provider_key).first()
            if sibling:
                IntegrationConnection.objects.filter(id=sibling.id).update(is_active=True)

    if len(names) == 1:
        messages.success(request, f"Connection '{names[0]}' deleted.")
    else:
        messages.success(request, f"Deleted {len(names)} connections.")
    return redirect("dashboard:settings")


@csrf_exempt
@require_POST
def settings_connection_test(request):
    """Probe a connection's reachability using its resolved (DB-over-env) settings.

    Targets the connection named by `conn_id` when present (its stored settings
    over env), otherwise the provider's active/legacy resolution. Freshly-typed,
    non-blank fields override for this probe only, so values can be tested before
    saving.
    """
    from agent.runtime.config import resolve_settings
    from agent.runtime.providers.registry import get_provider

    from agent.models import IntegrationConnection

    key = (request.POST.get("provider") or "").strip()
    conn_id = (request.POST.get("conn_id") or "").strip()

    conn = None
    if conn_id:
        conn = IntegrationConnection.objects.filter(id=conn_id).first()
        if conn is not None:
            key = conn.provider_key

    schema = _CONNECTION_SCHEMA.get(key)
    if schema is None:
        messages.error(request, f"Unknown connector: {key}")
        return redirect("dashboard:settings")

    provider = get_provider(key)
    resolved = resolve_settings(key, provider.setting_defaults() if provider else {})
    # A specific connection's stored settings win over the active-resolution above.
    if conn and isinstance(conn.settings, dict):
        for field, value in conn.settings.items():
            if value not in (None, ""):
                resolved[field] = value
    # Non-blank freshly-typed fields override for this probe only.
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

