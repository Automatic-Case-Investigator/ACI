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


# Built-in connector connection forms. Each field's value lives in
# `ProviderConfig.settings` (key below), which the runtime already injects into the
# provider's MCP subprocess on launch — so saving here reconfigures the live tools.
# `secret` fields render their current value (hidden behind a show/hide toggle on
# this local, no-auth console) so the operator can verify what's actually stored;
# submitting a blank secret clears it.
_CONNECTION_SCHEMA = {
    "aci-wazuh": {
        "label": "Wazuh", "kind": "SIEM", "category": "SIEM",
        "fields": [
            {"name": "url", "label": "Base URL", "type": "text", "placeholder": "https://wazuh:9200"},
            {"name": "index_pattern", "label": "Index pattern", "type": "text", "placeholder": "wazuh-alerts-*"},
            {"name": "user", "label": "User", "type": "text", "placeholder": "admin"},
            {"name": "password", "label": "Password", "type": "secret"},
            {"name": "verify_tls", "label": "Verify TLS", "type": "bool"},
        ],
    },
    "aci-thehive": {
        "label": "TheHive", "kind": "SOAR", "category": "SOAR",
        "fields": [
            {"name": "host", "label": "Host", "type": "text", "placeholder": "http://thehive"},
            {"name": "port", "label": "Port", "type": "text", "placeholder": "9000"},
            {"name": "api_key", "label": "API key", "type": "secret"},
            {"name": "verify_tls", "label": "Verify TLS", "type": "bool"},
        ],
    },
    "aci-ti": {
        "label": "VirusTotal (TI)", "kind": "TI", "category": "TI",
        "fields": [
            {"name": "api_key", "label": "API key", "type": "secret",
             "pattern": r"^[0-9a-fA-F]{64}$",
             "pattern_hint": "a 64-character hexadecimal string"},
            {"name": "base_url", "label": "Base URL", "type": "text",
             "placeholder": "https://www.virustotal.com"},
            {"name": "calls_per_minute", "label": "Rate limit (calls/min)", "type": "text",
             "placeholder": "4"},
        ],
    },
}
# AVFS credentials are internal — configured via .env only, not the settings UI.


def _integration_rows() -> list[dict]:
    """Per-connector connection forms with effective (DB-over-env) values."""
    from agent.runtime.config import is_enabled, provider_category, resolve_settings
    from agent.runtime.providers.registry import get_provider

    rows = []
    for key, schema in _CONNECTION_SCHEMA.items():
        provider = get_provider(key)
        resolved = resolve_settings(key, provider.setting_defaults() if provider else {})
        fields = []
        for f in schema["fields"]:
            value = resolved.get(f["name"], "")
            is_secret = f["type"] == "secret"
            fields.append({
                "name": f["name"],
                "label": f["label"],
                "type": f["type"],
                "placeholder": f.get("placeholder", ""),
                "value": str("" if value is None else value),
                "secret_set": bool(value) if is_secret else False,
                "checked": str(value).strip().lower() == "true" if f["type"] == "bool" else False,
            })
        category = provider_category(key)
        rows.append({
            "key": key,
            "label": schema["label"],
            "kind": schema["kind"],
            "category": schema.get("category", schema["kind"]),
            "internal": category == "internal",
            "enabled": is_enabled(key, provider.default_enabled if provider else True),
            "fields": fields,
        })
    return rows


def _test_connection(key: str, s: dict) -> tuple[bool, str]:
    """Best-effort reachability probe against the resolved connection settings."""
    import httpx

    try:
        if key == "aci-wazuh":
            base = (s.get("url") or f"https://{s.get('host')}:{s.get('port') or 9200}").rstrip("/")
            verify = str(s.get("verify_tls", "false")).strip().lower() == "true"
            r = httpx.get(f"{base}/_cluster/health", auth=(s.get("user") or "admin", s.get("password") or ""), verify=verify, timeout=10)
            r.raise_for_status()
            return True, f"reachable (cluster {r.json().get('status', 'ok')})"
        if key == "aci-thehive":
            base = f"{(s.get('host') or '').rstrip('/')}:{s.get('port') or 9000}"
            verify = str(s.get("verify_tls", "true")).strip().lower() == "true"
            r = httpx.get(f"{base}/api/case", params={"range": "0-1"}, headers={"Authorization": f"Bearer {s.get('api_key', '')}"}, verify=verify, timeout=10)
            r.raise_for_status()
            return True, "authenticated"
        if key == "avfs":
            base = (s.get("url") or "").rstrip("/")
            r = httpx.get(base, headers={"Authorization": f"Bearer {s.get('auth_token', '')}"}, timeout=10)
            return True, f"reachable (HTTP {r.status_code})"
        if key == "aci-ti":
            from django.conf import settings as dj_settings
            api_key = (s.get("api_key") or getattr(dj_settings, "VT_API_KEY", "") or "").strip()
            if not api_key:
                return False, "no API key set"
            base = (s.get("base_url") or getattr(dj_settings, "VT_BASE_URL", "") or "https://www.virustotal.com").rstrip("/")
            r = httpx.get(f"{base}/api/v3/ip_addresses/8.8.8.8", headers={"x-apikey": api_key}, timeout=10)
            if r.status_code == 401:
                return False, "invalid API key (HTTP 401)"
            if r.status_code == 429:
                return True, "authenticated (rate limited — HTTP 429)"
            r.raise_for_status()
            return True, "authenticated"
    except Exception as exc:
        return False, f"unreachable — {type(exc).__name__}: {str(exc)[:160]}"
    return False, "no test available for this connector"


def _provider_rows() -> list[dict]:
    """Built-in MCP providers (internal + default) with category and lock state.

    - internal: always enabled, no toggle, not deletable.
    - default: enable/disable allowed, not deletable.
    """
    from agent.runtime.config import is_enabled, provider_category
    from agent.runtime.providers.registry import list_providers

    rows = []
    for p in sorted(list_providers(), key=lambda x: x.key):
        category = provider_category(p.key)
        rows.append({
            "key": p.key,
            "kind": p.kind,
            "category": category,
            "enabled": is_enabled(p.key, p.default_enabled),
            "locked": category == "internal",   # no toggle / no delete
            "deletable": False,                  # built-ins are never deletable
        })
    return rows


def _custom_mcp_rows() -> list[dict]:
    """User-added MCP servers (MCPServerConfig) — full CRUD."""
    from agent.models import MCPServerConfig

    rows = []
    for s in MCPServerConfig.objects.all():
        rows.append({
            "id": s.id,
            "name": s.name,
            "transport": s.transport,
            "command_or_url": s.command_or_url,
            "enabled": s.enabled,
            "health_status": s.health_status,
            "allowed_agents": s.allowed_agents,
        })
    return rows


def _agent_rows() -> list[dict]:
    """Registered agents with their EFFECTIVE (override-applied) settings, plus the
    list of providers available to toggle in each agent's tool policy."""
    from agent.agents.registry import get_agent, list_agents
    from agent.runtime.config.overrides import resolve_agent_definition

    # Tool-policy options = built-in providers + enabled custom MCP servers.
    available = [p["key"] for p in _provider_rows()] + [
        m["id"] for m in _custom_mcp_rows()
    ]
    rows = []
    for name in sorted(list_agents()):
        base = get_agent(name)
        if not base:
            continue
        a = resolve_agent_definition(base)
        rows.append({
            "name": a.name,
            "description": a.description,
            "tool_policy": a.tool_policy,
            "available_providers": [
                {"key": k, "on": k in a.tool_policy} for k in available
            ],
            "max_steps": a.budget.max_steps,
            "max_tool_calls": a.budget.max_tool_calls,
            "produces_handoff": a.produces_handoff,
            "consumes_handoff": a.consumes_handoff,
            "stream_intent": getattr(a, "stream_intent", True),
        })
    return rows


def _workflow_rows() -> list[dict]:
    """Workflow bindings with EFFECTIVE (override-applied) enabled/dedupe values."""
    from agent.runtime.config.overrides import resolve_workflow
    from agent.runtime.triggers.registry import list_bindings

    rows = []
    for b in list_bindings():
        enabled, window = resolve_workflow(
            b.event_type, default_enabled=b.enabled, default_window=b.dedupe_window
        )
        rows.append({
            "event_type": b.event_type,
            "agent_name": b.agent_name,
            "enabled": enabled,
            "dedupe_window": window,
        })
    return rows


def _workflow_event_options() -> list[dict]:
    """Registered workflow events are the only valid trigger targets."""
    from agent.runtime.triggers.registry import list_bindings

    rows = [
        {"event_type": b.event_type, "agent_name": b.agent_name}
        for b in list_bindings()
    ]
    preferred = {"new_case": 0, "new_alert": 1}
    return sorted(rows, key=lambda row: (preferred.get(row["event_type"], 99), row["event_type"]))


def _provider_options() -> list[dict]:
    """Providers that can identify a trigger source.

    Deliberately independent from MCP provider configuration: trigger sources are
    event ingress adapters, not tool connectors.
    """
    from agent.runtime.triggers.providers import list_trigger_providers

    return [
        {"key": provider.key, "label": provider.label}
        for provider in list_trigger_providers()
    ]


def _webhook_url(request, trigger_id: str) -> str:
    """Absolute URL the SIEM/SOAR should POST events to for this trigger."""
    from django.urls import reverse

    return request.build_absolute_uri(reverse("configured_webhook", args=[trigger_id]))


def _workflow_trigger_rows(request) -> list[dict]:
    """Operator-configured webhook triggers."""
    from agent.runtime.triggers.providers import get_trigger_provider, normalize_provider_key

    bindings = {b["event_type"]: b for b in _workflow_event_options()}
    rows = []
    for t in WorkflowTriggerConfig.objects.all():
        binding = bindings.get(t.event_type)
        provider = get_trigger_provider(t.provider_key)
        rows.append({
            "id": t.id,
            "name": t.name,
            "webhook_url": _webhook_url(request, t.id),
            "provider_key": normalize_provider_key(t.provider_key),
            "provider_label": provider.label if provider else t.provider_key,
            "event_type": t.event_type,
            "target": binding["agent_name"] if binding else "unregistered",
            "enabled": t.enabled,
            "dedupe_window": t.dedupe_window,
            "secret_set": bool(t.secret),
            "updated_at": t.updated_at,
        })
    return rows


def _escalation_rows() -> list[dict]:
    """Verdict → action rows (effective), with the action choices for each select."""
    from agent.runtime.config.overrides import resolve_escalation_map

    from agent.runtime.analysis.verdict import VERDICT_ORDER

    effective = resolve_escalation_map()
    actions = [c[0] for c in EscalationRule.ACTION_CHOICES]
    return [
        {"verdict": v, "action": effective.get(v, "none"), "actions": actions}
        for v in VERDICT_ORDER
    ]


def _baseline_adapter_name() -> str:
    """Active baseline SIEM adapter name (no SIEM connection made)."""
    from agent.runtime.learning.baseline_adapters import active_adapter_name

    return active_adapter_name()


def _baseline_window_days() -> int:
    """Effective lookback window (operator config over the setting default)."""
    from agent.runtime.learning.baselines import get_window_days

    return get_window_days()


def _baseline_subject_hint() -> str:
    """SIEM-specific guidance on how to phrase a subject ID, from the adapter."""
    from agent.runtime.learning.baseline_adapters import active_adapter_name, adapter_meta

    hint = adapter_meta(active_adapter_name()).get("subject_id_hint", "")
    return hint or (
        "Use the subject identifier exactly as it appears in your SIEM — a "
        "username, or an endpoint/host name."
    )


def _baseline_subject_rows() -> list[dict]:
    """Operator-configured baseline subjects."""
    return [
        {
            "id": c.id,
            "subject_type": c.subject_type,
            "subject_id": c.subject_id,
            "enabled": c.enabled,
            "updated_at": c.updated_at,
        }
        for c in BaselineSubjectConfig.objects.all()
    ]


def _baseline_vis(feature: str, value: dict) -> dict:
    """Return a display-ready visualization spec for a single baseline feature."""

    def _bars(items: list[dict]) -> dict:
        max_c = max((b["count"] for b in items), default=1) or 1
        for b in items:
            b["pct"] = round(b["count"] / max_c * 100)
        return {"type": "bar", "bars": items}

    if feature == "active_hours":
        counts = value.get("counts", {})
        return _bars([
            {"label": f"{h:02d}:00", "count": counts.get(str(h), 0)}
            for h in range(24)
        ])

    if feature == "common_rules":
        return _bars([
            {"label": f"rule {x['rule_id']}", "count": x["count"]}
            for x in value.get("top_rules", [])
        ])

    if feature == "common_users":
        return _bars([
            {"label": x["user"], "count": x["count"]}
            for x in value.get("top_users", [])
        ])

    if feature == "source_ips":
        items = [{"label": x["ip"], "count": x["count"]} for x in value.get("top_ips", [])]
        if not items:
            return {"type": "empty", "msg": "no source IPs recorded"}
        return _bars(items)

    if feature == "event_volume":
        return {
            "type": "stats",
            "items": [
                {"label": "daily mean", "value": str(value.get("daily_mean", 0))},
                {"label": "std dev", "value": str(value.get("daily_std", 0))},
                {"label": "p5 / p95", "value": f"{value.get('p5', 0)} / {value.get('p95', 0)}"},
                {"label": "days observed", "value": str(value.get("total_days_observed", 0))},
            ],
        }

    if feature == "auth_failure_rate":
        total = value.get("auth_events", 0)
        failed = value.get("auth_failures", 0)
        success = total - failed
        rate = value.get("failure_rate", 0.0)
        return {
            "type": "rate",
            "rate_pct": f"{round(rate * 100, 1)}%",
            "bars": [
                {"label": "success", "count": success,
                 "pct": round(success / total * 100) if total else 0},
                {"label": "failed", "count": failed,
                 "pct": round(failed / total * 100) if total else 0},
            ],
        }

    return {"type": "json", "value": json.dumps(value, indent=2, default=str)}


def _baseline_snapshot_rows() -> list[dict]:
    """Computed baselines grouped by subject for visualization."""
    grouped: dict[tuple, dict] = {}
    for b in BaselineSnapshot.objects.all():
        key = (b.subject_type, b.subject_id)
        grp = grouped.get(key)
        if grp is None:
            grp = grouped[key] = {
                "subject_type": b.subject_type,
                "subject_id": b.subject_id,
                "features": [],
                "computed_at": b.computed_at,
            }
        grp["features"].append({
            "feature": b.feature,
            "health": b.health,
            "window_days": b.window_days,
            "vis": _baseline_vis(b.feature, b.value),
            "computed_at": b.computed_at,
        })
        if b.computed_at and (grp["computed_at"] is None or b.computed_at > grp["computed_at"]):
            grp["computed_at"] = b.computed_at
    return sorted(grouped.values(), key=lambda g: (g["subject_type"], g["subject_id"]))


def _runtime_context() -> dict:
    from agent.runtime.learning.baseline_adapters import list_adapters
    from agent.runtime.config.runtime_config import (
        baseline_adapter_name,
        baseline_interval_hours,
        debug_mode,
        ti_cache_ttl_hours,
        workflows_enabled,
    )

    return {
        "workflows_enabled": workflows_enabled(),
        "baseline_adapter": baseline_adapter_name(),
        "baseline_adapter_options": list_adapters(),
        "baseline_interval_hours": baseline_interval_hours(),
        "debug_mode": debug_mode(),
        "ti_cache_ttl_hours": ti_cache_ttl_hours(),
    }

