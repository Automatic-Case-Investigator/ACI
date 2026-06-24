"""Supported external sources for workflow triggers.

This registry is intentionally separate from MCP providers. A system can receive
events from TheHive or Wazuh even if the corresponding MCP connector is disabled,
and adding another trigger source should only require registering it here.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


PayloadParser = Callable[[str, dict], tuple[str | None, str | None]]


@dataclass(frozen=True)
class TriggerProvider:
    key: str
    label: str
    events: tuple[str, ...]
    parse_payload: PayloadParser


def _parse_thehive(event_type: str, body: dict) -> tuple[str | None, str | None]:
    object_type = str(body.get("objectType") or body.get("object_type") or "").lower()
    operation = str(body.get("operation") or body.get("action") or "").lower()
    obj = body.get("object") or body.get("details") or {}
    case_id = obj.get("_id") or obj.get("id") or body.get("rootId") or body.get("case_id")
    expected = "case" if event_type == "new_case" else "alert" if event_type == "new_alert" else ""

    if expected and object_type and object_type != expected:
        return None, f"payload objectType {object_type!r} does not match {event_type}"
    if operation and operation not in {"creation", "create", "update"}:
        return None, f"unhandled operation {operation!r}"
    if not case_id:
        return None, "could not resolve case_id from TheHive payload"
    return str(case_id), None


def _parse_wazuh(event_type: str, body: dict) -> tuple[str | None, str | None]:
    if event_type != "new_alert":
        return None, "Wazuh webhooks only map to new_alert"
    alert_id = (
        body.get("case_id")
        or body.get("alert_id")
        or body.get("id")
        or body.get("_id")
        or body.get("rule", {}).get("id")
    )
    agent_id = body.get("agent", {}).get("id") or body.get("agent_id")
    case_id = alert_id or agent_id
    if not case_id:
        return None, "could not resolve alert id from Wazuh payload"
    return str(case_id), None


_PROVIDERS: tuple[TriggerProvider, ...] = (
    TriggerProvider("thehive", "TheHive", ("new_case", "new_alert"), _parse_thehive),
    TriggerProvider("wazuh", "Wazuh", ("new_alert",), _parse_wazuh),
)

_ALIASES = {
    "aci-thehive": "thehive",
    "aci-wazuh": "wazuh",
}


def normalize_provider_key(provider_key: str) -> str:
    key = (provider_key or "").strip().lower()
    return _ALIASES.get(key, key)


def list_trigger_providers() -> list[TriggerProvider]:
    return list(_PROVIDERS)


def get_trigger_provider(provider_key: str) -> TriggerProvider | None:
    key = normalize_provider_key(provider_key)
    for provider in _PROVIDERS:
        if provider.key == key:
            return provider
    return None


def is_supported_trigger_provider(provider_key: str) -> bool:
    return get_trigger_provider(provider_key) is not None


def parse_trigger_payload(provider_key: str, event_type: str, body: dict) -> tuple[str | None, str | None]:
    provider = get_trigger_provider(provider_key)
    if provider is None:
        return None, f"unsupported trigger provider {provider_key!r}"
    if event_type not in provider.events:
        return None, f"{provider.label} does not support {event_type}"
    return provider.parse_payload(event_type, body)
