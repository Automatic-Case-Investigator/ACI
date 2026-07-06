"""Standardized provider capability contracts and rendering helpers."""
from __future__ import annotations

from typing import Any

from .base import (
    CAPABILITY_DOCS,
    KIND_FILESYSTEM,
    KIND_SIEM,
    KIND_SOAR,
    KIND_UTILITY,
    MCPProvider,
    OPTIONAL_CAPABILITIES_BY_KIND,
    REQUIRED_CAPABILITIES_BY_KIND,
)


def provider_contract_snapshot(provider: MCPProvider) -> dict[str, Any]:
    capability_ids = _capability_ids_for(provider)
    standardized = []
    for cap_id in capability_ids:
        standardized.append({
            "id": cap_id,
            "required": cap_id in REQUIRED_CAPABILITIES_BY_KIND.get(provider.kind, ()),
            "tools": list(provider.capabilities.get(cap_id, ())),
            "doc": CAPABILITY_DOCS.get(cap_id, {}),
        })
    return {
        "provider_key": provider.key,
        "provider_kind": provider.kind,
        "instructions_required": bool(provider.instructions_required),
        "standardized_capabilities": standardized,
    }


def instructions_required_for_server(server_name: str, default: bool = True) -> bool:
    from .registry import get_provider

    provider = get_provider(server_name)
    if provider is None:
        return default
    return bool(provider.instructions_required)


def format_provider_capability_contracts(provider_keys: list[str]) -> str:
    """Describe the standardized capability contract for active built-in providers."""
    from .registry import get_provider

    providers: list[MCPProvider] = []
    seen: set[str] = set()
    for key in provider_keys:
        provider = get_provider(key)
        if provider is None or provider.key in seen:
            continue
        seen.add(provider.key)
        if provider.kind not in {KIND_SIEM, KIND_SOAR, KIND_UTILITY, KIND_FILESYSTEM}:
            continue
        providers.append(provider)
    if not providers:
        return ""

    lines = ["## Standardized MCP Capability Contract", ""]
    lines.append(
        "Reason about SIEM, SOAR, filesystem, and utility access through the "
        "standardized capability roles below first. Use the mapped platform tool "
        "names only when you actually invoke a tool."
    )
    for kind, title in (
        (KIND_SIEM, "SIEM providers"),
        (KIND_SOAR, "SOAR providers"),
        (KIND_FILESYSTEM, "Filesystem providers"),
        (KIND_UTILITY, "Utility providers"),
    ):
        kind_providers = [provider for provider in providers if provider.kind == kind]
        if not kind_providers:
            continue
        lines.extend(["", f"### {title}"])
        required = REQUIRED_CAPABILITIES_BY_KIND.get(kind, ())
        optional = OPTIONAL_CAPABILITIES_BY_KIND.get(kind, ())
        if required:
            lines.extend(["", "Required capabilities:"])
            for cap_id in required:
                doc = CAPABILITY_DOCS[cap_id]
                lines.append(f"- `{cap_id}`: {doc['description']}")
        if optional:
            lines.extend(["", "Optional capabilities:"])
            for cap_id in optional:
                doc = CAPABILITY_DOCS[cap_id]
                lines.append(f"- `{cap_id}`: {doc['description']}")

    lines.extend(["", "### Active provider bindings"])
    for provider in providers:
        snapshot = provider_contract_snapshot(provider)
        suffix = "" if snapshot["instructions_required"] else " (instructions optional)"
        lines.append(f"- `{provider.key}` ({provider.kind}){suffix}")
        for capability in snapshot["standardized_capabilities"]:
            tools = capability["tools"]
            if not tools:
                continue
            mapped = ", ".join(f"`{tool}`" for tool in tools)
            lines.append(f"  {capability['id']} -> {mapped}")
    return "\n".join(lines)


def _capability_ids_for(provider: MCPProvider) -> tuple[str, ...]:
    declared = tuple(provider.capabilities.keys())
    if declared:
        return declared
    return REQUIRED_CAPABILITIES_BY_KIND.get(provider.kind, ()) + OPTIONAL_CAPABILITIES_BY_KIND.get(provider.kind, ())
