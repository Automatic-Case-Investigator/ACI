"""Build MCP server configs and load tools via langchain-mcp-adapters.

Server configs are assembled from the provider registry (runtime/providers): each
key in an agent's `tool_policy` resolves to a registered provider, whose connection
settings come from `runtime/config.py` (DB overrides over env defaults). A disabled
provider (per its ProviderConfig row) is dropped from the run. Adding a platform
means registering a provider — not editing this module.
"""
from __future__ import annotations

import logging
import shlex

from langchain_mcp_adapters.client import MultiServerMCPClient
from mcp import types
import traceback

from .. import config as cfg
from ..providers.registry import get_provider

log = logging.getLogger(__name__)


def _server_configs(tool_policy: list[str], run_ctx: dict | None = None) -> dict:
    configs: dict = {}
    for key in tool_policy:
        provider = get_provider(key)
        if provider is not None:
            if not cfg.is_enabled(key, default=provider.default_enabled):
                log.info("provider %s is disabled; skipping", key)
                continue
            resolved = cfg.resolve_settings(key, provider.setting_defaults())
            configs[provider.key] = provider.build_config(resolved, run_ctx)
            continue

        configured = _configured_mcp_server(key, run_ctx)
        if configured is not None:
            configs[key] = configured
            continue

        log.warning("tool_policy references unknown provider %r; skipping", key)
    return configs


def _configured_mcp_server(key: str, run_ctx: dict | None = None) -> dict | None:
    """Resolve a DB-configured MCP server not backed by a built-in provider."""
    try:
        from agent.models import MCPServerConfig

        row = MCPServerConfig.objects.filter(id=key, enabled=True).first()
    except Exception as exc:
        log.debug("MCPServerConfig lookup for %s unavailable: %s", key, exc)
        return None
    if row is None:
        return None

    allowed = row.allowed_agents or []
    agent_name = (run_ctx or {}).get("agent_name")
    if allowed and agent_name not in allowed:
        log.info("configured MCP %s is not allowed for agent %s", key, agent_name)
        return None

    raw_env = row.env or {}
    env = {str(k): str(v) for k, v in raw_env.items() if not isinstance(v, (dict, list))}
    if run_ctx:
        if run_ctx.get("case_id"):
            env.setdefault("ACI_CASE_ID", str(run_ctx["case_id"]))
        if run_ctx.get("run_id"):
            env.setdefault("ACI_RUN_ID", str(run_ctx["run_id"]))
        if run_ctx.get("agent_name"):
            env.setdefault("ACI_AGENT_NAME", str(run_ctx["agent_name"]))

    if row.transport == MCPServerConfig.TRANSPORT_STDIO:
        parts = shlex.split(row.command_or_url)
        if not parts:
            raise ValueError(f"MCP server {key} has an empty stdio command")
        return {
            "transport": "stdio",
            "command": parts[0],
            "args": parts[1:],
            "env": env,
        }
    if row.transport == MCPServerConfig.TRANSPORT_HTTP:
        headers = raw_env.get("headers") if isinstance(raw_env.get("headers"), dict) else {}
        return {
            "transport": "streamable_http",
            "url": row.command_or_url,
            "headers": headers,
        }
    raise ValueError(f"Unsupported MCP transport for {key}: {row.transport}")


async def build_mcp_client(
    tool_policy: list[str], run_ctx: dict | None = None
) -> MultiServerMCPClient:
    """Build an MCP client for a tool policy.

    `run_ctx` (case_id/run_id/agent_name) lets providers scope their subprocess to
    the current run — notably the task queue, whose identity must be owned by the
    runtime, not chosen by the model.
    """
    from asgiref.sync import sync_to_async

    # _server_configs uses Django ORM (ProviderConfig / MCPServerConfig lookups).
    # Calling it directly from async code triggers SynchronousOnlyOperation.
    # sync_to_async runs it in the main Django sync thread where ORM is allowed.
    configs = await sync_to_async(_server_configs, thread_sensitive=True)(tool_policy, run_ctx)
    return MultiServerMCPClient(configs)


async def load_mcp_prompt_guidance(
    client: MultiServerMCPClient,
    *,
    preferred_prompt: str = "agent_instructions",
    required: bool = True,
) -> str:
    """Load tool/server-specific guidance from MCP prompts.

    Agent prompts stay capability-oriented; concrete tool semantics belong to the
    MCP servers that expose those tools. By default every configured server must
    provide either initialization instructions or an MCP prompt before its tools are
    made available to an agent.
    """
    sections: list[str] = []
    missing: list[str] = []
    for server_name in client.connections:
        try:
            server_sections: list[str] = []
            async with client.session(server_name, auto_initialize=False) as session:
                init = await session.initialize()
                if init.instructions:
                    server_sections.append(f"### {server_name}: Server Instructions\n\n{init.instructions.strip()}")

                if init.capabilities.prompts:
                    listed = await session.list_prompts()
                    prompts = listed.prompts
                    if preferred_prompt:
                        preferred = [p for p in prompts if p.name == preferred_prompt]
                        prompts = preferred or prompts
                    for prompt in prompts:
                        result = await session.get_prompt(prompt.name)
                        text = _prompt_result_to_text(result)
                        if text:
                            title = prompt.description or prompt.name
                            server_sections.append(f"### {server_name}: {title}\n\n{text}")

            if server_sections:
                sections.extend(server_sections)
            else:
                missing.append(server_name)
        except Exception as exc:
            if required:
                raise RuntimeError(f"Failed to load MCP instructions for {server_name}: {exc}") from exc
            
            missing.append(server_name)
    if required and missing:
        names = ", ".join(missing)
        raise RuntimeError(
            "MCP instructions are required before tools may be used, but no "
            f"instructions/prompts were loaded for: {names}"
        )
    return "\n\n".join(sections)


def _prompt_result_to_text(result: types.GetPromptResult) -> str:
    parts: list[str] = []
    for message in result.messages:
        content = message.content
        if isinstance(content, types.TextContent):
            parts.append(content.text.strip())
    return "\n\n".join(part for part in parts if part)
