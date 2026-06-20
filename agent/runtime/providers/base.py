"""Provider abstraction for MCP servers (SOAR / SIEM / utility / filesystem).

A provider describes one MCP server: its stable `key` (matched against an agent's
`tool_policy`), its `kind`, and two callables:

- `setting_defaults()` pulls this server's connection fields from django settings
  (the env-backed source of truth today).
- `build_config(resolved, run_ctx)` turns a resolved settings dict (DB overrides
  merged over the defaults by `runtime/config.py`) into the MCP server config
  consumed by `MultiServerMCPClient`. `run_ctx` carries the current run's identity
  (case_id/run_id/agent_name) so a provider can scope its subprocess to that run;
  it is None when the client is built outside a specific run.

Adding a new MCP platform = drop a module in this package that registers a provider.
No edits to `mcp_client.py`.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

# Kinds mirror agent/models.py:ProviderConfig.KIND_* so admin + registry agree.
KIND_SOAR = "soar"
KIND_SIEM = "siem"
KIND_UTILITY = "utility"
KIND_FILESYSTEM = "filesystem"


@dataclass(frozen=True)
class MCPProvider:
    key: str
    kind: str
    setting_defaults: Callable[[], dict]
    build_config: Callable[[dict, Optional[dict]], dict]
    default_enabled: bool = True
