# Current Project State

This document captures the current runtime and operations shape of ACI. It is
intended to bridge the high-level `README.md` / `ARCHITECTURE.md` docs when those
files lag behind active development.

## Runtime Shape

ACI is a Django 5 + Daphne ASGI service with an interactive WebSocket dashboard,
REST API, workflow webhook ingress, DB-backed settings console, and a shared
queue-driven LangGraph runtime for `triage` and `investigation`.

All run paths converge on `agent.runtime.engine.run.run_agent`, which:

1. resolves the registered `AgentDefinition`;
2. applies `AgentConfig` overrides for budget, tool policy, and intent streaming;
3. marks the `AgentRun` running;
4. builds the MCP client from enabled built-in providers plus enabled custom MCP
   servers;
5. loads MCP prompt guidance before exposing tools;
6. builds the OpenAI-compatible model client from `ModelProviderConfig`;
7. composes platform and agent prompt layers;
8. invokes the compiled graph in `agent.runtime.graph.builder`.

The graph package was split from the older monolithic graph module. Historical
imports from `agent.runtime.graph` are preserved through package-level re-exports.

The canonical orchestrator surface is the package
`agent.runtime.orchestrator`. The flat `agent.runtime.orchestrator.py` file is
now only a compatibility shim.

Stable high-level runtime entrypoints are:

- `run_orchestrator`
- `OrchestratorSession`
- `dispatch_run`
- `run_agent`
- `build_mcp_client`
- `compose_system_prompt`

## Prompt And Provider Boundaries

Prompt composition is layered deliberately:

- platform-agnostic reasoning method and identity stay in `agent/prompts/`;
- runtime context assembly lives in
  `agent.runtime.config.prompts` and `agent.runtime.config.prompt_sections`;
- provider capability contracts are rendered separately from core reasoning;
- MCP-specific instructions are loaded from each MCP server package and appended
  as guidance, rather than duplicated into the core agent prompt.

Built-in provider registration also has a clearer internal split between:

- provider registration and capability mapping;
- provider config/env resolution;
- MCP instruction loading;
- provider capability-contract rendering.

## Registered Agents

| Agent | Role | Default Tool Policy | Default Budget | Orchestrator-routable |
|---|---|---|---|---|
| `triage` | Reads SOAR case context, checks nearby SIEM evidence and memory, assesses severity/category, and returns a report plus prioritized investigation plan. | `aci-thehive`, `aci-wazuh`, `aci-taskqueue`, `aci-memory`, `avfs` | 12 steps, 18 tool calls | yes |
| `investigation` | Performs SIEM-backed investigation, enriches artifacts, maintains the findings board, and posts a grounded final report. | `aci-thehive`, `aci-wazuh`, `aci-taskqueue`, `aci-board`, `aci-memory`, `avfs` | 40 steps, 60 tool calls | yes |
| `seeder` | Internal-only. Parses a completed triage report into the investigation task queue; called directly by investigation's `seed`, never routed by the orchestrator. | `aci-taskqueue` | 20 steps, 25 tool calls | no |

Triage produces structured handoff metadata; investigation consumes it. The
orchestrator passes handoffs through `AgentRun.metadata` rather than prompt
string parsing.

## Graph Nodes

The active graph is:

```text
seed -> claim -> think -> use_tools/assess -> pivot -> claim
                                      \-> finish -> verdict_contract -> reassess_verdict -> publish_finish
```

Key behavior:

- `seed` creates initial queue work. A normal triage handoff calls the
  `seeder` agent (deterministic plan-item extraction + a bounded model pass
  for gaps, deduplicated against the existing queue); a resume run creates an
  open-gaps task directly.
- `claim` owns queue claiming. `claim_next` is never exposed to the model.
- `think` calls the model with allowed tools and compacts old non-evidence
  context when prompt tokens exceed about 80% of the configured context length.
- `use_tools` executes MCP calls, caps oversized tool results, expands AVFS `~`
  paths, deterministically extracts artifacts (including decoded hex/base64/
  URL-encoded payloads) from event-shaped JSON, auto-correlates confirmed
  entities, builds the kill-chain view, and can trigger TI enrichment.
- `assess` completes the current task with a non-empty summary. For
  `investigation`, a single **per-task self-review** (`graph/reflection.py`)
  replaces the older fixed cascade of separate guard nodes — one model call
  judges the task holistically (using deterministic signals: evidence-query
  count, broad-result hit count, unpivoted IOCs, unqueried volume-profile
  clusters, unreported board compromise artifacts) and either approves
  completion or re-injects one consolidated correction (`needs_more_work`).
  Fail-open and bounded by a retry budget plus a convergence guard so a task
  cannot loop forever on orientation-only turns.
- `pivot` updates the Findings Board from `## Findings` (gated by the
  self-review's grounding/novelty verdicts) and `## Hypotheses`, validates
  `## New Leads`, queues approved follow-up tasks, and posts an immediate
  escalation comment when active compromise is confirmed — reading
  confirmed compromise indicators directly off the board, not only the
  agent's own narrative, so a decoded artifact the agent never re-narrates
  still escalates.
- `finish` builds the structured final investigation summary or marks budget
  exhaustion.
- `verdict_contract` generates/repairs the canonical fenced JSON verdict block.
- `reassess_verdict` compares triage and investigation verdicts, resolving
  conflicts with a focused model call only when needed.
- `publish_finish` writes `final.md` to AVFS and posts the report to TheHive.

## SIEM Query Robustness

`aci-wazuh`'s `WazuhClient` (`aci-mcp-servers/aci-wazuh/aci_wazuh/client.py`)
adds deterministic guards surfaced back to the model as a `hint`/`note`
rather than a silent failure: malformed-query hints, ISO-timestamp-in-keyword
stripping, and detection of a `bool` `should` clause with no `must`/
`minimum_should_match` (scoring-only under ES/OS defaults — the most common
way a query that looks narrow silently matches the whole time window).
Prompt guidance also teaches verifying `agent.id` cardinality before treating
events scoped only by `agent.name` as one host's activity, since a display
name is not guaranteed unique.

## Configuration Model

The settings model is DB-over-env:

- `ModelProviderConfig`: base URL, API key, model, tool-calling mode, timeout,
  context length, and sampling parameters.
- `IntegrationConnection`: named, multi-instance connections for built-in connectors
  (Wazuh, TheHive, VirusTotal), grouped by platform type in the settings UI. Many
  connections may exist per provider; exactly one `is_active` per provider is what the
  runtime resolves. `resolve_settings` precedence is `.env defaults < ProviderConfig
  (legacy singleton) < active IntegrationConnection`.
- `ProviderConfig`: legacy per-provider enabled state and connection settings, kept as
  the fallback layer beneath `IntegrationConnection` for deployments that predate the
  multi-connection model.
- `MCPServerConfig`: custom stdio or streamable-HTTP MCP servers, with optional
  per-agent allow lists.
- `AgentConfig`: budget, tool-policy, and intent-streaming overrides.
- `RuntimeConfig`: automatic workflow kill switch, baseline adapter/cadence,
  debug mode, and TI cache TTL.
- `WorkflowConfig` and `WorkflowTriggerConfig`: event bindings and configured
  webhook endpoints.
- `EscalationRule`: verdict-to-action mapping.

`.env` is now mostly host bootstrap: Django basics, AVFS URL/token/agent id,
queue/board/cache SQLite paths, baseline defaults, public intent defaults, and
the workflow kill switch fallback. Model and connector credentials should be
entered through Dashboard -> Settings for normal operation.

## Built-In MCP Providers

| Provider | Category | Purpose |
|---|---|---|
| `aci-taskqueue` | internal | Queue authority for pending/claimed/completed tasks. |
| `aci-board` | internal | Findings Board facts, hypotheses, artifacts, and TI results. |
| `aci-memory` | internal | Read-only patterns, baselines, and analyst feedback. |
| `avfs` | internal optional HTTP | Workspace filesystem and durable report/artifact storage. Skipped if unreachable or configured with the placeholder token. |
| `aci-thehive` | default SOAR | Case/alert reads, similar cases, comments, report pages, and case updates. |
| `aci-wazuh` | default SIEM | Search, keyword search, event lookup, field profiling, index listing, and mappings. |

Internal providers cannot be disabled through settings. Default providers can be
enabled/disabled and reconfigured, but not deleted. Custom MCP servers are full
CRUD through settings.

Provider metadata is standardized internally around:

- `provider_key`
- `provider_kind`
- standardized capabilities
- mapped tool names
- `instructions_required`

## Learning, Memory, And TI

Cross-case learning is backed by Django models and exposed to agents via
`aci-memory`:

- `PatternEntry` and `PatternCandidate` store reviewed and proposed TP/FP
  patterns.
- `FeedbackEntry` records mutable analyst corrections for run verdicts.
- `BaselineSnapshot`, `BaselineSubjectConfig`, and `BaselineComputeConfig`
  store behavioral baselines and their computation scope.

Artifact extraction is deterministic and runs after investigation tool results.
It records event-derived artifacts such as IPs, hashes, domains, hosts, users,
processes, files, and command lines. Shell-bearing syscheck diffs and long
hex-encoded payloads are normalized before board write.

Threat-intelligence enrichment is optional. When VirusTotal is configured,
artifacts are cached in SQLite, rate-limited, written to the board as advisory
`ti_result` entries, and malicious/suspicious results can create follow-up
investigation tasks.

## Workflows And Webhooks

Automatic workflows are implemented but globally disabled by default.

Supported bindings:

| Event | Target Agent |
|---|---|
| `new_case` | `triage` |
| `new_alert` | `triage` |

Supported trigger providers:

| Provider | Events |
|---|---|
| TheHive | `new_case`, `new_alert` |
| Wazuh | `new_alert` |

Configured triggers expose:

```text
POST /api/agent/webhooks/<trigger_id>/
```

The compatibility endpoint remains:

```text
POST /api/agent/webhooks/thehive/
```

Webhook execution requires all of the following:

- global workflows enabled by `RuntimeConfig.workflows_enabled` or
  `WORKFLOWS_ENABLED=true`;
- trigger row enabled;
- optional secret match through `X-ACI-Webhook-Secret` or `?secret=...`;
- registered workflow binding enabled;
- provider payload successfully parsed into a case or alert id.

The manual command path is:

```bash
python manage.py run_workflow new_case <case_id>
python manage.py run_workflow new_alert <case_id> --payload '{}'
```

## Session Publication And Run Continuation

Interactive orchestrator sessions persist durable analyst-visible state in
`AgentRun.metadata["orch_session"]`.

Specialist completion now refreshes analyst-visible session state through one
shared path:

- orchestrator-triggered completion updates `OrchestratorSession` directly;
- direct resume and restart use
  `agent.dashboard.runner.session_state.publish_specialist_result_to_session`;
- shared mutation/publication helpers live in
  `agent.runtime.orchestrator.specialist_sync`.

This closes the earlier gap where a directly resumed specialist run could finish
correctly in its own `AgentRun` record without republishing the updated result
back into the orchestrator chat/session state.

## Development Commands

Offline verification:

```bash
PYTHONPATH=. python -m pytest tests/unit tests/django -q
```

Focused examples:

```bash
PYTHONPATH=. python -m pytest tests/unit/graph/test_graph_stub.py -q
PYTHONPATH=. python -m pytest tests/unit/analysis/test_verdict_parsing.py -q
PYTHONPATH=. python -m pytest tests/unit/graph/test_lead_model.py -q
PYTHONPATH=. python -m pytest tests/unit/graph/test_compaction_preserves_tool_messages.py -q
```

Local inspection scripts live in `scripts/dev/`; see `scripts/dev/README.md`.
