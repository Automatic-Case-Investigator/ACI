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

## Registered Agents

| Agent | Role | Default Tool Policy | Default Budget |
|---|---|---|---|
| `triage` | Reads SOAR case context, checks nearby SIEM evidence and memory, assesses severity/category, and returns a report plus prioritized investigation plan. | `aci-thehive`, `aci-wazuh`, `aci-taskqueue`, `aci-memory`, `avfs` | 12 steps, 18 tool calls |
| `investigation` | Performs SIEM-backed investigation, enriches artifacts, maintains the findings board, and posts a grounded final report. | `aci-thehive`, `aci-wazuh`, `aci-taskqueue`, `aci-board`, `aci-memory`, `avfs` | 40 steps, 60 tool calls |

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

- `seed` creates initial queue work. Investigation creates a "Populate
  investigation queue" task from the handoff when no pending work exists.
- `claim` owns queue claiming. `claim_next` is never exposed to the model.
- `think` calls the model with allowed tools and compacts old non-evidence
  context when prompt tokens exceed about 80% of the configured context length.
- `use_tools` executes MCP calls, caps oversized tool results, expands AVFS `~`
  paths, records artifacts from event-shaped JSON, and can trigger TI enrichment.
- `assess` completes the current task with a non-empty summary and applies guard
  rails: seed population, triage SIEM query, investigation SIEM query, and
  required investigation summary sections.
- `pivot` updates the Findings Board from `## Confirmed Facts` and
  `## Hypotheses`, validates `## New Leads`, queues approved follow-up tasks,
  and posts an immediate escalation comment when active compromise is confirmed.
- `finish` builds the structured final investigation summary or marks budget
  exhaustion.
- `verdict_contract` generates/repairs the canonical fenced JSON verdict block.
- `reassess_verdict` compares triage and investigation verdicts, resolving
  conflicts with a focused model call only when needed.
- `publish_finish` writes `final.md` to AVFS and posts the report to TheHive.

## Configuration Model

The settings model is DB-over-env:

- `ModelProviderConfig`: base URL, API key, model, tool-calling mode, timeout,
  context length, and sampling parameters.
- `ProviderConfig`: enabled state and connection settings for built-in connectors
  such as Wazuh, TheHive, and VirusTotal.
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

## Development Commands

Offline verification:

```bash
PYTHONPATH=. python -m pytest tests/unit tests/django -q
```

Focused examples:

```bash
PYTHONPATH=. python -m pytest tests/unit/test_graph_stub.py -q
PYTHONPATH=. python -m pytest tests/unit/test_verdict_parsing.py -q
PYTHONPATH=. python -m pytest tests/unit/test_lead_model.py -q
PYTHONPATH=. python -m pytest tests/unit/test_compaction_preserves_tool_messages.py -q
```

Local inspection scripts live in `scripts/dev/`; see `scripts/dev/README.md`.
