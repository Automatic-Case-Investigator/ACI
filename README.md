# ACI — Autonomous Case Investigator

**ACI** is a SOC (Security Operations Center) agent platform that automates alert triage and multi-step incident investigation using agentic AI. Built on Django 5, LangGraph, MCP, and WebSocket-driven real-time streaming, ACI transforms raw SIEM/SOAR alerts into structured, evidence-backed incident reports.

Most AI SOC tools optimize for speed across the full alert-to-response lifecycle — triage, enrichment, risk scoring, containment. ACI's focus is different: deeper investigation before conclusion. It breaks a case into discrete investigation tasks, runs iterative SIEM queries, preserves intermediate evidence, and anchors every finding to retrieved log events rather than case narrative. The result is a traceable investigation record — what happened, which evidence supports it, which claims are still unconfirmed, and what follow-up is needed — that analysts, responders, and auditors can independently verify.

## Features

- **Live reasoning stream**: Real-time visibility into agent intent, tool calls, and results via WebSocket dashboard
- **Task-driven investigation**: Cases are decomposed into discrete, prioritized tasks worked one at a time, keeping investigation focused and progress auditable
- **Evidence-anchored findings**: Confirmed facts, working hypotheses, and extracted artifacts are tracked across tasks and tied to specific retrieved log events
- **MCP tool ecosystem**: Pluggable integrations with SIEM, SOAR, workspace, and memory providers via Model Context Protocol
- **Durable analyst session state**: Orchestrator conversations, specialist handoffs, resumes, and restarts are persisted back into the analyst-visible session state

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Dashboard (WebSocket)             │
│         Analyst ↔ Live Event Stream                  │
└──────────────────────┬──────────────────────────────┘
                       │
┌──────────────────────┴──────────────────────────────┐
│              Django 5 + Daphne ASGI                  │
│  ┌─────────────────────────────────────────────┐   │
│  │  Orchestrator Session Runtime                │   │
│  │    ↓ triage() ↓ investigate()                │   │
│  │  ┌──────────────┐  ┌──────────────┐         │   │
│  │  │Triage Agent  │  │Investigation │         │   │
│  │  │(Alert→Plan)  │  │Agent(Queue)  │         │   │
│  │  └──────────────┘  └──────────────┘         │   │
│  └─────────────────────────────────────────────┘   │
│                       │                             │
│  ┌────────────────────┴─────────────────────────┐  │
│  │     MCP Provider Layer                        │  │
│  │  • aci-wazuh (SIEM search/events)           │  │
│  │  • aci-thehive (SOAR case mgmt)             │  │
│  │  • aci-board (findings board)               │  │
│  │  • aci-taskqueue (task queue)               │  │
│  │  • aci-memory / avfs / custom MCP           │  │
│  └──────────────────────────────────────────────┘  │
│                       │                             │
└───────────────────────┼─────────────────────────────┘
                        │
        ┌───────────────┼───────────────┐
        │               │               │
      Wazuh          TheHive          AVFS
      (SIEM)         (SOAR)       (Workspace)
```

See the [documentation](docs/README.md) for the full design, organized by subsystem —
start with the [Architecture Overview](docs/architecture/overview.md). For the current
implementation snapshot, see [Current State](docs/project/current-state.md).

## Quick Start

```bash
python3.13 -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\Activate.ps1
pip install -r requirements.txt
for pkg in taskqueue board memory wazuh thehive; do pip install -e aci-mcp-servers/aci-$pkg; done
cp sample.env .env            # then edit endpoints/credentials
python manage.py migrate
docker compose up -d avfs
python -m daphne -p 8000 aci.asgi:application   # open http://localhost:8000/dashboard/
```

Full setup, run options (dashboard / CLI / REST), and testing are in the guides:

- [Getting Started](docs/guides/getting-started.md) — prerequisites, installation, configuration, running.
- [Operations](docs/guides/operations.md) — testing, development, troubleshooting.

## Documentation

Full documentation lives in [`docs/`](docs/README.md), organized by subsystem:

- **Architecture** — [overview](docs/architecture/overview.md), [runtime & agent graph](docs/architecture/runtime/agent-graph.md), [prompts](docs/architecture/runtime/prompts.md), [queue & streaming](docs/architecture/runtime/queue-and-streaming.md), [orchestrator](docs/architecture/orchestrator.md), [tools](docs/architecture/tools.md), [findings board](docs/architecture/findings-board.md), [workspace](docs/architecture/workspace.md), [automation](docs/architecture/automation.md).
- **Reference** — [configuration](docs/reference/configuration.md), [API](docs/reference/api.md).
- **Project** — [current state](docs/project/current-state.md), [SOC rubric](docs/project/soc-rubric.md).

## Project Structure

```
ACI/
├── aci/                          # Django project config (settings, urls, asgi/wsgi)
├── agent/                        # Django app: agent runtime, dashboard, models
│   ├── agents/                   # Agent registry + definitions: triage, investigation, seeder
│   ├── prompts/                  # Layered system prompts (platform, triage, investigation, seeder, playbook, orchestrator)
│   ├── runtime/                  # Harness layer — see breakdown below
│   ├── ti/                       # Threat-intelligence enrichment (cache, providers e.g. VirusTotal)
│   ├── workspace/                # AVFS writer, citation helpers, workspace indexer
│   ├── dashboard/                # WebSocket consumer, run views/actions, settings views, runner lifecycle
│   ├── models/                   # Django models: AgentRun, AgentEvent, config, learning (patterns/baselines/feedback)
│   ├── views/                    # REST API views: runs, webhooks, public endpoints
│   ├── management/commands/      # run_agent, run_workflow, compute_baselines
│   └── templatetags/
├── agent/runtime/                # (expanded)
│   ├── engine/                   # run_agent, dispatch_run, MCP client, model client, streaming, seeder_runner
│   ├── graph/                    # LangGraph build: builder, nodes_loop, interpretation/ (interpret node),
│   │                              # nodes_flow/ (assess/pivot/completion), observation, reflection (self-review),
│   │                              # leads/lead_model, board, validation, synthesis, publication, parsing, timeutil, state
│   ├── analysis/                 # Deterministic enrichment: artifacts (incl. decode layer), correlation_leads,
│   │                              # kill_chain, query_memo, pattern_matcher, alert_metadata, intent
│   ├── orchestrator/             # Conversational orchestrator: driver, session, messages, prompts, tools,
│   │                              # specialist_sync (publishes resumed/restarted results back to session)
│   ├── providers/                # Built-in MCP provider configs + standardized capability contracts
│   ├── config/                   # Prompt composition, runtime/agent-config overrides
│   ├── policy/                   # Workflow automation policy: dedup, escalation routing (separate from reasoning)
│   ├── triggers/                 # Webhook trigger bindings/providers/registry
│   ├── learning/                 # Baseline computation + adapters
│   └── infra/                    # AVFS path helpers, event logbus
├── aci-mcp-servers/              # Installable MCP server packages (each `pip install -e`-able)
│   ├── aci-taskqueue/            # MCP: task queue (claim authority)
│   ├── aci-board/                # MCP: Findings Board (facts/hypotheses/artifacts/correlations/kill-chain/TI)
│   ├── aci-memory/                # MCP: cross-case patterns, baselines, analyst feedback (read-only)
│   ├── aci-wazuh/                # MCP: SIEM search/events/profiling + query-shape robustness guards
│   └── aci-thehive/              # MCP: SOAR case/alert reads, comments, report publication
├── static/dashboard/             # Frontend JavaScript and CSS
├── templates/                    # Django templates
├── tests/
│   ├── unit/                     # Graph/reflection/board/seeder/Wazuh-client/prompt-layer unit tests (offline)
│   ├── django/                   # Settings + resume/session behavior (Django test client)
│   └── integration/              # End-to-end scenario tests
├── scripts/dev/                  # Local inspection scripts (inspect_events, poll, submit) — see scripts/dev/README.md
├── docs/                         # Documentation, organized by subsystem (see docs/README.md)
│   ├── architecture/             # Explanation: overview, runtime, orchestrator, tools, board, workspace, automation
│   ├── reference/                # Configuration + API reference
│   ├── guides/                   # Getting started + operations (testing, dev, troubleshooting)
│   └── project/                  # current-state.md, soc-rubric.md
├── sample.env                    # Environment variable template
├── requirements.txt              # Python dependencies
├── manage.py                     # Django management CLI
├── ARCHITECTURE.md               # Redirect stub → docs/
└── README.md                     # This file
```

## License

(License information to be added)

## See Also

- [Documentation](docs/README.md) — full docs index, organized by subsystem
- [Architecture Overview](docs/architecture/overview.md) — runtime design, graph diagrams, and design philosophy
- [Current State](docs/project/current-state.md) — current runtime shape, built-in providers, configuration model, and workflows
- [Agent Prompts](agent/prompts/) — Triage, investigation, and orchestrator instructions
- [Sample Configuration](sample.env) — Environment variable template
