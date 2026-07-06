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

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the canonical runtime design and [`docs/current_project_state.md`](docs/current_project_state.md) for the current implementation snapshot.

## Prerequisites

- **Python 3.13** with pip
- **Docker & Docker Compose** (for AVFS workspace)
- **External services** (local or remote):
  - Wazuh 4.x (SIEM)
  - TheHive 5.x (SOAR)
  - LLM API compatible with OpenAI (vLLM, Ollama, or Claude API)

## Installation

### 1. Clone and set up the environment

```bash
cd ACI
python3.13 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\Activate.ps1

pip install -r requirements.txt
pip install -e aci-mcp-servers/aci-taskqueue
pip install -e aci-mcp-servers/aci-board
pip install -e aci-mcp-servers/aci-memory
pip install -e aci-mcp-servers/aci-wazuh
pip install -e aci-mcp-servers/aci-thehive
```

### 2. Configure environment variables

```bash
cp sample.env .env
```

Edit `.env` with your actual endpoints and credentials:

> The LLM/model provider (base URL, API key, model name, sampling, context
> length, timeout) is configured in the dashboard under **Settings → Model
> provider** and stored in the database — not in `.env`.

```env
# SIEM (Wazuh)
WAZUH_URL=https://wazuh.example.com:9201
WAZUH_USER=admin
WAZUH_PASSWORD=your-password
WAZUH_VERIFY_TLS=false

# SOAR (TheHive)
THEHIVE_HOST=http://thehive.example.com
THEHIVE_PORT=9000
THEHIVE_API_KEY=your-api-key

# Workspace (AVFS)
AVFS_URL=http://127.0.0.1:8765/
AVFS_AUTH_TOKEN=your-secure-token    # NOT "change-me-avfs-token"
AVFS_AGENT_ID=agent_1
```

### 3. Run database migrations

```bash
python manage.py migrate
```

### 4. Start AVFS (Docker)

```bash
docker compose up -d avfs
```

## Running the System

### Option A: Web Dashboard (Interactive)

```bash
python -m daphne -p 8000 aci.asgi:application
```

Open [http://localhost:8000/dashboard/](http://localhost:8000/dashboard/) and type an incident question. The orchestrator keeps a durable analyst session, routes to triage and investigation as needed, and now republishes resumed or restarted specialist results back into that same analyst-visible session state.

### Option B: CLI Agent

```bash
python manage.py run_agent \
  --agent-name investigation \
  --case-id "~254202040" \
  --question "Were there any failed SSH logins in the last 24 hours?"
```

### Option C: REST API

```bash
curl -X POST http://localhost:8000/api/agent/runs/ \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"agent_name": "investigation", "case_id": "~254202040", "question": "Investigate the case"}'
```

See [API Reference](ARCHITECTURE.md#api-reference) in `ARCHITECTURE.md`.

## Testing

All tests run offline (no LLM, Wazuh, TheHive, or AVFS needed):

```bash
# Full offline suite
PYTHONPATH=. python -m pytest tests/unit tests/django -q

# Individual test files
PYTHONPATH=. python -m pytest tests/unit/graph/test_graph_stub.py -v
PYTHONPATH=. python -m pytest tests/unit/analysis/test_verdict_parsing.py -v
```

Tests live under `tests/unit/` (graph logic, per-task self-review, Findings Board + board-driven compromise detection, seeder dedup, Wazuh query-shape guards, provider contracts, prompt composition, verdict parsing, alert metadata, feedback loop, TI enrichment, orchestrator lifecycle) and `tests/django/` (settings and resume/session behavior). Local helper scripts are documented in [`scripts/dev/README.md`](scripts/dev/README.md).

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
├── docs/
│   ├── current_project_state.md  # Current runtime/configuration snapshot (bridges README/ARCHITECTURE)
│   └── soc_agent_rubric.md       # SOC investigation quality rubric
├── sample.env                    # Environment variable template
├── requirements.txt              # Python dependencies
├── manage.py                     # Django management CLI
├── ARCHITECTURE.md               # Runtime design, graph diagrams, API reference, configuration, troubleshooting
└── README.md                     # This file
```

## License

(License information to be added)

## See Also

- [ARCHITECTURE.md](ARCHITECTURE.md) — Runtime design, graph diagrams, API reference, configuration, and troubleshooting
- [docs/current_project_state.md](docs/current_project_state.md) — Current runtime shape, built-in providers, configuration model, and workflows
- [Agent Prompts](agent/prompts/) — Triage, investigation, and orchestrator instructions
- [Sample Configuration](sample.env) — Environment variable template
