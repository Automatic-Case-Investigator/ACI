# ACI — Autonomous Cyber Investigation

**ACI** is a production-grade SOC (Security Operations Center) agent platform that automates security incident investigation using agentic AI. Built on Django 5, LangGraph, and WebSocket-driven real-time streaming, ACI transforms raw SIEM/SOAR alerts into structured, evidence-backed incident reports.

## Features

- **Multi-agent orchestration**: Triage → Orchestrator → Investigation pipeline with natural handoff and state management
- **Live reasoning stream**: Real-time visibility into agent intent, tool calls, and results via WebSocket dashboard
- **Evidence-backed findings**: Mandatory raw-event validation; no fabricated facts
- **Findings board**: Persistent tracking of confirmed facts, hypotheses, and artifacts across investigation tasks
- **MCP tool ecosystem**: Integrations with Wazuh (SIEM), TheHive (SOAR), and AVFS (workspace) via Model Context Protocol
- **Task queue**: Human-in-the-loop task management with dynamic lead creation and prioritization
- **Production safety**: Budget-aware execution, graceful degradation, and transparent task completion

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
│  │  Orchestrator Agent (LangGraph)              │   │
│  │    ↓ triage() ↓ investigate()                │   │
│  │  ┌──────────────┐  ┌──────────────┐         │   │
│  │  │Triage Agent  │  │Investigation │         │   │
│  │  │(Alert→Plan)  │  │Agent(Queue)  │         │   │
│  │  └──────────────┘  └──────────────┘         │   │
│  └─────────────────────────────────────────────┘   │
│                       │                             │
│  ┌────────────────────┴─────────────────────────┐  │
│  │     MCP Tool Ecosystem (stdio)               │  │
│  │  • aci-wazuh (SIEM search/events)           │  │
│  │  • aci-thehive (SOAR case mgmt)             │  │
│  │  • aci-board (findings board)               │  │
│  │  • aci-taskqueue (task queue)               │  │
│  └──────────────────────────────────────────────┘  │
│                       │                             │
└───────────────────────┼─────────────────────────────┘
                        │
        ┌───────────────┼───────────────┐
        │               │               │
      Wazuh          TheHive          AVFS
      (SIEM)         (SOAR)       (Workspace)
```

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for detailed runtime design and graph diagrams.

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
pip install -e aci-mcp-servers/aci-wazuh
pip install -e aci-mcp-servers/aci-thehive
```

### 2. Configure environment variables

```bash
cp sample.env .env
```

Edit `.env` with your actual endpoints and credentials:

```env
# LLM Configuration
LLM_BASE_URL=http://vllm.example.com/v1          # vLLM, Ollama, or Claude API endpoint
LLM_API_KEY=your-api-key-here
LLM_MODEL_NAME=meta-llama/Llama-2-13b-hf          # Model identifier

# SIEM (Wazuh)
WAZUH_URL=https://wazuh.example.com:9201
WAZUH_USER=admin
WAZUH_PASSWORD=your-password
WAZUH_VERIFY_TLS=false                            # Set to true in production

# SOAR (TheHive)
THEHIVE_HOST=http://thehive.example.com
THEHIVE_PORT=9000
THEHIVE_API_KEY=your-api-key

# Workspace (AVFS)
AVFS_URL=http://127.0.0.1:8765/
AVFS_AUTH_TOKEN=your-secure-token                # NOT "change-me-avfs-token"
AVFS_AGENT_ID=agent_1
```

### 3. Run database migrations

```bash
python manage.py migrate
```

### 4. Start AVFS (Docker)

AVFS provides the agent workspace for storing evidence, findings, and investigation output.

```bash
docker compose up -d avfs

# Verify it's running
docker compose logs -f avfs
```

To stop:
```bash
docker compose down
```

## Running the System

### Option A: Web Dashboard (Interactive)

Start the Django development server:

```bash
python -m daphne -p 8000 aci_backend.asgi:application
```

Open [http://localhost:8000/dashboard/](http://localhost:8000/dashboard/) and type an incident question. The orchestrator will route to triage → confirmation → investigation.

### Option B: CLI Agent

Run an agent directly (headless, no dashboard):

```bash
python manage.py run_agent \
  --agent-name investigation \
  --case-id "~254202040" \
  --question "Were there any failed SSH logins in the last 24 hours?"
```

### Option C: REST API

Submit and poll agent runs programmatically:

```bash
# Start run
curl -X POST http://localhost:8000/api/agent/runs/ \
  -H "Authorization: Bearer <token>" \
  -d '{
    "agent_name": "investigation",
    "case_id": "~254202040",
    "question": "Investigate the case"
  }'

# Poll for completion
curl http://localhost:8000/api/agent/runs/<run_id>/
```

See [API Reference](#api-reference) below.

## Testing

All tests run offline (no LLM, Wazuh, TheHive, or AVFS needed):

```bash
# From project root
PYTHONPATH=. python .claude/skills/run-aci-backend/tests/test_graph_stub.py -v
```

Tests cover:
- LangGraph agent execution and state transitions
- Task queue seeding from triage handoff
- Triage → investigation handoff mechanics
- Findings board persistence and deduplication
- Intent streaming and event correlation

## Project Structure

```
ACI/
├── aci_backend/                    # Django core configuration
│   ├── settings.py                 # Django settings
│   ├── asgi.py                     # Daphne ASGI entry point
│   └── urls.py                     # URL routing
├── agent/
│   ├── agents/                     # Agent definitions (orchestrator, triage, investigation)
│   ├── prompts/                    # System prompts for each agent
│   ├── runtime/
│   │   ├── graph.py                # LangGraph execution graph
│   │   ├── orchestrator.py         # Multi-round analyst conversation loop
│   │   └── providers/              # MCP tool providers
│   ├── dashboard/                  # WebSocket consumer and dashboard views
│   ├── models.py                   # Django models (AgentRun, AgentEvent)
│   ├── management/commands/        # Django CLI commands
│   └── workspace/                  # AVFS integration and workspace I/O
├── aci-mcp-servers/
│   ├── aci-taskqueue/              # MCP: Task queue (crud operations on queue)
│   ├── aci-board/                  # MCP: Findings board (facts, hypotheses, artifacts)
│   ├── aci-wazuh/                  # MCP: SIEM search and event retrieval
│   └── aci-thehive/                # MCP: SOAR case and alert management
├── static/dashboard/               # Frontend: JavaScript and CSS
│   ├── app.js                      # WebSocket client and event rendering
│   └── app.css                     # Dashboard styles
├── templates/                      # Django templates
│   ├── cotton/                     # Base layout and components
│   └── dashboard/                  # Dashboard views and event templates
├── .claude/
│   ├── skills/run-aci-backend/     # Claude Code skill definition
│   ├── debug/                      # Debug and check scripts
│   └── projects/*/memory/          # Project memory for context continuity
├── sample.env                      # Environment variable template
├── requirements.txt                # Python dependencies
├── manage.py                       # Django management CLI
├── ARCHITECTURE.md                 # Technical architecture and design
└── README.md                       # This file
```

## Configuration Reference

### Core Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_BASE_URL` | Required | OpenAI-compatible LLM API endpoint |
| `LLM_API_KEY` | Required | API authentication key |
| `LLM_MODEL_NAME` | Required | Model identifier (e.g., `gpt-4`, `llama2`) |
| `LLM_TIMEOUT` | 0 (disabled) | Request timeout in seconds |
| `SECRET_KEY` | Required | Django secret key (auto-generated) |

### SIEM Integration (Wazuh)

| Variable | Default | Description |
|----------|---------|-------------|
| `WAZUH_URL` | Required | Wazuh API endpoint (https://...:9201) |
| `WAZUH_USER` | Required | Wazuh admin username |
| `WAZUH_PASSWORD` | Required | Wazuh admin password |
| `WAZUH_VERIFY_TLS` | `true` | Verify SSL certificates |

### SOAR Integration (TheHive)

| Variable | Default | Description |
|----------|---------|-------------|
| `THEHIVE_HOST` | Required | TheHive API host |
| `THEHIVE_PORT` | 9000 | TheHive API port |
| `THEHIVE_API_KEY` | Required | TheHive API key |

### Workspace (AVFS)

| Variable | Default | Description |
|----------|---------|-------------|
| `AVFS_URL` | `http://127.0.0.1:8765/` | AVFS HTTP endpoint |
| `AVFS_AUTH_TOKEN` | Required | AVFS authentication token (NOT `change-me-avfs-token`) |
| `AVFS_AGENT_ID` | `agent_1` | Agent workspace identifier |

### Database

| Variable | Default | Description |
|----------|---------|-------------|
| `TASKQUEUE_DB_PATH` | `taskqueue.db` | Task queue SQLite database path |
| `BOARD_DB_PATH` | `board.db` | Findings board SQLite database path |

## API Reference

### Agent Runs

#### Start a run
```
POST /api/agent/runs/
Authorization: Bearer <token>
Content-Type: application/json

{
  "agent_name": "investigation",
  "case_id": "~254202040",
  "question": "What happened?"
}

Response: { "run_id": "...", "status": "queued" }
```

#### Get run status
```
GET /api/agent/runs/<run_id>/
Authorization: Bearer <token>

Response: {
  "run_id": "...",
  "status": "completed",
  "result": "...",
  "error": null
}
```

#### Get run events (streamed)
```
GET /api/agent/runs/<run_id>/events/
Authorization: Bearer <token>

Response: [
  { "id": 1, "kind": "note", "source": "orchestrator", "summary": "..." },
  ...
]
```

#### Cancel a run
```
POST /api/agent/runs/<run_id>/cancel/
Authorization: Bearer <token>
```

#### Resume a run
```
POST /api/agent/runs/<run_id>/resume/
Authorization: Bearer <token>
```

### Task Queue

```
GET    /api/agent/cases/<case_id>/queues/<agent_name>/tasks/?run_id=<run_id>
POST   /api/agent/cases/<case_id>/queues/<agent_name>/tasks/
PATCH  /api/agent/cases/<case_id>/queues/<agent_name>/tasks/<task_id>/
DELETE /api/agent/cases/<case_id>/queues/<agent_name>/tasks/<task_id>/
```

### Workspace & Reports

```
GET /api/agent/cases/<case_id>/workspace/
GET /api/agent/cases/<case_id>/reports/latest/
```

## Troubleshooting

### "ModuleNotFoundError: No module named 'aci_taskqueue'"

Ensure MCP servers are installed in editable mode:
```bash
pip install -e aci-mcp-servers/aci-taskqueue
pip install -e aci-mcp-servers/aci-board
```

### "Failed to load MCP instructions for aci-wazuh"

Wazuh is unreachable or credentials are wrong. Verify:
- `WAZUH_URL` points to a live Wazuh instance
- `WAZUH_USER` and `WAZUH_PASSWORD` are correct
- Network connectivity exists

### "AVFS_AUTH_TOKEN is the literal 'change-me-avfs-token'"

AVFS is intentionally disabled with the default token. Set a real token in `.env`:
```env
AVFS_AUTH_TOKEN=your-secure-random-string
```

Then restart the AVFS container:
```bash
docker compose restart avfs
```

### Django migration errors

Run migrations:
```bash
python manage.py migrate
```

### "Harmony token stripping" or empty investigation report

The local LLM may be too small or out of context. Try:
1. Reducing the number of task summaries fed to the final report synthesis
2. Using a larger model (13B+ parameters recommended)
3. Checking `ARCHITECTURE.md` §Report Assembly for guardrails

## Development

### Running debug scripts

Debug and check scripts are in `.claude/debug/`:

```bash
PYTHONPATH=. python .claude/debug/check_run.py
```

Common scripts:
- `check_run.py` — Inspect a specific run's tasks
- `check_session.py` — Inspect a session's events
- `check_board.py` — Inspect the findings board
- `dump_session.py` — Export all events for a session

### Making changes

1. Create a feature branch
2. Update tests if needed (`.claude/skills/run-aci-backend/tests/`)
3. Run the test suite to verify no regressions
4. Commit with a clear message

## Contributing

Contributions are welcome. Please:

1. Follow the code style in the existing codebase
2. Add tests for new functionality
3. Update documentation for user-facing changes
4. Reference issues or design docs in commit messages

## License

(License information to be added)

## Support

For questions or issues:
- Check [ARCHITECTURE.md](ARCHITECTURE.md) for design details
- Review `.claude/skills/run-aci-backend/SKILL.md` for local testing
- Check `.claude/debug/` scripts for common diagnostic queries

## See Also

- [ARCHITECTURE.md](ARCHITECTURE.md) — Technical design, graph diagrams, and runtime contracts
- [Agent Prompts](agent/prompts/) — Triage, investigation, and orchestrator instructions
- [Sample Configuration](sample.env) — Environment variable reference
