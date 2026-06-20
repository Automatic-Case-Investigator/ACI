# ACI — Autonomous Case Investigator

**ACI** is a SOC (Security Operations Center) agent platform that automates security incident investigation using agentic AI. Built on Django 5, LangGraph, and WebSocket-driven real-time streaming, ACI transforms raw SIEM/SOAR alerts into structured, evidence-backed incident reports.

Most AI SOC tools optimize for speed across the full alert-to-response lifecycle — triage, enrichment, risk scoring, containment. ACI's focus is different: deeper investigation before conclusion. It breaks a case into discrete investigation tasks, runs iterative SIEM queries, preserves intermediate evidence, and anchors every finding to retrieved log events rather than case narrative. The result is a traceable investigation record — what happened, which evidence supports it, which claims are still unconfirmed, and what follow-up is needed — that analysts, responders, and auditors can independently verify.

## Features

- **Live reasoning stream**: Real-time visibility into agent intent, tool calls, and results via WebSocket dashboard
- **Task-driven investigation**: Cases are decomposed into discrete, prioritized tasks worked one at a time, keeping investigation focused and progress auditable
- **Evidence-anchored findings**: Confirmed facts, working hypotheses, and extracted artifacts are tracked across tasks and tied to specific retrieved log events
- **MCP tool ecosystem**: Pluggable integrations with SIEM and SOAR platforms via Model Context Protocol

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

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for detailed runtime design, graph diagrams, API reference, and configuration.

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
LLM_BASE_URL=http://vllm.example.com/v1
LLM_API_KEY=your-api-key-here
LLM_MODEL_NAME=meta-llama/Llama-2-13b-hf

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

Open [http://localhost:8000/dashboard/](http://localhost:8000/dashboard/) and type an incident question. The orchestrator routes to triage → analyst confirmation → investigation.

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
PYTHONPATH=. python .claude/skills/run-aci-backend/tests/test_graph_stub.py -v
```

## Project Structure

```
ACI/
├── aci/                    # Django core configuration
├── agent/
│   ├── agents/             # Agent definitions (orchestrator, triage, investigation)
│   ├── prompts/            # System prompts for each agent
│   ├── runtime/            # LangGraph graph, orchestrator, MCP providers
│   ├── dashboard/          # WebSocket consumer and dashboard views
│   ├── models.py           # Django models (AgentRun, AgentEvent)
│   └── workspace/          # AVFS integration and workspace I/O
├── aci-mcp-servers/
│   ├── aci-taskqueue/      # MCP: Task queue
│   ├── aci-board/          # MCP: Findings board
│   ├── aci-wazuh/          # MCP: SIEM search
│   └── aci-thehive/        # MCP: SOAR case management
├── static/dashboard/       # Frontend JavaScript and CSS
├── templates/              # Django templates
├── sample.env              # Environment variable template
├── requirements.txt        # Python dependencies
├── manage.py               # Django management CLI
├── ARCHITECTURE.md         # Runtime design, API reference, configuration
└── README.md               # This file
```

## License

(License information to be added)

## See Also

- [ARCHITECTURE.md](ARCHITECTURE.md) — Runtime design, graph diagrams, API reference, configuration, and troubleshooting
- [Agent Prompts](agent/prompts/) — Triage, investigation, and orchestrator instructions
- [Sample Configuration](sample.env) — Environment variable template
