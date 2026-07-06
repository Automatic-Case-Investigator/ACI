# Getting Started

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

For the full list of settings, see the [Configuration Reference](../reference/configuration.md).

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

Open [http://localhost:8000/dashboard/](http://localhost:8000/dashboard/) and type an incident question. The orchestrator keeps a durable analyst session, routes to triage and investigation as needed, and republishes resumed or restarted specialist results back into that same analyst-visible session state.

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

See the [API Reference](../reference/api.md) for the full endpoint list.

## Next steps

- [Testing](operations.md#testing) — run the offline suite.
- [Architecture Overview](../architecture/overview.md) — how the system is designed.
