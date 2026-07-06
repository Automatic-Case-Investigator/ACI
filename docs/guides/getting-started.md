# Getting Started

Install ACI, configure it, and run your first investigation. Steps 1–5 are one-time setup;
step 6 is how you run investigations from then on.

Then open the dashboard → **Settings** to configure the model provider and the Wazuh/TheHive
connections. The sections below walk through each step.

## Prerequisites

- **Python 3.13** with pip
- **Docker & Docker Compose** (for the AVFS workspace container)
- **External services** (local or remote):
  - Wazuh 4.x (SIEM)
  - TheHive 5.x (SOAR)
  - An OpenAI-compatible LLM API (vLLM, Ollama, or Claude API)

## How configuration works

ACI reads configuration from two places — knowing which is which avoids the most common
setup mistake:

- **`.env`** — bootstrap and workspace settings, read at startup (step 2).
- **Dashboard → Settings** — the model provider and the Wazuh/TheHive/VirusTotal
  connections, stored in the database (step 5). These are **not** in `.env`.

See the [Configuration Reference](../reference/configuration.md) for every setting.

## 1. Install dependencies

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

## 2. Configure `.env`

```bash
cp sample.env .env
```

`.env` holds only bootstrap and workspace settings. The one you must change is
`AVFS_AUTH_TOKEN` — while it stays the literal `change-me-avfs-token`, AVFS is disabled.

```env
# Django
SECRET_KEY=change-me-in-production
DEBUG=true
ALLOWED_HOSTS=*

# Which agents emit an extra LLM-generated public progress note before each action
# ("triage", "triage,investigation", or "all")
PUBLIC_INTENT_AGENTS=triage

# AVFS shared workspace/memory — docker compose reads these same values
AVFS_URL=http://127.0.0.1:8765/
AVFS_AUTH_TOKEN=change-me-avfs-token   # set to a real secret to ENABLE AVFS
AVFS_AGENT_ID=agent_1

# Global kill-switch for webhook-triggered agent runs (leave false unless using webhooks)
WORKFLOWS_ENABLED=false
```

## 3. Initialize the database and workspace

```bash
python manage.py migrate          # creates the SQLite schema
docker compose up -d avfs         # starts AVFS; reads AVFS_* from your .env
```

## 4. Start the server

```bash
python -m daphne -p 8000 aci.asgi:application
```

Open [http://localhost:8000/dashboard/](http://localhost:8000/dashboard/).

## 5. Configure connections in the dashboard

In the dashboard, open **Settings** and configure:

- **Model provider** — base URL, API key, model name, sampling, context length, and timeout
  for your OpenAI-compatible endpoint (vLLM / Ollama / Claude API).
- **Wazuh (SIEM)** — Base URL, Index pattern, User, Password, Verify TLS.
- **TheHive (SOAR)** — Host, Port, API key, Verify TLS.
- **VirusTotal (TI)** — API key (optional; enables artifact enrichment).

Each connection has a **Test** button that verifies reachability before you save. These
settings are stored in the database and persist across restarts.

## 6. Run an investigation

### Dashboard (interactive)

Type an incident question in the dashboard. The orchestrator keeps a durable analyst session,
routes to triage and investigation as needed, and republishes resumed or restarted specialist
results back into that same analyst-visible session state.

### CLI

```bash
python manage.py run_agent \
  --agent-name investigation \
  --case-id "~254202040" \
  --question "Were there any failed SSH logins in the last 24 hours?"
```

### REST API

Obtain a JWT, then start a run:

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/token/ \
  -H "Content-Type: application/json" \
  -d '{"username": "<user>", "password": "<pass>"}' | python -c "import sys,json;print(json.load(sys.stdin)['access'])")

curl -X POST http://localhost:8000/api/agent/runs/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"agent_name": "investigation", "case_id": "~254202040", "question": "Investigate the case"}'
```

See the [API Reference](../reference/api.md) for the full endpoint list (status, events,
cancel, resume, restart, feedback).

## Next steps

- [Testing](operations.md#testing) — run the offline suite.
- [Architecture Overview](../architecture/overview.md) — how the system is designed.
- [Configuration Reference](../reference/configuration.md) — all settings.