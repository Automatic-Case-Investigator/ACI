# Getting Started

This is a tutorial of installing, configuring, and running the platform.

## Prerequisites

- **Python 3.13** with pip
- **Docker & Docker Compose** (for the AVFS workspace container)
- **External services** (local or remote):
  - Wazuh 4.x (SIEM)
  - TheHive 5.x (SOAR)
  - An OpenAI-compatible LLM API (vLLM, Ollama, or OpenAI API)

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

In the dashboard, open **Settings -> Model** and configure model settings:

- base URL: API URL for the LLM provider
- Model name: the model name to use
- API key: API key for authenticating the API
- Tool calling mode: the mode used for tool calling (auto recommended)
- Temperature: Parameter deciding how creative the token decoding should be (0 stands for completely deterministic)
- Max tokens: Maximum tokens allowed for the input
- Context length: Context window size
- Request timeout: Timeout for waiting LLM provider response (none recommended)

In the dashboard, open **Settings -> Integrations** and configure integration with SOC technologies:

- **SIEM** — Base URL, Index pattern, Authentication credentials, Verify TLS.
- **SOAR** — Host, Port, Authentication credentials, Verify TLS.
- **TI (Optional)** — API key (optional; enables artifact enrichment).

For platform-by-platform setup — including where to obtain each platform's API
key — see [Connecting With SOC Technologies](connecting-with-soc-technologies.md).

## 6. Run an investigation

Type an incident question in the dashboard. The orchestrator should spawn a session and routes to triage and investigation as needed.

![image](/assets/images/example_conversation_start.png)