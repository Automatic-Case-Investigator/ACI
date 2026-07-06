# Configuration Reference

ACI has two configuration layers:

- **`.env`** — bootstrap, workspace, and runtime-tuning settings read at process startup
  (listed below). Copy `sample.env` to `.env` to start.
- **Dashboard → Settings** — the model provider and the SIEM/SOAR/TI **connections**, stored
  in the database (`ModelProviderConfig` / `ProviderConfig`). These are **not** in `.env`;
  see [Dashboard settings](#dashboard-settings-database-backed).

## Environment variables (`.env`)

### Core

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | `dev-secret-key-...` | Django secret key (set a real value in production) |
| `DEBUG` | `true` | Django debug mode |
| `ALLOWED_HOSTS` | `*` | Comma-separated allowed hosts |
| `PUBLIC_INTENT_AGENTS` | `triage` | Agents that emit an LLM-generated public progress note before each action (`triage`, `triage,investigation`, or `all`) |
| `WORKFLOWS_ENABLED` | `false` | Global kill-switch for webhook-triggered agent runs |

### Workspace (AVFS)

| Variable | Default | Description |
|----------|---------|-------------|
| `AVFS_URL` | `http://127.0.0.1:8765/` | AVFS HTTP endpoint |
| `AVFS_AUTH_TOKEN` | Required | AVFS auth token — AVFS stays disabled while this is the literal `change-me-avfs-token` |
| `AVFS_AGENT_ID` | `agent_1` | Agent workspace identifier |

### Baselines

| Variable | Default | Description |
|----------|---------|-------------|
| `BASELINE_SIEM_ADAPTER` | `wazuh` | Adapter used to compute host/behavior baselines |
| `BASELINE_WINDOW_DAYS` | `30` | Look-back window for baseline computation |
| `BASELINE_COMPUTE_INTERVAL_HOURS` | `24` | How often baselines recompute |

### Databases (SQLite paths)

| Variable | Default | Description |
|----------|---------|-------------|
| `TASKQUEUE_DB_PATH` | `taskqueue.db` | Task queue database |
| `BOARD_DB_PATH` | `board.db` | Findings Board database |
| `TI_CACHE_DB_PATH` | `ti_cache.db` | Threat-intelligence cache database |

### Threat intelligence (optional)

VirusTotal can also be configured in the dashboard (see below); these variables are the
`.env` fallback and rate-limit tuning.

| Variable | Default | Description |
|----------|---------|-------------|
| `VT_API_KEY` | `""` | VirusTotal API key (enables enrichment when set) |
| `VT_BASE_URL` | `https://www.virustotal.com` | VirusTotal API base URL |
| `TI_CACHE_TTL_HOURS` | `24` | Enrichment cache TTL |
| `TI_CALLS_PER_MINUTE` | `4` | Enrichment rate limit |

## Dashboard settings (database-backed)

Configured under **Settings** in the dashboard and stored in the database — persisted across
restarts, not in `.env`. Each connection has a **Test** button that verifies reachability
before saving.

| Setting | Fields |
|---------|--------|
| **Model provider** | Base URL, API key, model name, sampling, context length, timeout (OpenAI-compatible: vLLM / Ollama / Claude API) |
| **Wazuh (SIEM)** | Base URL, Index pattern, User, Password, Verify TLS |
| **TheHive (SOAR)** | Host, Port, API key, Verify TLS |
| **VirusTotal (TI)** | API key |

See [Getting Started](../guides/getting-started.md#5-configure-connections-in-the-dashboard)
for the setup walkthrough.
