# Configuration Reference

ACI has two configuration layers:

- **`.env`** — bootstrap, workspace, and runtime-tuning settings read at process startup
  (listed below). Copy `sample.env` to `.env` to start.
- **Dashboard → Settings** — the model provider and the SIEM/SOAR/TI **connections**, stored
  in the database (`ModelProviderConfig`, `IntegrationConnection`, `ProviderConfig`). These are
  **not** in `.env`; see [Dashboard settings](#dashboard-settings-database-backed).

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
restarts, not in `.env`.

### Model provider

A single OpenAI-compatible model provider (`ModelProviderConfig`): Base URL, API key, model
name, tool-calling mode, sampling params, context length, and request timeout. Works with
vLLM, Ollama, the Claude API, or any OpenAI-compatible endpoint.

### Integrations (connections)

Integrations are **named connections** grouped by platform type (SIEM / SOAR / TI), stored as
`IntegrationConnection` rows. You can register **as many connections per provider as you like**
(e.g. a prod and a lab Wazuh); the one marked **active** is what the agent uses at run time.
Each connection has **Test** (probe reachability), **Set active**, **Edit**, and **Delete**
actions, and connections can be multi-selected for bulk delete.

| Provider (type) | Fields |
|-----------------|--------|
| **Wazuh** (SIEM) | Indexer Base URL, Index pattern, User, Password, Verify TLS |
| **TheHive** (SOAR) | API Base URL, API key, Verify TLS |
| **VirusTotal** (TI) | API key, API Base URL, Rate limit (calls/min) |

Whether a provider *runs at all* is a separate enable/disable toggle: for Wazuh and TheHive it
lives in **Settings → MCP servers**; for VirusTotal (TI enrichment — no MCP server) the toggle
is in the Integrations group header.

**Resolution precedence** (lowest → highest), per provider:

```
.env / built-in defaults  <  ProviderConfig.settings (legacy)  <  active IntegrationConnection
```

A provider with **no** connections behaves exactly as before — it falls back to the legacy
`ProviderConfig` row and the `.env` values (e.g. `VT_API_KEY`), so existing deployments need no
changes.

> **Migration note:** TheHive's former separate `Host` + `Port` fields are now a single
> **API Base URL** (e.g. `http://thehive:9000`). Connections saved under the old schema keep
> working — the URL is derived from the stored host/port until you next save.

See [Getting Started](../guides/getting-started.md#5-configure-connections-in-the-dashboard)
for the setup walkthrough.
