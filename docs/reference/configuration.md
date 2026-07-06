# Configuration Reference

### Core Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | Required | Django secret key (auto-generated) |
| `WORKFLOWS_ENABLED` | `false` | Fallback global workflow enable switch when DB runtime config is unset |

Model provider settings are primarily DB-backed through `ModelProviderConfig`
via Dashboard -> Settings. `.env` is now mainly bootstrap and fallback config.

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
| `TI_CACHE_DB_PATH` | `ti_cache.db` | Threat-intelligence cache SQLite database path |
