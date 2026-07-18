# Connecting With SOC Technologies

ACI investigates through your existing SIEM, SOAR, and threat-intelligence (TI)
platforms — it doesn't replace them. This guide covers connecting each supported
platform to ACI: what each one is used for, how to create a connection in the
dashboard, and where to obtain each platform's credentials.

For every other setting (model provider, agents, automation), see the
[Configuration Reference](../reference/configuration.md). For the first-time setup
walkthrough, see [Getting Started](getting-started.md).

## Supported Platforms

| Platform | Category | Used for | Required |
|---|---|---|---|
| [Wazuh](#wazuh-siem) | SIEM | Querying security events, profiling fields, correlating entities, and building the kill-chain view during investigation. | Yes |
| [TheHive](#thehive-soar) | SOAR | Reading cases and alerts, and posting interim notes and the final investigation report. | Yes |
| [VirusTotal](#virustotal-ti) | TI | Enriching confirmed artifacts (IPs, hashes, domains) with reputation data. | Optional |

## Creating A Connection

Every platform is configured the same way, in the dashboard under
**Settings → Integrations**. Connections are grouped into three tables by
platform type — **SIEM**, **SOAR**, **TI** — matching the table above.

1. Open the dashboard and go to **Settings → Integrations**.
2. In the table for the platform's category, click the **+ (Add new)** icon in
   that table's header. This opens a dialog asking for a connection **name**
   (e.g. "Prod Wazuh") and that platform's fields (URL, credentials, etc. — see
   the platform-specific sections below for exactly what each field expects).
3. Fill in the fields and save. The new connection appears as a row in the table.
4. Click **Test** on the row to verify ACI can reach the platform with the
   values you entered, before relying on it in a run.

You can register **more than one connection per platform** — for example, a
production and a lab Wazuh cluster — but only one connection per platform is used
at a time: the one marked **active**. Use the **Set active** action on a row to
switch which connection ACI uses; **Edit** reopens the same dialog to change a
connection's values, and **Delete** removes it (rows can also be multi-selected
for a bulk delete). Secret fields (passwords, API keys) show their currently
stored value on this local console — leave one blank when saving to clear it.

A platform with **no connections configured** falls back to whatever is set in
your `.env` file (if anything) — see the
[Configuration Reference](../reference/configuration.md#integrations-connections)
for that fallback behavior. Whether a platform's connector actually **runs** at
all (separate from which connection it uses) is toggled in
**Settings → MCP servers** for Wazuh and TheHive, or in the Integrations table
header itself for VirusTotal.

## Platform-Specific Setup

<details id="wazuh-siem">
<summary><strong>Wazuh (SIEM)</strong></summary>

ACI queries Wazuh's OpenSearch/Elasticsearch indexer directly — it does not use
the Wazuh dashboard or manager API — so the connection points at the **indexer**,
not the Wazuh manager.

**What you need:**

- The indexer's HTTPS URL and port (default `9200`).
- An indexer user with read access to the alert indices — the built-in `admin`
  user works, but a dedicated read-only role is recommended for production.
- The alert index pattern (default `wazuh-alerts-*`).

**Obtaining indexer credentials:**

1. If you don't already have a dedicated API user, create one in the Wazuh
   indexer's security configuration (`internal_users.yml` on the indexer node, or
   via the OpenSearch Security plugin UI if enabled) and assign it a role with
   read access to `wazuh-alerts-*`.
2. Confirm you can reach the indexer directly, e.g.:
   ```bash
   curl -u <user>:<password> -k https://<indexer-host>:9200/_cluster/health
   ```
   A successful response confirms the URL, credentials, and network path all work
   before you enter them into ACI.

**Fields in ACI's connection form:**

| Field | Value |
|---|---|
| Indexer Base URL | `https://<indexer-host>:9200` |
| Index pattern | `wazuh-alerts-*` (or your custom pattern) |
| User | The indexer user from above |
| Password | That user's password |
| Verify TLS | Off only for a self-signed/dev indexer certificate |

</details>

<details id="thehive-soar">
<summary><strong>TheHive (SOAR)</strong></summary>

**What you need:**

- TheHive's base URL and port (default `9000`).
- An API key for an account with permission to read cases/alerts and create case
  pages/comments.

**Obtaining an API key:**

1. Sign in to TheHive as the account ACI should act as (a dedicated service
   account is recommended over a personal analyst account).
2. Open your user profile (top-right avatar menu → **My profile**, in most
   TheHive 5.x installs).
3. Generate or reveal your **API key** from the profile page and copy it — TheHive
   only shows the full key value once when it's (re)generated.
4. Confirm the organization/permission scope of that account includes the cases
   and alerts ACI should have access to.

**Fields in ACI's connection form:**

| Field | Value |
|---|---|
| API Base URL | `http://<thehive-host>:9000` (include the scheme; `https://` if TLS-terminated) |
| API key | The key from step 3 |
| Verify TLS | Off only for a self-signed/dev certificate |

</details>

<details id="virustotal-ti">
<summary><strong>VirusTotal (TI)</strong></summary>

VirusTotal is optional — without it configured, ACI simply skips artifact
enrichment. It's the only platform here with no dedicated MCP connector; enabling
or disabling it is done directly from its row in the Integrations table rather
than in **Settings → MCP servers**.

**What you need:**

- A VirusTotal account and its API key.

**Obtaining an API key:**

1. Create or sign in to a [VirusTotal](https://www.virustotal.com) account.
2. Open your account menu → **API key** to view your personal API key.
3. Note your account tier's rate limit (the free tier is commonly 4 requests/min)
   — you'll enter this into ACI so it paces enrichment calls correctly.

**Fields in ACI's connection form:**

| Field | Value |
|---|---|
| API key | Your VirusTotal API key — a 64-character hexadecimal string |
| API Base URL | `https://www.virustotal.com` (default; only change for a private/enterprise instance) |
| Rate limit (calls/min) | Your account tier's request-per-minute limit |

</details>

## Next Steps

- [Getting Started](getting-started.md#6-run-an-investigation) — run your first
  investigation once your connections are configured.
- [Configuration Reference](../reference/configuration.md) — every other setting,
  including the model provider and `.env` variables.
