"""TheHive 5 REST API client.

Endpoint map (tested against v5.1.9):
  GET  /api/case/{id}             — get case
  GET  /api/case?range=0-N        — list cases
  GET  /api/alert/{id}            — get alert
  POST /api/v1/query              — flexible query engine (used for case alerts)
  POST /api/v1/case/{id}/page     — create a case page (investigation report)
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx


def _epoch_ms_to_iso(value: Any) -> str | None:
    """Convert a TheHive epoch-millisecond timestamp to ISO 8601 UTC."""
    if not isinstance(value, (int, float)):
        return None
    try:
        return datetime.fromtimestamp(value / 1000, tz=timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        return None


class TheHiveClient:
    def __init__(self, *, host: str, port: str = "9000", api_key: str, verify_tls: str = "true") -> None:
        if not host:
            raise ValueError("TheHive host is not configured — set it in Settings → Integrations")
        host = host.rstrip("/")
        if not host.startswith(("http://", "https://")):
            host = f"http://{host}"
        self._base = f"{host}:{port}"
        api_key = api_key.strip().replace('\r', '').replace('\n', '')
        if not api_key:
            raise ValueError("TheHive API key is not configured — set it in Settings → Integrations")
        verify = verify_tls.lower() == "true"
        self._client = httpx.Client(
            base_url=self._base,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            verify=verify,
            timeout=30,
        )

    def _raise(self, r: httpx.Response) -> None:
        if r.is_error:
            raise httpx.HTTPStatusError(
                f"HTTP {r.status_code} {r.request.method} {r.request.url}: {r.text[:300]}",
                request=r.request,
                response=r,
            )

    def _get(self, path: str, params: dict | None = None) -> Any:
        r = self._client.get(path, params=params)
        self._raise(r)
        return r.json()

    def _post(self, path: str, body: dict) -> Any:
        r = self._client.post(path, json=body)
        self._raise(r)
        return r.json()

    def _patch(self, path: str, body: dict) -> Any:
        r = self._client.patch(path, json=body)
        self._raise(r)
        return r.json()

    def _query(self, operations: list[dict]) -> Any:
        return self._post("/api/v1/query", {"query": operations})

    # ── Cases ──────────────────────────────────────────────────────────────────

    def get_case(self, case_id: str) -> dict:
        return self._get(f"/api/case/{case_id}")

    def list_cases(self, max_results: int = 20) -> list[dict]:
        return self._get("/api/case", params={"range": f"0-{max_results}"})

    def update_case(self, case_id: str, fields: dict) -> dict:
        return self._patch(f"/api/case/{case_id}", fields)

    # ── Alerts ─────────────────────────────────────────────────────────────────

    def get_alert(self, alert_id: str) -> dict:
        return self._get(f"/api/alert/{alert_id}")

    # Fields kept when summarising alerts — full descriptions are dropped because
    # a single case can link thousands of alerts (megabytes of markdown).
    _ALERT_SUMMARY_FIELDS = (
        "_id", "type", "source", "sourceRef", "title", "severity",
        "date", "tags", "status", "read",
    )

    # Hard ceiling on how many alert rows we ever return verbatim. A brute-force
    # case can link hundreds of near-identical alerts; dumping them all overflows
    # a small model's context and stalls triage. We always return a deduplicated,
    # grouped `summary` and only a bounded `alerts` sample.
    _ALERT_SAMPLE_CAP = 20
    _ALERT_SCAN_CAP = 500

    def list_case_alerts(self, case_id: str, max_results: int = 20) -> dict:
        """Return a deduplicated, grouped summary of alerts linked to a case.

        TheHive cases can link thousands of alerts; returning them in full
        overflows the model context (and reliably stalls a small triage model).
        We page the query engine, group the alerts by rule/title + severity so
        repeated noisy alerts collapse, and return that compact aggregate plus a
        small representative sample. Use get_alert for full detail on one alert.
        """
        sample_cap = max(1, min(int(max_results or self._ALERT_SAMPLE_CAP), self._ALERT_SAMPLE_CAP))
        alerts = self._query([
            {"_name": "listAlert", "_and": [{"_field": "caseId", "_value": case_id}]},
            {"_name": "page", "from": 0, "to": self._ALERT_SCAN_CAP},
        ])
        if not isinstance(alerts, list):
            return {"total": 0, "returned": 0, "groups": [], "alerts": []}

        summarized = []
        for a in alerts:
            item = {k: a.get(k) for k in self._ALERT_SUMMARY_FIELDS if k in a}
            # Surface a human-readable absolute timestamp so the investigation
            # agent can scope SIEM searches to when the incident actually
            # happened (not "now-1d", which misses historical incidents).
            item["date_iso"] = _epoch_ms_to_iso(a.get("date"))
            summarized.append(item)

        # Group by (title, severity) so a brute-force flood of identical alerts
        # collapses to one row with a count and a first/last-seen window — the
        # shape a triage analyst actually reasons over.
        groups: dict[tuple, dict] = {}
        for item in summarized:
            key = (item.get("title") or item.get("type") or "(untitled)", item.get("severity"))
            g = groups.get(key)
            iso = item.get("date_iso")
            if g is None:
                groups[key] = {
                    "title": key[0], "severity": key[1], "count": 1,
                    "first_seen": iso, "last_seen": iso,
                    "example_id": item.get("_id"), "tags": item.get("tags"),
                }
            else:
                g["count"] += 1
                if iso and (g["first_seen"] is None or iso < g["first_seen"]):
                    g["first_seen"] = iso
                if iso and (g["last_seen"] is None or iso > g["last_seen"]):
                    g["last_seen"] = iso

        grouped = sorted(groups.values(), key=lambda g: g["count"], reverse=True)
        isos = sorted(i["date_iso"] for i in summarized if i.get("date_iso"))
        return {
            "total": len(summarized),
            "truncated": len(summarized) >= self._ALERT_SCAN_CAP,
            "distinct_alert_types": len(grouped),
            "time_range": {"first": isos[0], "last": isos[-1]} if isos else None,
            "groups": grouped,
            # Bounded representative sample (full per-alert detail via get_alert).
            "alerts": summarized[:sample_cap],
        }

    # ── Reports ────────────────────────────────────────────────────────────────

    def post_report(self, case_id: str, summary: str, title: str = "Investigation Report") -> dict:
        """Create a new case page with the investigation summary (TheHive 5 Pages API)."""
        return self._post(f"/api/v1/case/{case_id}/page", {
            "title": title,
            "content": summary,
            "category": "Investigation",
        })

    def post_case_comment(self, case_id: str, message: str) -> dict:
        """Record an ACI workflow note on the case.

        TheHive deployments used by ACI expose the Pages API consistently, while
        `/api/v1/case/{id}/timeline` returns 404 on some versions. Use a dated
        case page for workflow notes so escalation side effects do not fail.
        """
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        return self.post_report(
            case_id,
            f"**{stamp}**\n\n{message}",
            title=f"ACI workflow note {stamp}",
        )
