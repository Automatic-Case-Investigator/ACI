"""Wazuh/OpenSearch baseline adapter.

Encapsulates every Wazuh-specific detail of baseline computation: the client,
the field names (`data.srcuser`, `agent.name`, `rule.id`, `data.srcip`,
`@timestamp`), the OpenSearch query DSL, and which features each subject type
yields. The orchestrator sees only `FeatureResult`s and clean subject IDs.
"""
from __future__ import annotations

import logging
import statistics
from collections import Counter
from datetime import datetime

from .base import FeatureResult
from .registry import register_adapter

log = logging.getLogger(__name__)

# Wazuh populates these placeholder values for missing/unknown users.
_SKIP_USERS = frozenset({"", "-", "N/A", "n/a", "unknown", "(null)"})


def _daily_stats(buckets: list[dict]) -> dict:
    """Summarise date-histogram buckets into mean/std/percentile stats."""
    counts = [b["doc_count"] for b in buckets]
    if not counts:
        return {"daily_mean": 0.0, "daily_std": 0.0, "p5": 0.0, "p95": 0.0, "total_days_observed": 0}
    mean = statistics.mean(counts)
    std = statistics.stdev(counts) if len(counts) > 1 else 0.0
    sorted_counts = sorted(counts)
    n = len(sorted_counts)
    p5 = sorted_counts[max(0, int(n * 0.05))]
    p95 = sorted_counts[min(n - 1, int(n * 0.95))]
    return {
        "daily_mean": round(mean, 2),
        "daily_std": round(std, 2),
        "p5": float(p5),
        "p95": float(p95),
        "total_days_observed": n,
    }


def _hours_from_events(events: list[dict]) -> Counter:
    counter: Counter = Counter()
    for ev in events:
        ts = ev.get("@timestamp")
        if not ts:
            continue
        try:
            dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            counter[str(dt.hour)] += 1
        except (ValueError, TypeError):
            pass
    return counter


class WazuhBaselineAdapter:
    """Derives behavioral baselines from a Wazuh OpenSearch index."""

    name = "wazuh"

    def __init__(self) -> None:
        from aci_wazuh.client import WazuhClient

        self._client = WazuhClient()

    def _time_range(self, days: int) -> dict:
        return {"from": f"now-{days}d", "to": "now"}

    # ── Discovery ────────────────────────────────────────────────────────────

    def discover_subjects(self, subject_type: str, days: int) -> list[str]:
        tr = self._time_range(days)
        if subject_type == "user":
            result = self._client.profile_field("data.srcuser", time_range=tr, top_n=500)
            return [
                v["value"] for v in result.get("top_values", [])
                if v.get("value") and str(v["value"]).strip() not in _SKIP_USERS
            ]
        if subject_type == "endpoint":
            result = self._client.profile_field("agent.name", time_range=tr, top_n=500)
            return [
                v["value"] for v in result.get("top_values", [])
                if v.get("value") and str(v["value"]).strip()
            ]
        return []

    # ── Feature computation ──────────────────────────────────────────────────

    def compute_features(self, subject_type: str, subject_id: str, days: int) -> list[FeatureResult]:
        if subject_type == "user":
            return self._user_features(subject_id, days)
        if subject_type == "endpoint":
            return self._endpoint_features(subject_id, days)
        return []

    def _user_features(self, uid: str, days: int) -> list[FeatureResult]:
        tr = self._time_range(days)
        out: list[FeatureResult] = []

        # source_ips
        try:
            result = self._client.profile_field(
                "data.srcip", query={"term": {"data.srcuser": uid}}, time_range=tr, top_n=20
            )
            out.append(FeatureResult(
                feature="source_ips",
                value={"top_ips": [
                    {"ip": v["value"], "count": v["count"]} for v in result.get("top_values", [])
                ]},
                event_count=result.get("matched_docs", 0),
            ))
        except Exception as exc:
            log.warning("wazuh baseline: user %s source_ips failed: %s", uid, exc)

        # active_hours
        try:
            result = self._client.search(
                {"term": {"data.srcuser": uid}}, time_range=tr, max_results=100,
                source_fields=["@timestamp"],
            )
            hours = _hours_from_events(result.get("events", []))
            # Count the events actually returned — the client runs searches with
            # track_total_hits disabled, so result["total"] is an unreliable
            # lower bound (often 0) and must not be used for the health gate.
            out.append(FeatureResult(
                feature="active_hours",
                value={"counts": dict(hours)},
                event_count=sum(hours.values()),
            ))
        except Exception as exc:
            log.warning("wazuh baseline: user %s active_hours failed: %s", uid, exc)

        # event_volume
        try:
            aggs = {"by_day": {"date_histogram": {"field": "@timestamp", "calendar_interval": "day"}}}
            raw = self._client.aggregate(aggs, query={"term": {"data.srcuser": uid}}, time_range=tr)
            buckets = raw.get("by_day", {}).get("buckets", [])
            out.append(FeatureResult(
                feature="event_volume",
                value=_daily_stats(buckets),
                event_count=sum(b["doc_count"] for b in buckets),
            ))
        except Exception as exc:
            log.warning("wazuh baseline: user %s event_volume failed: %s", uid, exc)

        # auth_failure_rate
        try:
            aggs = {
                "auth_stats": {
                    "filters": {
                        "filters": {
                            "total_auth": {"match": {"rule.groups": "authentication"}},
                            "failed_auth": {"match": {"rule.groups": "authentication_failed"}},
                        }
                    }
                }
            }
            raw = self._client.aggregate(aggs, query={"term": {"data.srcuser": uid}}, time_range=tr)
            buckets = raw.get("auth_stats", {}).get("buckets", {})
            total = buckets.get("total_auth", {}).get("doc_count", 0)
            failed = buckets.get("failed_auth", {}).get("doc_count", 0)
            rate = round(failed / total, 4) if total > 0 else 0.0
            out.append(FeatureResult(
                feature="auth_failure_rate",
                value={"auth_events": total, "auth_failures": failed, "failure_rate": rate},
                event_count=total,
            ))
        except Exception as exc:
            log.warning("wazuh baseline: user %s auth_failure_rate failed: %s", uid, exc)

        return out

    def _endpoint_features(self, eid: str, days: int) -> list[FeatureResult]:
        tr = self._time_range(days)
        out: list[FeatureResult] = []

        # common_rules
        try:
            result = self._client.profile_field(
                "rule.id", query={"term": {"agent.name": eid}}, time_range=tr, top_n=20
            )
            out.append(FeatureResult(
                feature="common_rules",
                value={"top_rules": [
                    {"rule_id": v["value"], "count": v["count"]} for v in result.get("top_values", [])
                ]},
                event_count=result.get("matched_docs", 0),
            ))
        except Exception as exc:
            log.warning("wazuh baseline: endpoint %s common_rules failed: %s", eid, exc)

        # active_hours
        try:
            result = self._client.search(
                {"term": {"agent.name": eid}}, time_range=tr, max_results=100,
                source_fields=["@timestamp"],
            )
            hours = _hours_from_events(result.get("events", []))
            # Count the events actually returned — the client runs searches with
            # track_total_hits disabled, so result["total"] is an unreliable
            # lower bound (often 0) and must not be used for the health gate.
            out.append(FeatureResult(
                feature="active_hours",
                value={"counts": dict(hours)},
                event_count=sum(hours.values()),
            ))
        except Exception as exc:
            log.warning("wazuh baseline: endpoint %s active_hours failed: %s", eid, exc)

        # common_users
        try:
            result = self._client.profile_field(
                "data.srcuser",
                query={"term": {"agent.name": eid}},
                time_range=tr,
                top_n=20,
            )
            out.append(FeatureResult(
                feature="common_users",
                value={"top_users": [
                    {"user": v["value"], "count": v["count"]}
                    for v in result.get("top_values", [])
                    if str(v["value"]).strip() not in _SKIP_USERS
                ]},
                event_count=result.get("matched_docs", 0),
            ))
        except Exception as exc:
            log.warning("wazuh baseline: endpoint %s common_users failed: %s", eid, exc)

        # event_volume
        try:
            aggs = {"by_day": {"date_histogram": {"field": "@timestamp", "calendar_interval": "day"}}}
            raw = self._client.aggregate(aggs, query={"term": {"agent.name": eid}}, time_range=tr)
            buckets = raw.get("by_day", {}).get("buckets", [])
            out.append(FeatureResult(
                feature="event_volume",
                value=_daily_stats(buckets),
                event_count=sum(b["doc_count"] for b in buckets),
            ))
        except Exception as exc:
            log.warning("wazuh baseline: endpoint %s event_volume failed: %s", eid, exc)

        return out


register_adapter(
    "wazuh",
    WazuhBaselineAdapter,
    subject_id_hint=(
        "A Wazuh username (the data.srcuser value) or an endpoint agent name "
        "(the agent.name value), exactly as it appears in your alerts."
    ),
)
