"""Zero-hit field-existence feedback on WazuhClient.search()/profile_field().

A query on a field NAME that is not in the index mapping returns 0 hits exactly like a
genuine absence. The client compares queried leaf-fields against the cached index mapping
and, only on a zero/empty result, attaches `field_warnings` + a corrective note pointing
at the real field name (e.g. `url` → `data.url`). See project_siem_analyst_loop memory.
"""
from __future__ import annotations

import os
import sys
import unittest

import httpx

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

from aci_wazuh.client import WazuhClient as W

# Mapping the fake index exposes: data.url/data.srcip, agent.name, rule.id/rule.groups.
_MAPPING = {"wazuh-alerts-*": {"mappings": {"properties": {
    "data": {"properties": {"url": {"type": "keyword"}, "srcip": {"type": "ip"}}},
    "agent": {"properties": {"name": {"type": "keyword"}}},
    "rule": {"properties": {"id": {"type": "keyword"}, "groups": {"type": "keyword"}}},
}}}}


class _Fake:
    """Serves the _mapping GET and a search/profile POST with a caller-set hit total."""

    def __init__(self, total, *, profile_buckets=None):
        self._total = total
        self._profile_buckets = profile_buckets if profile_buckets is not None else []

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def get(self, path, **_kw):
        req = httpx.Request("GET", f"https://wazuh.local{path}")
        return httpx.Response(200, json=_MAPPING, request=req)

    def post(self, path, json):
        req = httpx.Request("POST", f"https://wazuh.local{path}")
        aggs = json.get("aggs") or {}
        if "clauses" in aggs:  # clause_diagnostics side-request
            return httpx.Response(200, json={
                "hits": {"total": {"value": 0}}, "aggregations": {"clauses": {"buckets": {}}}},
                request=req)
        if "top" in aggs or "rare" in aggs:  # profile_field
            key = "top" if "top" in aggs else "rare"
            return httpx.Response(200, json={
                "hits": {"total": {"value": self._total}},
                "aggregations": {key: {"buckets": self._profile_buckets}}},
                request=req)
        # main search
        return httpx.Response(200, json={
            "hits": {"total": {"value": self._total, "relation": "eq"}, "hits": []},
            "aggregations": {"rule_groups": {"buckets": []}},
        }, request=req)


def _client(fake) -> W:
    c = W.__new__(W)
    c._default_index = "wazuh-alerts-*"
    c._get_client = lambda: fake
    c._client = lambda: fake
    return c


_TR = {"from": "2022-01-18T12:00:00Z", "to": "2022-01-18T12:45:00Z"}


class SearchFieldWarningTest(unittest.TestCase):
    def test_zero_hit_on_absent_field_warns_with_candidate(self):
        q = {"bool": {"must": [{"wildcard": {"url": {"value": "*/wp-content/*"}}}]}}
        result = _client(_Fake(0)).search(query=q, time_range=_TR)
        self.assertEqual(result["total"], 0)
        warnings = result.get("field_warnings")
        self.assertTrue(warnings)
        w = next(x for x in warnings if x["queried"] == "url")
        self.assertIn("data.url", w["candidates"])
        self.assertIn("data.url", result["note"])

    def test_zero_hit_on_present_field_gives_no_warning(self):
        q = {"bool": {"must": [{"term": {"data.url": "/x.php"}}]}}
        result = _client(_Fake(0)).search(query=q, time_range=_TR)
        self.assertEqual(result["total"], 0)
        self.assertNotIn("field_warnings", result)

    def test_non_zero_result_never_warns(self):
        q = {"bool": {"must": [{"wildcard": {"url": {"value": "*/x/*"}}}]}}
        result = _client(_Fake(7)).search(query=q, time_range=_TR)
        self.assertEqual(result["total"], 7)
        self.assertNotIn("field_warnings", result)


class ProfileFieldWarningTest(unittest.TestCase):
    def test_empty_profile_on_absent_field_warns(self):
        # Aggregating an unmapped field returns 0 buckets and matched_docs 0.
        result = _client(_Fake(0)).profile_field(field="url", time_range=_TR)
        self.assertEqual(result["matched_docs"], 0)
        w = next(x for x in result.get("field_warnings", []) if x["queried"] == "url")
        self.assertIn("data.url", w["candidates"])

    def test_present_field_with_matches_no_warning(self):
        result = _client(_Fake(50, profile_buckets=[{"key": "web", "doc_count": 50}])).profile_field(
            field="rule.groups", time_range=_TR)
        self.assertEqual(result["matched_docs"], 50)
        self.assertNotIn("field_warnings", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
