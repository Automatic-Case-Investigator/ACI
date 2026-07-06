"""Flood selectivity map + minority-event sample on WazuhClient.search().

When a search is flooded, the tool runs a per-field terms aggregation, ranks which axis
the events actually vary along (a dominant value with a minority = the discriminator),
and fetches a small sample of the deviating events — so the agent reaches the residue
even if it ignores the note. See project_siem_analyst_loop memory.
"""
from __future__ import annotations

import os
import sys
import json
import types
import unittest
from importlib.util import module_from_spec, spec_from_file_location

import httpx

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, project_root)

from aci_wazuh.client import WazuhClient as W


def _load_build_observation():
    agent_pkg = types.ModuleType("agent")
    agent_pkg.__path__ = [os.path.join(project_root, "agent")]
    runtime_pkg = types.ModuleType("agent.runtime")
    runtime_pkg.__path__ = [os.path.join(project_root, "agent", "runtime")]
    graph_pkg = types.ModuleType("agent.runtime.graph")
    graph_pkg.__path__ = [os.path.join(project_root, "agent", "runtime", "graph")]
    analysis_pkg = types.ModuleType("agent.runtime.analysis")
    analysis_pkg.__path__ = [os.path.join(project_root, "agent", "runtime", "analysis")]
    query_memo = types.ModuleType("agent.runtime.analysis.query_memo")
    query_memo.BROAD_HIT_THRESHOLD = 10000

    def _extract_hit_count(raw):
        if isinstance(raw, dict):
            return raw.get("total")
        try:
            return json.loads(raw).get("total")
        except Exception:
            return None

    query_memo.extract_hit_count = _extract_hit_count
    sys.modules.setdefault("agent", agent_pkg)
    sys.modules.setdefault("agent.runtime", runtime_pkg)
    sys.modules.setdefault("agent.runtime.graph", graph_pkg)
    sys.modules.setdefault("agent.runtime.analysis", analysis_pkg)
    sys.modules.setdefault("agent.runtime.analysis.query_memo", query_memo)

    path = os.path.join(project_root, "agent", "runtime", "graph", "observation.py")
    spec = spec_from_file_location("agent.runtime.graph.observation", path)
    module = module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module.build_observation


class _Fake:
    """Fake OpenSearch: main search returns per-field agg buckets; the minority-sample
    follow-up (a query with no `aggs`) returns the sample hits."""

    def __init__(self, total, relation, *, sel_fields=None, sel_other=None,
                 rule_groups=None, sample=None):
        self._total = total
        self._rel = relation
        self._sel = sel_fields or {}          # {field: [{"key":..,"doc_count":..}, ...]}
        self._other = sel_other or {}         # {field: sum_other_doc_count}
        self._rg = rule_groups or [{"key": "web", "doc_count": total}]
        self._sample = sample if sample is not None else [{"_id": "ws1"}, {"_id": "ws2"}]
        self.sample_requests = []

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def post(self, path, json):
        req = httpx.Request("POST", f"https://wazuh.local{path}")
        aggs = json.get("aggs") or {}
        if "clauses" in aggs:  # clause_diagnostics side-request
            return httpx.Response(200, json={
                "hits": {"total": {"value": 0}}, "aggregations": {"clauses": {"buckets": {}}}},
                request=req)
        if "by_value" in aggs:  # residue-sample follow-up (must_not dominant, terms+top_hits)
            self.sample_requests.append(json)
            return httpx.Response(200, json={
                "hits": {"total": {"value": 0}},
                "aggregations": {"by_value": {"buckets": [
                    {"key": "200", "ex": {"hits": {"hits": self._sample}}}]}}},
                request=req)
        # main search: rule_groups + per-field selectivity aggregations
        aggregations = {"rule_groups": {"buckets": self._rg}}
        for field, buckets in self._sel.items():
            aggregations[W._agg_key(field)] = {
                "buckets": buckets, "sum_other_doc_count": self._other.get(field, 0)}
        return httpx.Response(200, json={
            "hits": {"total": {"value": self._total, "relation": self._rel}, "hits": [{"_id": "h1"}]},
            "aggregations": aggregations,
        }, request=req)


def _client(fake) -> W:
    c = W.__new__(W)
    c._default_index = "wazuh-alerts-*"
    c._get_client = lambda: fake
    c._client = lambda: fake
    return c


_TR = {"from": "2022-01-18T12:00:00Z", "to": "2022-01-18T12:45:00Z"}
_Q = {"bool": {"must": [{"term": {"agent.name": "wazuh-client"}},
                        {"wildcard": {"rule.groups": {"value": "web"}}}]}}


class SelectivityMapTest(unittest.TestCase):
    def test_discriminator_surfaced_and_residue_sample_is_returned(self):
        # data.id: dominant 404, then a LARGE minority 403 (more scan) and a RARE 200 (the
        # webshell success). The sample should include the rare residue, not only the
        # largest minority.
        fake = _Fake(10000, "gte", sel_fields={
            "data.id": [{"key": "404", "doc_count": 9700},
                        {"key": "403", "doc_count": 250},
                        {"key": "200", "doc_count": 50}],
        }, sample=[{"_id": "ws1"}, {"_id": "ws2"}, {"_id": "ws3"}])
        result = _client(fake).search(query=_Q, time_range=_TR)
        disc = next(e for e in result["selectivity_map"] if e["role"] == "discriminator")
        self.assertEqual(disc["field"], "data.id")
        self.assertEqual(disc["dominant"], "404")
        # the residue sample is delivered (not just described)
        self.assertEqual(len(result["minority_sample"]), 3)
        # the note highlights the RARE minority (200), not the largest (403)
        self.assertIn("200", result["note"])
        self.assertIn("data.id=200", result["note"])
        # the follow-up excluded the dominant (residue sample), not filtered to one minority
        self.assertTrue(fake.sample_requests)
        req = fake.sample_requests[-1]["query"]["bool"]
        self.assertEqual(req["must_not"][0]["term"]["data.id"], "404")

    def test_high_cardinality_field_not_chosen_as_discriminator(self):
        # dstip spread across many values, none dominant -> high_cardinality, no discriminator.
        fake = _Fake(10000, "gte", sel_fields={
            "data.dstip": [{"key": f"10.0.0.{i}", "doc_count": 100} for i in range(8)],
        })
        result = _client(fake).search(query=_Q, time_range=_TR)
        roles = {e["field"]: e["role"] for e in result["selectivity_map"]}
        self.assertEqual(roles["data.dstip"], "high_cardinality")
        self.assertNotIn("minority_sample", result)

    def test_homogeneous_field_is_flood_signature(self):
        # rule.id all 31151 (no minority) -> flood_signature (a must_not target), not a discriminator.
        fake = _Fake(10000, "gte", sel_fields={
            "rule.id": [{"key": "31151", "doc_count": 10000}],
        })
        result = _client(fake).search(query=_Q, time_range=_TR)
        roles = {e["field"]: e["role"] for e in result["selectivity_map"]}
        self.assertEqual(roles["rule.id"], "flood_signature")
        self.assertNotIn("minority_sample", result)

    def test_discriminator_ranks_above_signature_and_noise(self):
        fake = _Fake(10000, "gte", sel_fields={
            "rule.id": [{"key": "31151", "doc_count": 10000}],                       # signature
            "data.dstip": [{"key": f"10.0.0.{i}", "doc_count": 100} for i in range(8)],  # noise
            "data.id": [{"key": "404", "doc_count": 9800}, {"key": "200", "doc_count": 200}],  # disc
        })
        result = _client(fake).search(query=_Q, time_range=_TR)
        # discriminator is first in the ranked map
        self.assertEqual(result["selectivity_map"][0]["field"], "data.id")
        self.assertEqual(result["selectivity_map"][0]["role"], "discriminator")

    def test_non_flooded_result_gets_no_map(self):
        fake = _Fake(5, "eq", sel_fields={
            "data.id": [{"key": "404", "doc_count": 4}, {"key": "200", "doc_count": 1}],
        })
        result = _client(fake).search(query=_Q, time_range=_TR)
        self.assertNotIn("selectivity_map", result)
        self.assertNotIn("minority_sample", result)

    def test_share_denominator_is_field_total_not_capped_hits(self):
        # On a TRUNCATED result the hits total is a capped 10000, but the agg counts the
        # true (millions) total. dominant_share must use the field's own bucket sum +
        # sum_other_doc_count, so it never exceeds 100% (regression for the 302%/12456% bug).
        fake = _Fake(10000, "gte", sel_fields={
            "data.id": [{"key": "403", "doc_count": 30000}, {"key": "200", "doc_count": 500}],
        }, sel_other={"data.id": 200})  # true field total = 30000+500+200 = 30700
        result = _client(fake).search(query=_Q, time_range=_TR)
        disc = next(e for e in result["selectivity_map"] if e["field"] == "data.id")
        self.assertLessEqual(disc["dominant_share"], 1.0)
        self.assertAlmostEqual(disc["dominant_share"], 30000 / 30700, places=2)
        self.assertEqual(disc["role"], "discriminator")
        self.assertEqual(disc["minorities"][0]["value"], "200")

    def test_absent_fields_are_skipped(self):
        fake = _Fake(10000, "gte", sel_fields={
            "data.id": [{"key": "404", "doc_count": 9900}, {"key": "200", "doc_count": 100}],
            # other candidate fields return no buckets -> not in the map
        })
        result = _client(fake).search(query=_Q, time_range=_TR)
        fields = {e["field"] for e in result["selectivity_map"]}
        self.assertEqual(fields, {"data.id"})


class BuildObservationDiscriminatorTest(unittest.TestCase):
    def test_selectivity_map_surfaces_as_observation_discriminator(self):
        build_observation = _load_build_observation()
        result = {
            "total": 10000, "truncated": True, "total_relation": "gte",
            "selectivity_map": [{
                "field": "data.id", "dominant": "404", "dominant_share": 0.99,
                "minorities": [{"value": "403", "count": 30}, {"value": "200", "count": 5}],
                "role": "discriminator"}],
            "minority_sample": [{"_id": "ws1"}],
        }
        obs = build_observation([{"name": "search", "raw": result}], objective="scan tail")
        d = obs["discriminator"]
        self.assertEqual(d["field"], "data.id")
        self.assertEqual(d["minority"], "200")          # kept for backward compatibility
        self.assertEqual(d["minority_values"], ["403", "200"])
        self.assertIn("ws1", d["sample_event_ids"])
        self.assertTrue(any("inspect and decode" in m for m in obs["recommended_moves"]))

    def test_no_discriminator_when_no_selectivity_map(self):
        build_observation = _load_build_observation()
        obs = build_observation([{"name": "search", "raw": {"total": 3, "hits": {"total": {"value": 3}}}}],
                                objective="x")
        self.assertIsNone(obs["discriminator"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
