"""Unit tests for SIEM query-shape robustness (Fix 2 + the should/must footgun guard).

Covers the deterministic guards added to the Wazuh client:
  - _strip_temporal_tokens: ISO timestamps placed in keyword terms are removed
    (they belong in time_range and otherwise force the OR-fallback to match the index).
  - _query_error_hint: a malformed structured query gets one actionable line instead
    of a raw Elasticsearch stack trace.
  - _has_noop_should / search(): a `bool` clause with `should` but no `must`/
    `minimum_should_match` is scoring-only under ES/OS defaults — the query silently
    matches everything else in scope instead of being narrowed by those terms. Confirmed
    live: a query intended to match an IP/content discriminator via `should` alongside a
    `filter` time range returned 10,000+ truncated hits because `should` provided no
    actual filtering.
"""
from __future__ import annotations

import json
import os
import sys
import unittest

import httpx

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, "aci-mcp-servers", "aci-wazuh"))

from aci_wazuh.client import WazuhClient as W


class StripTemporalTokensTest(unittest.TestCase):
    def test_strips_iso_datetime_terms_keeps_real_terms(self):
        q, dropped = W._strip_temporal_tokens(
            "wazuh-client 2022-01-18T12:04:10Z 2022-01-18T12:34:10Z"
        )
        self.assertEqual(q, "wazuh-client")
        self.assertEqual(len(dropped), 2)

    def test_keeps_query_without_timestamps(self):
        q, dropped = W._strip_temporal_tokens("172.17.130.196 authentication success")
        self.assertEqual(q, "172.17.130.196 authentication success")
        self.assertEqual(dropped, [])

    def test_all_timestamps_yields_empty(self):
        q, dropped = W._strip_temporal_tokens("2022-01-18 2022-01-19T00:00:00+00:00")
        self.assertEqual(q, "")
        self.assertEqual(len(dropped), 2)

    def test_ip_is_not_mistaken_for_a_date(self):
        q, dropped = W._strip_temporal_tokens("10.35.35.206")
        self.assertEqual(q, "10.35.35.206")
        self.assertEqual(dropped, [])


class QueryErrorHintTest(unittest.TestCase):
    def test_parsing_exception_gets_hint(self):
        err = {"error": {"root_cause": [
            {"type": "parsing_exception", "reason": "[should] query malformed"}]}}
        hint = W._query_error_hint(err)
        self.assertIsNotNone(hint)
        self.assertIn("bool", hint)

    def test_query_malformed_string_gets_hint(self):
        self.assertIsNotNone(W._query_error_hint("[should] query malformed, expected END_OBJECT"))

    def test_unrelated_error_gets_no_hint(self):
        self.assertIsNone(W._query_error_hint({"error": {"type": "index_not_found_exception"}}))


class NoopShouldDetectionTest(unittest.TestCase):
    def test_filter_plus_should_no_must_is_flagged(self):
        # The exact shape observed live: time-range filter + should discriminators,
        # no must, no minimum_should_match — should is scoring-only here.
        dsl = {"bool": {
            "filter": [{"range": {"@timestamp": {"gte": "x", "lte": "y"}}}],
            "should": [{"match": {"full_log": "172.17.130.196"}}],
        }}
        self.assertTrue(W._has_noop_should(dsl))

    def test_should_with_must_is_not_flagged(self):
        dsl = {"bool": {
            "must": [{"term": {"data.srcip": "1.2.3.4"}}],
            "should": [{"term": {"rule.groups": "attack"}}],
        }}
        self.assertFalse(W._has_noop_should(dsl))

    def test_should_with_minimum_should_match_is_not_flagged(self):
        dsl = {"bool": {
            "filter": [{"range": {"@timestamp": {}}}],
            "should": [{"term": {"a": "b"}}],
            "minimum_should_match": 1,
        }}
        self.assertFalse(W._has_noop_should(dsl))

    def test_nested_noop_should_under_outer_must_is_flagged(self):
        # search() wraps the caller's dsl in an outer {"bool": {"must": dsl, "filter": [...]}}.
        # The caller's own noop-should shape, now nested under "must", must still be caught.
        dsl = {"bool": {
            "must": {"bool": {
                "filter": [{"range": {"@timestamp": {}}}],
                "should": [{"match": {"full_log": "x"}}],
            }},
            "filter": [{"range": {"@timestamp": {}}}],
        }}
        self.assertTrue(W._has_noop_should(dsl))

    def test_plain_term_query_no_bool_is_not_flagged(self):
        self.assertFalse(W._has_noop_should({"term": {"data.srcip": "1.2.3.4"}}))

    def test_no_should_at_all_is_not_flagged(self):
        dsl = {"bool": {"filter": [{"range": {"@timestamp": {}}}]}}
        self.assertFalse(W._has_noop_should(dsl))


class SearchNoopShouldNoteTest(unittest.TestCase):
    """End-to-end: search() attaches the warning note when the live failure shape recurs."""

    class _FakeClient:
        def __init__(self, total=10000, relation="gte"):
            self._total, self._relation = total, relation

        def post(self, path, json):
            return httpx.Response(
                200,
                json={"hits": {"total": {"value": self._total, "relation": self._relation},
                               "hits": []}},
                request=httpx.Request("POST", f"https://wazuh.local{path}"),
            )

    def _client(self, fake):
        client = W.__new__(W)
        client._default_index = "wazuh-alerts-*"
        client._get_client = lambda: fake
        return client

    def test_noop_should_query_gets_warning_note(self):
        client = self._client(self._FakeClient())
        result = client.search(
            query={"bool": {"should": [{"match": {"full_log": "172.17.130.196"}}]}},
            time_range={"from": "2022-01-17T00:00:00Z", "to": "2022-01-19T00:00:00Z"},
        )
        self.assertIn("note", result)
        self.assertIn("SCORING-ONLY", result["note"])

    def test_well_formed_must_query_gets_no_note(self):
        client = self._client(self._FakeClient(total=3, relation="eq"))
        result = client.search(
            query={"bool": {"must": [{"term": {"data.srcip": "1.2.3.4"}}]}},
            time_range={"from": "2022-01-17T00:00:00Z", "to": "2022-01-19T00:00:00Z"},
        )
        self.assertNotIn("note", result)


class SearchMaxResultsTest(unittest.TestCase):
    """search() honors the caller's max_results as the OpenSearch body `size` (regression:
    the search MCP schema omitted max_results and the server handler dropped it, pinning
    every search to the default page size)."""

    class _CapturingClient:
        def __init__(self):
            self.bodies = []

        def post(self, path, json):
            if not (json.get("aggs") or {}).get("clauses"):  # ignore the diagnostics side-call
                self.bodies.append(json)
            return httpx.Response(
                200,
                json={"hits": {"total": {"value": 3, "relation": "eq"}, "hits": []}},
                request=httpx.Request("POST", f"https://wazuh.local{path}"),
            )

    def _client(self, fake):
        client = W.__new__(W)
        client._default_index = "wazuh-alerts-*"
        client._get_client = lambda: fake
        client._client = lambda: fake
        return client

    def _main_size(self, fake):
        return next(b["size"] for b in fake.bodies if "size" in b and b.get("size") != 0)

    def test_caller_max_results_becomes_body_size(self):
        fake = self._CapturingClient()
        self._client(fake).search(
            query={"bool": {"must": [{"term": {"data.srcip": "1.2.3.4"}}]}},
            time_range={"from": "2022-01-17T00:00:00Z", "to": "2022-01-19T00:00:00Z"},
            max_results=50,
        )
        self.assertEqual(self._main_size(fake), 50)

    def test_default_size_is_twenty(self):
        fake = self._CapturingClient()
        self._client(fake).search(
            query={"bool": {"must": [{"term": {"data.srcip": "1.2.3.4"}}]}},
            time_range={"from": "2022-01-17T00:00:00Z", "to": "2022-01-19T00:00:00Z"},
        )
        self.assertEqual(self._main_size(fake), 20)

    def test_size_capped_at_hundred(self):
        fake = self._CapturingClient()
        self._client(fake).search(
            query={"bool": {"must": [{"term": {"data.srcip": "1.2.3.4"}}]}},
            time_range={"from": "2022-01-17T00:00:00Z", "to": "2022-01-19T00:00:00Z"},
            max_results=5000,
        )
        self.assertEqual(self._main_size(fake), 100)


class ClauseLabelTest(unittest.TestCase):
    def test_labels_common_clause_shapes(self):
        self.assertEqual(W._clause_label({"term": {"data.srcip": "1.2.3.4"}}), "data.srcip=1.2.3.4")
        self.assertEqual(W._clause_label({"match": {"full_log": {"query": "x"}}}), "full_log=x")
        self.assertEqual(
            W._clause_label({"terms": {"rule.groups": ["a", "b", "c", "d", "e"]}}),
            "rule.groups in [a,b,c,d…]",
        )
        self.assertEqual(W._clause_label({"exists": {"field": "data.dstip"}}), "exists data.dstip")


class ExtractBoolClausesTest(unittest.TestCase):
    def test_splits_must_and_should_and_drops_timestamp(self):
        dsl = {"bool": {
            "must": [{"term": {"data.srcip": "1.2.3.4"}},
                     {"range": {"@timestamp": {"gte": "a", "lte": "b"}}}],
            "should": [{"term": {"rule.groups": "attack"}}],
        }}
        musts, shoulds = W._extract_bool_clauses(dsl)
        self.assertEqual(musts, [{"term": {"data.srcip": "1.2.3.4"}}])  # @timestamp dropped
        self.assertEqual(shoulds, [{"term": {"rule.groups": "attack"}}])

    def test_bare_leaf_is_one_must(self):
        musts, shoulds = W._extract_bool_clauses({"term": {"data.srcip": "1.2.3.4"}})
        self.assertEqual(len(musts), 1)
        self.assertEqual(shoulds, [])

    def test_match_all_yields_no_clauses(self):
        self.assertEqual(W._extract_bool_clauses({"match_all": {}}), ([], []))


class ClauseDiagnosticsTest(unittest.TestCase):
    """search() attaches per-clause selectivity (docs each clause matches in the window)."""

    class _DualFake:
        def __init__(self, main_total, window_docs, clause_counts):
            self._main_total = main_total
            self._window = window_docs
            self._counts = clause_counts  # {"m0": 1200000, "s0": 12, ...}

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def post(self, path, json):
            req = httpx.Request("POST", f"https://wazuh.local{path}")
            if "clauses" in (json.get("aggs") or {}):
                buckets = {k: {"doc_count": v} for k, v in self._counts.items()}
                return httpx.Response(200, json={
                    "hits": {"total": {"value": self._window}},
                    "aggregations": {"clauses": {"buckets": buckets}},
                }, request=req)
            return httpx.Response(200, json={
                "hits": {"total": {"value": self._main_total, "relation": "eq"},
                         "hits": [{"_id": "e1"}]},
            }, request=req)

    def _client(self, fake):
        client = W.__new__(W)
        client._default_index = "wazuh-alerts-*"
        client._get_client = lambda: fake
        client._client = lambda: fake
        return client

    def test_per_clause_counts_attached(self):
        fake = self._DualFake(main_total=3, window_docs=1_300_000,
                              clause_counts={"m0": 1_200_000, "s0": 12})
        client = self._client(fake)
        result = client.search(
            query={"bool": {
                "must": [{"term": {"data.srcip": "172.17.130.196"}}],
                "should": [{"terms": {"rule.groups": ["authentication_success"]}}],
            }},
            time_range={"from": "2022-01-18T00:00:00Z", "to": "2022-01-19T00:00:00Z"},
        )
        diag = result["clause_diagnostics"]
        self.assertEqual(diag["window_docs"], 1_300_000)
        self.assertEqual(diag["clauses"], [
            {"clause": "data.srcip=172.17.130.196", "type": "must", "matches": 1_200_000},
            {"clause": "rule.groups in [authentication_success]", "type": "should", "matches": 12},
        ])

    def test_no_clauses_no_diagnostics(self):
        fake = self._DualFake(main_total=5, window_docs=0, clause_counts={})
        result = self._client(fake).search(
            query={"match_all": {}},
            time_range={"from": "2022-01-18T00:00:00Z", "to": "2022-01-19T00:00:00Z"})
        self.assertNotIn("clause_diagnostics", result)


class FloodBreakdownTest(unittest.TestCase):
    """An over-broad search surfaces its rule.groups composition and, for an entity-only
    query, a prescriptive 'scope by rule.groups' note."""

    class _Fake:
        def __init__(self, total, relation, rg_buckets):
            self._total, self._rel, self._rg = total, relation, rg_buckets

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def post(self, path, json):
            req = httpx.Request("POST", f"https://wazuh.local{path}")
            if "clauses" in (json.get("aggs") or {}):  # clause_diagnostics side-request
                return httpx.Response(200, json={
                    "hits": {"total": {"value": 0}},
                    "aggregations": {"clauses": {"buckets": {}}}}, request=req)
            return httpx.Response(200, json={
                "hits": {"total": {"value": self._total, "relation": self._rel},
                         "hits": [{"_id": "e1"}]},
                "aggregations": {"rule_groups": {"buckets": self._rg}},
            }, request=req)

    def _client(self, fake):
        c = W.__new__(W)
        c._default_index = "wazuh-alerts-*"
        c._get_client = lambda: fake
        c._client = lambda: fake
        return c

    def test_entity_only_flood_gets_breakdown_and_class_scope_note(self):
        rg = [{"key": "ids", "doc_count": 745000}, {"key": "web", "doc_count": 5200}]
        result = self._client(self._Fake(10000, "gte", rg)).search(
            query={"bool": {"must": [{"term": {"data.srcip": "10.35.35.206"}}]}},
            time_range={"from": "2022-01-18T00:00:00Z", "to": "2022-01-19T00:00:00Z"})
        self.assertEqual(result["rule_groups_breakdown"][0], {"group": "ids", "count": 745000})
        self.assertIn("rule.groups", result["note"])
        self.assertIn("ids", result["note"])
        self.assertIn("union", result["note"].lower())  # the entity-union guidance

    def test_class_scoped_flood_gets_generic_note_not_entity_note(self):
        rg = [{"key": "web", "doc_count": 600}]
        result = self._client(self._Fake(600, "eq", rg)).search(
            query={"bool": {"must": [{"term": {"agent.name": "h"}},
                                     {"term": {"rule.groups": "web"}}]}},
            time_range={"from": "2022-01-18T00:00:00Z", "to": "2022-01-19T00:00:00Z"})
        self.assertIn("rule_groups_breakdown", result)
        self.assertNotIn("union", result["note"].lower())  # already class-scoped

    def test_small_result_gets_no_breakdown(self):
        rg = [{"key": "web", "doc_count": 5}]
        result = self._client(self._Fake(5, "eq", rg)).search(
            query={"bool": {"must": [{"term": {"data.srcip": "1.2.3.4"}}]}},
            time_range={"from": "2022-01-18T00:00:00Z", "to": "2022-01-19T00:00:00Z"})
        self.assertNotIn("rule_groups_breakdown", result)
        self.assertNotIn("note", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
