from __future__ import annotations

import os
import sys
import unittest

import httpx

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, "aci-mcp-servers", "aci-wazuh"))

from aci_wazuh.client import WazuhClient


class _FakeOpenSearchClient:
    """Returns a fixed aggregation response and records posted bodies."""

    def __init__(self, aggregations, total=0) -> None:
        self.posts: list[tuple[str, dict]] = []
        self._aggs = aggregations
        self._total = total

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def post(self, path: str, json: dict) -> httpx.Response:
        self.posts.append((path, json))
        return httpx.Response(
            200,
            json={"hits": {"total": {"value": self._total}}, "aggregations": self._aggs},
            request=httpx.Request("POST", f"https://wazuh.local{path}"),
        )


def _client(fake: _FakeOpenSearchClient) -> WazuhClient:
    c = WazuhClient.__new__(WazuhClient)
    c._default_index = "wazuh-alerts-*"
    c._client = lambda: fake  # type: ignore[method-assign]
    return c


def _agg(body: dict) -> dict:
    return body["aggs"]


class TestProfileFieldDefault(unittest.TestCase):
    def test_default_uses_terms_and_returns_top_values(self):
        fake = _FakeOpenSearchClient(
            {"top": {"buckets": [{"key": "31101", "doc_count": 940239},
                                 {"key": "31151", "doc_count": 71334}],
                     "sum_other_doc_count": 12}},
            total=1017364,
        )
        result = _client(fake).profile_field("rule.id", top_n=20)

        agg = _agg(fake.posts[0][1])
        self.assertIn("terms", agg["top"])
        self.assertEqual(agg["top"]["terms"], {"field": "rule.id", "size": 20})
        self.assertEqual(result["matched_docs"], 1017364)
        self.assertEqual(result["top_values"][0], {"value": "31101", "count": 940239})
        self.assertEqual(result["other_count"], 12)
        self.assertNotIn("rare_values", result)


class TestProfileFieldRare(unittest.TestCase):
    def test_rare_uses_rare_terms_with_default_cap(self):
        # The needles a top-N view buries: level-0 webshell rule, 2-record service-stop.
        fake = _FakeOpenSearchClient(
            {"rare": {"buckets": [{"key": "80700", "doc_count": 2},
                                  {"key": "31108", "doc_count": 4},
                                  {"key": "5402", "doc_count": 9}]}},
            total=1017364,
        )
        result = _client(fake).profile_field("rule.id", rare=True)

        agg = _agg(fake.posts[0][1])
        self.assertIn("rare_terms", agg["rare"])
        self.assertEqual(agg["rare"]["rare_terms"]["field"], "rule.id")
        self.assertEqual(agg["rare"]["rare_terms"]["max_doc_count"], 10)  # default
        self.assertEqual(result["max_doc_count"], 10)
        self.assertEqual([b["value"] for b in result["rare_values"]], ["80700", "31108", "5402"])
        self.assertNotIn("top_values", result)

    def test_max_doc_count_is_clamped_to_supported_range(self):
        fake = _FakeOpenSearchClient({"rare": {"buckets": []}})
        _client(fake).profile_field("rule.id", rare=True, max_doc_count=500)
        self.assertEqual(_agg(fake.posts[0][1])["rare"]["rare_terms"]["max_doc_count"], 100)

        fake2 = _FakeOpenSearchClient({"rare": {"buckets": []}})
        _client(fake2).profile_field("rule.id", rare=True, max_doc_count=0)
        self.assertEqual(_agg(fake2.posts[0][1])["rare"]["rare_terms"]["max_doc_count"], 1)

    def test_rare_results_sliced_to_top_n(self):
        buckets = [{"key": f"r{i}", "doc_count": 1} for i in range(40)]
        fake = _FakeOpenSearchClient({"rare": {"buckets": buckets}})
        result = _client(fake).profile_field("rule.id", rare=True, top_n=5)
        self.assertEqual(len(result["rare_values"]), 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
