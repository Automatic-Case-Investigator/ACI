from __future__ import annotations

import os
import sys
import unittest

import httpx

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, "aci-mcp-servers", "aci-wazuh"))

from aci_wazuh.client import WazuhClient

_WINDOW = {"from": "2026-06-25T00:00:00Z", "to": "2026-06-25T01:00:00Z"}


def _operator(body: dict) -> str:
    """Pull default_operator out of a posted search body (range-filtered or not)."""
    bq = body["query"]["bool"]
    should = bq["must"][0]["bool"]["should"] if "must" in bq else bq["should"]
    return should[0]["simple_query_string"]["default_operator"]


class _FakeOpenSearchClient:
    """Returns a configurable (total, events) per AND/OR pass, keyed on the operator."""

    def __init__(self, and_hits=(0, []), or_hits=(0, [])) -> None:
        self.posts: list[tuple[str, dict]] = []
        self._and = and_hits
        self._or = or_hits

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def post(self, path: str, json: dict) -> httpx.Response:
        self.posts.append((path, json))
        total, events = self._and if _operator(json) == "and" else self._or
        return httpx.Response(
            200,
            json={"hits": {"total": {"value": total}, "hits": events}},
            request=httpx.Request("POST", f"https://wazuh.local{path}"),
        )


class TestWazuhSearchKeyword(unittest.TestCase):
    def _client(self, fake: _FakeOpenSearchClient) -> WazuhClient:
        client = WazuhClient.__new__(WazuhClient)
        client._default_index = "wazuh-alerts-*"
        client._client = lambda: fake  # type: ignore[method-assign]
        return client

    def test_terms_use_and_semantics_by_default(self):
        # All-term match returns events → no fallback pass is issued.
        fake = _FakeOpenSearchClient(and_hits=(3, [{"_id": "a"}]))
        client = self._client(fake)

        client.search_keyword("powershell mimikatz svchost", time_range=_WINDOW, max_results=250)

        self.assertEqual(len(fake.posts), 1)
        self.assertEqual(fake.posts[0][0], "/wazuh-alerts-*/_search")
        self.assertEqual(fake.posts[0][1]["size"], 100)
        self.assertTrue(fake.posts[0][1]["track_total_hits"])
        self.assertEqual(_operator(fake.posts[0][1]), "and")
        # Range filter is applied.
        self.assertIn("filter", fake.posts[0][1]["query"]["bool"])

    def test_query_with_paths_preserved_and_uses_and(self):
        fake = _FakeOpenSearchClient(and_hits=(2, [{"_id": "b"}]))
        client = self._client(fake)

        client.search_keyword(
            "kali nano crontab.Tgi9hP /tmp/crontab.Tgi9hP/crontab 10.0.2.15",
            time_range={"from": "2025-04-20T03:44:10Z", "to": "2025-04-20T04:04:10Z"},
        )

        clause = fake.posts[0][1]["query"]["bool"]["must"][0]["bool"]["should"][0]
        self.assertEqual(
            clause["simple_query_string"]["query"],
            "kali nano crontab.Tgi9hP /tmp/crontab.Tgi9hP/crontab 10.0.2.15",
        )
        self.assertIn("full_log", clause["simple_query_string"]["fields"])
        self.assertIn("data.audit.execve.a1", clause["simple_query_string"]["fields"])
        self.assertEqual(clause["simple_query_string"]["default_operator"], "and")

    def test_falls_back_to_or_when_no_all_term_match(self):
        # No document matches all terms → broaden to ANY-term and flag it.
        fake = _FakeOpenSearchClient(and_hits=(0, []), or_hits=(5, [{"_id": "c"}]))
        client = self._client(fake)

        result = client.search_keyword("kali ssh login su sudo pts", time_range=_WINDOW)

        self.assertEqual(len(fake.posts), 2)
        self.assertEqual(_operator(fake.posts[0][1]), "and")
        self.assertEqual(_operator(fake.posts[1][1]), "or")
        self.assertTrue(result.get("broadened"))
        self.assertIn("note", result)
        self.assertEqual(result["total"], 5)

    def test_no_fallback_flag_when_or_also_empty(self):
        fake = _FakeOpenSearchClient(and_hits=(0, []), or_hits=(0, []))
        client = self._client(fake)

        result = client.search_keyword("nonexistent terms", time_range=_WINDOW)

        self.assertEqual(len(fake.posts), 2)
        self.assertNotIn("broadened", result)
        self.assertEqual(result["events"], [])

    def test_large_all_term_match_flagged_too_broad(self):
        fake = _FakeOpenSearchClient(and_hits=(8563, [{"_id": "d"}]))
        client = self._client(fake)

        result = client.search_keyword("kali", time_range=_WINDOW)

        self.assertEqual(len(fake.posts), 1)  # had events → no fallback
        self.assertTrue(result.get("too_broad"))
        self.assertIn("note", result)

    def test_focused_all_term_match_has_no_flags(self):
        fake = _FakeOpenSearchClient(and_hits=(12, [{"_id": "e"}]))
        client = self._client(fake)

        result = client.search_keyword("kali nano crontab", time_range=_WINDOW)

        self.assertEqual(len(fake.posts), 1)
        self.assertNotIn("too_broad", result)
        self.assertNotIn("broadened", result)
        self.assertEqual(result["total"], 12)

    def test_blank_query_returns_no_results_without_calling_opensearch(self):
        fake = _FakeOpenSearchClient()
        client = self._client(fake)

        result = client.search_keyword(" \t\n ")

        self.assertEqual(result, {"total": 0, "events": []})
        self.assertEqual(fake.posts, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
