from __future__ import annotations

import os
import sys
import unittest

import httpx

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, "aci-mcp-servers", "aci-wazuh"))

from aci_wazuh.client import WazuhClient

_START = "2026-06-25T00:00:00Z"
_END = "2026-06-25T04:00:00Z"


class _FakeOpenSearchClient:
    """Returns a fixed date_histogram aggregation and records posted bodies."""

    def __init__(self, buckets, total=0) -> None:
        self.posts: list[tuple[str, dict]] = []
        self._buckets = buckets
        self._total = total

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def post(self, path: str, json: dict) -> httpx.Response:
        self.posts.append((path, json))
        return httpx.Response(
            200,
            json={
                "hits": {"total": {"value": self._total}},
                "aggregations": {"volume": {"buckets": self._buckets}},
            },
            request=httpx.Request("POST", f"https://wazuh.local{path}"),
        )


def _hist(body: dict) -> dict:
    return body["aggs"]["volume"]["date_histogram"]


class TestWazuhEventVolume(unittest.TestCase):
    def _client(self, fake: _FakeOpenSearchClient) -> WazuhClient:
        client = WazuhClient.__new__(WazuhClient)
        client._default_index = "wazuh-alerts-*"
        client._client = lambda: fake  # type: ignore[method-assign]
        return client

    def test_explicit_interval_is_honored(self):
        fake = _FakeOpenSearchClient(buckets=[])
        client = self._client(fake)

        client.get_event_volume(_START, _END, interval="15m")

        self.assertEqual(_hist(fake.posts[0][1])["fixed_interval"], "15m")

    def test_interval_computed_from_bins_when_absent(self):
        fake = _FakeOpenSearchClient(buckets=[])
        client = self._client(fake)

        # 4h window / 4 bins = 3600s buckets.
        client.get_event_volume(_START, _END, bins=4)

        self.assertEqual(_hist(fake.posts[0][1])["fixed_interval"], "3600s")

    def test_default_interval_fallback_on_unparseable_window(self):
        fake = _FakeOpenSearchClient(buckets=[])
        client = self._client(fake)

        client.get_event_volume("not-a-date", "also-bad")

        self.assertEqual(_hist(fake.posts[0][1])["fixed_interval"], "1h")

    def test_extended_bounds_track_the_window(self):
        fake = _FakeOpenSearchClient(buckets=[])
        client = self._client(fake)

        client.get_event_volume(_START, _END, interval="1h")

        bounds = _hist(fake.posts[0][1])["extended_bounds"]
        self.assertEqual(bounds, {"min": _START, "max": _END})

    def test_bucket_formatting_and_summary_stats(self):
        buckets = [
            {"key_as_string": _START, "key": 1, "doc_count": 5},
            {"key_as_string": "2026-06-25T01:00:00Z", "key": 2, "doc_count": 0},
            {"key_as_string": "2026-06-25T02:00:00Z", "key": 3, "doc_count": 12},
        ]
        fake = _FakeOpenSearchClient(buckets=buckets, total=17)
        client = self._client(fake)

        result = client.get_event_volume(_START, _END, interval="1h")

        self.assertEqual(result["total"], 17)
        self.assertEqual(result["peak_count"], 12)
        self.assertEqual(result["empty_bins"], 1)
        self.assertEqual(result["bins"][0], {"time": _START, "count": 5})

    def test_dict_query_is_scoped_in_bool_must(self):
        fake = _FakeOpenSearchClient(buckets=[])
        client = self._client(fake)

        client.get_event_volume(
            _START, _END, query={"term": {"data.srcip": "1.2.3.4"}}, interval="1h"
        )

        must = fake.posts[0][1]["query"]["bool"]["must"]
        self.assertIn({"term": {"data.srcip": "1.2.3.4"}}, must)
        # Range filter is also applied.
        self.assertTrue(any("range" in clause for clause in must))

    def test_keyword_query_uses_simple_query_string(self):
        fake = _FakeOpenSearchClient(buckets=[])
        client = self._client(fake)

        client.get_event_volume(_START, _END, query="10.0.2.15 sshd", interval="1h")

        must = fake.posts[0][1]["query"]["bool"]["must"]
        sqs = [c for c in must if "simple_query_string" in c][0]["simple_query_string"]
        self.assertEqual(sqs["query"], "10.0.2.15 sshd")
        self.assertIn("full_log", sqs["fields"])

    @staticmethod
    def _buckets(counts):
        return [
            {"key_as_string": f"2026-06-25T{h:02d}:00:00Z", "key": h, "doc_count": c}
            for h, c in enumerate(counts)
        ]

    def test_plateau_onset_and_cessation_are_bounded(self):
        # Quiet edges, sustained elevated middle — a plateau, not a point spike.
        counts = [2, 3, 90, 95, 88, 92, 91, 4, 3]
        fake = _FakeOpenSearchClient(buckets=self._buckets(counts), total=sum(counts))
        result = self._client(fake).get_event_volume(_START, _END, interval="1h")

        self.assertIsNotNone(result["active_threshold"])
        self.assertEqual(result["onset"]["time"], "2026-06-25T02:00:00Z")
        self.assertEqual(result["cessation"]["time"], "2026-06-25T06:00:00Z")
        # All five plateau bins are active; the four quiet edge bins are not.
        self.assertEqual(len(result["active_bins"]), 5)
        # Peak (95) is at 03:00 — one active bin ramps up before it, three wind down after.
        self.assertEqual([b["time"] for b in result["pre_spike_active_bins"]],
                         ["2026-06-25T02:00:00Z"])
        self.assertEqual([b["time"] for b in result["post_spike_active_bins"]],
                         ["2026-06-25T04:00:00Z", "2026-06-25T05:00:00Z", "2026-06-25T06:00:00Z"])
        self.assertIn("Sustained elevated activity", result["note"])
        self.assertIn("plateau", result["note"])
        # Resolution caveat: the edges are only located to the bin width; re-profile finer.
        self.assertIn("bin width", result["note"])
        self.assertIn("finer interval", result["note"])
        # The ramp-up segment is appended because pre_spike_active_bins exists.
        self.assertIn("ramps up BEFORE", result["note"])
        self.assertIn("2026-06-25T02:00:00Z", result["note"])
        # 4h active span (02:00->06:00) is under the saturation threshold.
        self.assertFalse(result["saturated"])

    def test_saturated_window_flags_too_broad(self):
        # Activity clears the baseline across an 8h span (01:00->08:00) with only the two
        # edge bins quiet — the profile localized nothing. Should flag saturated and tell
        # the agent to narrow, not "query the onset/cessation edges".
        counts = [5, 8000, 8200, 7900, 8100, 8300, 8050, 8150, 7950, 6]
        fake = _FakeOpenSearchClient(buckets=self._buckets(counts), total=sum(counts))
        result = self._client(fake).get_event_volume(_START, _END, interval="1h")

        self.assertTrue(result["saturated"])
        self.assertEqual(result["onset"]["time"], "2026-06-25T01:00:00Z")
        self.assertEqual(result["cessation"]["time"], "2026-06-25T08:00:00Z")
        self.assertIn("spans", result["note"])
        self.assertIn("not localized", result["note"])
        # Unambiguous fix: shrink the WINDOW, not the interval (the observed misread was
        # coarsening the bin interval in response to saturation).
        self.assertIn("SHRINKING THE TIME WINDOW", result["note"])
        self.assertIn("Do NOT change the bin `interval`", result["note"])
        # The misleading plateau guidance must NOT be emitted for a saturated window.
        self.assertNotIn("Sustained elevated activity", result["note"])

    def test_pre_spike_message_emitted_without_plateau(self):
        # Two-bin active regime (90, 95) with the peak last: a ramp bin then the peak.
        # Not a plateau (<3 active bins), so only the pre-spike segment should appear.
        counts = [2, 90, 95, 3, 2]
        fake = _FakeOpenSearchClient(buckets=self._buckets(counts), total=sum(counts))
        result = self._client(fake).get_event_volume(_START, _END, interval="1h")

        self.assertEqual([b["time"] for b in result["pre_spike_active_bins"]],
                         ["2026-06-25T01:00:00Z"])
        self.assertEqual(result["post_spike_active_bins"], [])
        self.assertIn("ramps up BEFORE", result["note"])
        self.assertNotIn("Sustained elevated activity", result["note"])

    def test_steep_ramp_onset_includes_first_surge_bin(self):
        # Live case (~449101824): a ~70-event floor then a steep climb. The 118125 bin
        # is unmistakably active (~1600x the floor) but raw-count Otsu lumps it into
        # 'quiet' because isolating the tight 266k-318k top scores higher in absolute
        # variance. Log-scale Otsu must put the break below 118125 so onset is the
        # first surge bin, not the peak's neighbor.
        counts = [0, 72, 6, 118125, 317965, 314455, 266741]
        fake = _FakeOpenSearchClient(buckets=self._buckets(counts), total=sum(counts))
        result = self._client(fake).get_event_volume(_START, _END, interval="1h")

        self.assertEqual(result["active_threshold"], 118125.0)
        self.assertEqual(result["onset"]["time"], "2026-06-25T03:00:00Z")  # the 118125 bin
        self.assertEqual(len(result["active_bins"]), 4)
        # Peak (317965) is at 04:00; the 118125 ramp bin precedes it.
        self.assertEqual([b["time"] for b in result["pre_spike_active_bins"]],
                         ["2026-06-25T03:00:00Z"])
        self.assertIn("ramps up BEFORE", result["note"])

    def test_two_bursts_separated_by_gap_are_detected(self):
        # Two high runs (00:00-01:00 and 06:00-07:00) separated by 4 quiet bins — the
        # single onset/cessation would collapse them; bursts must surface both.
        counts = [8000, 8200, 0, 0, 0, 0, 5000, 5200]
        fake = _FakeOpenSearchClient(buckets=self._buckets(counts), total=sum(counts))
        result = self._client(fake).get_event_volume(_START, _END, interval="1h")

        bursts = result["bursts"]
        self.assertEqual(len(bursts), 2)
        # Sorted by total volume: the 16200-event burst first.
        self.assertEqual(bursts[0]["start"], "2026-06-25T00:00:00Z")
        self.assertEqual(bursts[0]["end"], "2026-06-25T01:00:00Z")
        self.assertEqual(bursts[0]["total"], 16200)
        self.assertEqual(bursts[1]["start"], "2026-06-25T06:00:00Z")
        self.assertIn("DISTINCT activity bursts", result["note"])
        self.assertIn("matches your objective", result["note"])

    def test_multi_burst_note_does_not_fall_back_to_peak_centered_guidance(self):
        counts = [9000, 8800, 0, 0, 0, 0, 15000, 15200]
        fake = _FakeOpenSearchClient(buckets=self._buckets(counts), total=sum(counts))
        result = self._client(fake).get_event_volume(_START, _END, interval="1h")

        self.assertEqual(len(result["bursts"]), 2)
        self.assertIn("do NOT treat the whole span as a single burst", result["note"])
        self.assertNotIn("densest activity near", result["note"])

    def test_one_bin_dip_does_not_split_a_burst(self):
        # A single sub-threshold bin inside a run is tolerated (gap <= _BURST_MAX_GAP_BINS).
        counts = [8000, 8200, 0, 8100, 8300]
        fake = _FakeOpenSearchClient(buckets=self._buckets(counts), total=sum(counts))
        result = self._client(fake).get_event_volume(_START, _END, interval="1h")
        self.assertEqual(len(result["bursts"]), 1)
        self.assertNotIn("DISTINCT activity bursts", result.get("note", ""))

    def test_single_plateau_is_one_burst(self):
        counts = [2, 3, 90, 95, 88, 92, 91, 4, 3]
        fake = _FakeOpenSearchClient(buckets=self._buckets(counts), total=sum(counts))
        result = self._client(fake).get_event_volume(_START, _END, interval="1h")
        self.assertEqual(len(result["bursts"]), 1)

    def test_flat_histogram_reports_no_regime(self):
        # Uniform counts: no distinct active period (unimodal guard trips).
        counts = [50, 48, 51, 49, 50, 52, 47]
        fake = _FakeOpenSearchClient(buckets=self._buckets(counts), total=sum(counts))
        result = self._client(fake).get_event_volume(_START, _END, interval="1h")

        self.assertIsNone(result["active_threshold"])
        self.assertIsNone(result["onset"])
        self.assertIsNone(result["cessation"])
        self.assertEqual(result["active_bins"], [])

    def test_post_peak_tail_filtered_to_above_baseline(self):
        # A sharp spike with a quiet floor that has noisy non-zero bins after it.
        # Old logic flagged every non-zero post-peak bin; now only above-baseline ones.
        counts = [1, 2, 800, 3, 2, 1, 2]
        fake = _FakeOpenSearchClient(buckets=self._buckets(counts), total=sum(counts))
        result = self._client(fake).get_event_volume(_START, _END, interval="1h")

        self.assertEqual(result["peak_count"], 800)
        # The low pre/post-spike noise (1,2 / 3,2,1,2) is below the active threshold.
        self.assertEqual(result["pre_spike_active_bins"], [])
        self.assertEqual(result["post_spike_active_bins"], [])

    def test_no_query_omits_bool_but_keeps_range(self):
        fake = _FakeOpenSearchClient(buckets=[])
        client = self._client(fake)

        client.get_event_volume(_START, _END, interval="1h")

        # Range alone still produces a query.bool.must with the range filter.
        must = fake.posts[0][1]["query"]["bool"]["must"]
        self.assertTrue(any("range" in clause for clause in must))
        self.assertEqual(fake.posts[0][1]["size"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
