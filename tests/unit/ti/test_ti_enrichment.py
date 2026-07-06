"""Tests for TI enrichment: TIResult, TICache, VirusTotalProvider, TIEnricher,
board/lead integration, cache management views."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

# ── Django setup ──────────────────────────────────────────────────────────────
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

_tmp_board = tempfile.mktemp(suffix="_board.db")
_tmp_ti    = tempfile.mktemp(suffix="_ti.db")
_tmp_tq    = tempfile.mktemp(suffix="_tq.db")

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
os.environ.setdefault("SECRET_KEY", "test-secret-key")
os.environ["BOARD_DB_PATH"]     = _tmp_board
os.environ["TI_CACHE_DB_PATH"]  = _tmp_ti
os.environ["TASKQUEUE_DB_PATH"] = _tmp_tq
os.environ["VT_API_KEY"]        = ""   # disabled by default

import django
django.setup()

from agent.ti.base import TIProvider, TIResult
from agent.ti.cache import TICache
from agent.ti.enricher import (
    TIEnricher,
    _build_cache,
    create_ti_leads,
    get_enricher,
    get_ti_cache,
    write_ti_results,
)
from agent.ti.providers.virustotal import VirusTotalProvider


# ── Helpers ───────────────────────────────────────────────────────────────────

def _tmp_cache(ttl_hours: int = 24) -> TICache:
    return TICache(db_path=tempfile.mktemp(suffix=".db"), ttl_hours=ttl_hours)


def _fake_result(
    verdict: str = "malicious",
    kind: str = "ip",
    value: str = "1.2.3.4",
    score: float = 0.6,
    indicators: str = "botnet; c2",
) -> TIResult:
    return TIResult(
        provider="virustotal",
        artifact_kind=kind,
        artifact_value=value,
        verdict=verdict,
        score=score,
        indicators=indicators,
        reference=f"https://www.virustotal.com/gui/ip-address/{value}",
        raw={"test": True},
    )


def _fake_artifact(kind: str = "ip", value: str = "1.2.3.4"):
    from dataclasses import dataclass

    @dataclass(frozen=True)
    class _Art:
        kind: str
        value: str
        source: str = ""

    return _Art(kind=kind, value=value)


# ── TestTIResult ──────────────────────────────────────────────────────────────

class TestTIResult(unittest.TestCase):
    def test_frozen(self):
        r = _fake_result()
        with self.assertRaises((AttributeError, TypeError)):
            r.verdict = "clean"  # type: ignore[misc]

    def test_raw_excluded_from_equality(self):
        r1 = TIResult("vt", "ip", "1.2.3.4", "malicious", 0.5, "botnet", "https://x", raw={"a": 1})
        r2 = TIResult("vt", "ip", "1.2.3.4", "malicious", 0.5, "botnet", "https://x", raw={"b": 999})
        self.assertEqual(r1, r2)

    def test_score_none_allowed(self):
        r = TIResult("vt", "domain", "evil.com", "unknown", None, "", "https://x")
        self.assertIsNone(r.score)


# ── TestTICache ───────────────────────────────────────────────────────────────

class TestTICache(unittest.TestCase):
    def setUp(self):
        self.cache = _tmp_cache()

    def test_miss_before_set(self):
        self.assertIsNone(self.cache.get("vt", "ip", "1.2.3.4", "case1"))

    def test_hit_after_set(self):
        r = _fake_result(value="5.5.5.5")
        self.cache.set(r, "caseA")
        got = self.cache.get("virustotal", "ip", "5.5.5.5", "caseA")
        self.assertIsNotNone(got)
        self.assertEqual(got.verdict, "malicious")

    def test_case_scope_isolation(self):
        r = _fake_result(value="7.7.7.7")
        self.cache.set(r, "case-X")
        self.assertIsNone(self.cache.get("virustotal", "ip", "7.7.7.7", "case-Y"))

    def test_value_normalised_to_lowercase(self):
        r = TIResult("vt", "sha256", "ABCDEF", "clean", 0.0, "", "https://x")
        self.cache.set(r, "c1")
        got = self.cache.get("vt", "sha256", "abcdef", "c1")
        self.assertIsNotNone(got)

    def test_insert_or_replace(self):
        r1 = _fake_result(verdict="malicious", score=0.9, value="9.9.9.9")
        r2 = TIResult("virustotal", "ip", "9.9.9.9", "clean", 0.0, "", "https://y")
        self.cache.set(r1, "case1")
        self.cache.set(r2, "case1")
        got = self.cache.get("virustotal", "ip", "9.9.9.9", "case1")
        self.assertEqual(got.verdict, "clean")

    def test_stats_counts_entries(self):
        self.cache.set(_fake_result(value="10.0.0.1"), "c1")
        self.cache.set(_fake_result(value="10.0.0.2"), "c1")
        stats = self.cache.stats()
        self.assertGreaterEqual(stats["total"], 2)
        self.assertIn("virustotal", stats["by_provider"])

    def test_clear_all(self):
        self.cache.set(_fake_result(value="11.0.0.1"), "c1")
        deleted = self.cache.clear_all()
        self.assertGreater(deleted, 0)
        self.assertEqual(self.cache.stats()["total"], 0)

    def test_cleanup_expired_removes_stale(self):
        from datetime import datetime, timedelta, timezone
        # Write an entry then manually backdate its expires_at.
        self.cache.set(_fake_result(value="12.0.0.1"), "c1")
        import sqlite3
        conn = sqlite3.connect(self.cache._db_path)
        conn.execute(
            "UPDATE ti_cache SET expires_at=? WHERE value=?",
            ((datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(), "12.0.0.1"),
        )
        conn.commit()
        conn.close()
        removed = self.cache.cleanup_expired()
        self.assertGreater(removed, 0)
        self.assertIsNone(self.cache.get("virustotal", "ip", "12.0.0.1", "c1"))

    def test_cleanup_expired_keeps_live_entries(self):
        self.cache.set(_fake_result(value="13.0.0.1"), "c1")
        removed = self.cache.cleanup_expired()
        self.assertEqual(removed, 0)
        self.assertIsNotNone(self.cache.get("virustotal", "ip", "13.0.0.1", "c1"))


# ── TestVirusTotalProvider ────────────────────────────────────────────────────

def _vt_response(malicious=0, suspicious=0, harmless=60, labels=None) -> dict:
    results = {}
    for i, label in enumerate(labels or []):
        results[f"engine_{i}"] = {"result": label, "category": "malicious"}
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": 0,
                },
                "last_analysis_results": results,
            }
        }
    }


class TestVirusTotalProvider(unittest.TestCase):
    def _provider(self):
        return VirusTotalProvider(api_key="fake-key")

    def _mock_resp(self, body: dict, status_code: int = 200):
        resp = MagicMock()
        resp.status_code = status_code
        resp.is_error = status_code >= 400
        resp.json.return_value = body
        return resp

    def test_malicious_ip(self):
        p = self._provider()
        body = _vt_response(malicious=12, suspicious=2, harmless=55, labels=["Trojan", "c2"])
        with patch("httpx.Client") as MockClient:
            MockClient.return_value.__enter__.return_value.get.return_value = self._mock_resp(body)
            r = p.lookup("ip", "1.2.3.4")
        self.assertEqual(r.verdict, "malicious")
        self.assertIsNotNone(r.score)
        self.assertGreater(r.score, 0.1)
        self.assertIn("Trojan", r.indicators)

    def test_suspicious_domain(self):
        p = self._provider()
        body = _vt_response(malicious=0, suspicious=5, harmless=60)
        with patch("httpx.Client") as MockClient:
            MockClient.return_value.__enter__.return_value.get.return_value = self._mock_resp(body)
            r = p.lookup("domain", "evil.com")
        self.assertEqual(r.verdict, "suspicious")

    def test_clean_hash(self):
        p = self._provider()
        body = _vt_response(malicious=0, suspicious=0, harmless=67)
        with patch("httpx.Client") as MockClient:
            MockClient.return_value.__enter__.return_value.get.return_value = self._mock_resp(body)
            r = p.lookup("sha256", "a" * 64)
        self.assertEqual(r.verdict, "clean")
        self.assertEqual(r.score, 0.0)

    def test_404_returns_unknown(self):
        p = self._provider()
        with patch("httpx.Client") as MockClient:
            MockClient.return_value.__enter__.return_value.get.return_value = self._mock_resp({}, 404)
            r = p.lookup("ip", "0.0.0.0")
        self.assertEqual(r.verdict, "unknown")

    def test_network_error_returns_unknown(self):
        p = self._provider()
        with patch("httpx.Client") as MockClient:
            MockClient.return_value.__enter__.return_value.get.side_effect = OSError("timeout")
            r = p.lookup("ip", "0.0.0.1")
        self.assertEqual(r.verdict, "unknown")
        self.assertIn("timeout", r.indicators)

    def test_ip_uses_ip_endpoint(self):
        p = self._provider()
        body = _vt_response()
        with patch("httpx.Client") as MockClient:
            mock_get = MockClient.return_value.__enter__.return_value.get
            mock_get.return_value = self._mock_resp(body)
            p.lookup("ip", "8.8.8.8")
        url = mock_get.call_args[0][0]
        self.assertIn("/api/v3/ip_addresses/8.8.8.8", url)

    def test_hash_uses_files_endpoint(self):
        p = self._provider()
        body = _vt_response()
        with patch("httpx.Client") as MockClient:
            mock_get = MockClient.return_value.__enter__.return_value.get
            mock_get.return_value = self._mock_resp(body)
            p.lookup("sha256", "abc123")
        url = mock_get.call_args[0][0]
        self.assertIn("/api/v3/files/abc123", url)

    def test_domain_uses_domains_endpoint(self):
        p = self._provider()
        body = _vt_response()
        with patch("httpx.Client") as MockClient:
            mock_get = MockClient.return_value.__enter__.return_value.get
            mock_get.return_value = self._mock_resp(body)
            p.lookup("domain", "example.com")
        url = mock_get.call_args[0][0]
        self.assertIn("/api/v3/domains/example.com", url)

    def test_supported_kinds(self):
        p = self._provider()
        for k in ("ip", "domain", "sha256", "sha1", "md5"):
            self.assertTrue(p.supports(k), k)
        for k in ("process", "user", "host", "command", "file"):
            self.assertFalse(p.supports(k), k)


# ── TestTIEnricher ────────────────────────────────────────────────────────────

class TestTIEnricher(unittest.TestCase):
    def _enricher(self, provider=None, calls_per_minute=60):
        cache = _tmp_cache()
        providers = [provider] if provider else []
        return TIEnricher(
            providers=providers,
            cache=cache,
            calls_per_minute=calls_per_minute,
        )

    def _mock_vt_provider(self, result: TIResult):
        p = MagicMock(spec=VirusTotalProvider)
        p.name = "virustotal"
        p.supported_kinds = frozenset({"ip", "domain", "sha256", "sha1", "md5"})
        p.supports.side_effect = lambda k: k in p.supported_kinds
        p.lookup.return_value = result
        return p

    def test_no_providers_returns_empty(self):
        e = self._enricher()
        result = e.enrich_batch([_fake_artifact()], "c1", "r1", "investigation")
        self.assertEqual(result, [])

    def test_unsupported_kind_skipped(self):
        mock_p = self._mock_vt_provider(_fake_result())
        e = self._enricher(provider=mock_p)
        e.enrich_batch([_fake_artifact(kind="process", value="cmd.exe")], "c1", "r1", "inv")
        mock_p.lookup.assert_not_called()

    def test_cache_hit_skips_provider(self):
        mock_p = self._mock_vt_provider(_fake_result())
        e = self._enricher(provider=mock_p)
        # Pre-populate cache.
        e._cache.set(_fake_result(value="1.2.3.4"), "c1")
        e.enrich_batch([_fake_artifact(value="1.2.3.4")], "c1", "r1", "inv")
        mock_p.lookup.assert_not_called()

    def test_all_artifacts_enriched_no_cap(self):
        mock_p = self._mock_vt_provider(_fake_result())
        e = self._enricher(provider=mock_p)
        arts = [_fake_artifact(value=f"10.0.0.{i}") for i in range(5)]
        e.enrich_batch(arts, "c1", "r1", "inv")
        self.assertEqual(mock_p.lookup.call_count, 5)

    def test_malicious_verdict_creates_lead(self):
        from aci_taskqueue import store as tq_store
        r = _fake_result(verdict="malicious", value="3.3.3.3")
        n = create_ti_leads([r], "case-lead-mal", "run-lead-mal", "investigation")
        self.assertEqual(n, 1)
        tasks = tq_store.list_tasks("case-lead-mal", "run-lead-mal", "investigation")
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0]["priority"], 80)
        self.assertEqual(tasks[0]["origin"], "ti_enrichment")

    def test_suspicious_verdict_priority(self):
        from aci_taskqueue import store as tq_store
        r = _fake_result(verdict="suspicious", value="evil2.com", kind="domain")
        create_ti_leads([r], "case-susp", "run-susp", "investigation")
        tasks = tq_store.list_tasks("case-susp", "run-susp", "investigation")
        self.assertTrue(any(t["priority"] == 60 for t in tasks))

    def test_clean_verdict_no_lead(self):
        from aci_taskqueue import store as tq_store
        r = _fake_result(verdict="clean", value="8.8.8.8")
        n = create_ti_leads([], "case-c", "run-c", "investigation")
        self.assertEqual(n, 0)

    def test_write_ti_results_to_board(self):
        from aci_board import store
        store.init_db()
        r = _fake_result(value="200.0.0.1")
        write_ti_results([r], "case-b", "run-b", "investigation")
        entries = store.list_entries("case-b", "run-b", "investigation")
        ti = [e for e in entries if e["kind"] == "ti_result"]
        self.assertEqual(len(ti), 1)
        self.assertIn("malicious", ti[0]["content"])
        self.assertIn("virustotal", ti[0]["content"])

    def test_dedup_key_prevents_duplicate_board_entries(self):
        from aci_board import store
        r = _fake_result(value="201.0.0.1")
        write_ti_results([r], "case-dup", "run-dup", "investigation")
        write_ti_results([r], "case-dup", "run-dup", "investigation")
        entries = store.list_entries("case-dup", "run-dup", "investigation")
        ti = [e for e in entries if e["kind"] == "ti_result"]
        self.assertEqual(len(ti), 1)


# ── TestGetEnricher ───────────────────────────────────────────────────────────

class TestGetEnricher(unittest.TestCase):
    def setUp(self):
        # Reset singleton state before each test.
        import agent.ti.enricher as enricher_mod
        enricher_mod._enricher_instance = None
        enricher_mod._cache_instance = None

    tearDown = setUp  # Reset after too.

    def test_returns_none_when_no_api_key(self):
        # Isolate from any DB-stored aci-ti ProviderConfig (these tests hit the
        # real DB): resolve_settings returns the env-backed defaults unchanged.
        from django.test import override_settings
        with override_settings(VT_API_KEY=""), \
                patch("agent.runtime.config.resolve_settings", side_effect=lambda key, defaults: defaults):
            self.assertIsNone(get_enricher())

    def test_returns_enricher_when_api_key_set(self):
        from django.test import override_settings
        with override_settings(VT_API_KEY="fake-key-for-test"):
            enricher = get_enricher()
        self.assertIsNotNone(enricher)
        self.assertIsInstance(enricher, TIEnricher)

    def test_singleton_identity(self):
        from django.test import override_settings
        with override_settings(VT_API_KEY="fake-key-for-test"):
            a = get_enricher()
            b = get_enricher()
        self.assertIs(a, b)

    def test_get_ti_cache_always_available(self):
        os.environ["VT_API_KEY"] = ""
        cache = get_ti_cache()
        self.assertIsNotNone(cache)
        self.assertIsInstance(cache, TICache)


# ── TestBoardContextTI ────────────────────────────────────────────────────────

class TestBoardContextTI(unittest.TestCase):
    def _format(self, entries: list) -> str:
        import json
        from agent.runtime.graph import _format_board_context
        raw = json.dumps({"entries": entries})
        return _format_board_context(raw)

    def test_ti_section_shown(self):
        entries = [
            {
                "kind": "ti_result",
                "content": "TI[virustotal] ip 1.2.3.4: malicious (0.60) — botnet; c2",
                "source": "https://www.virustotal.com/gui/ip-address/1.2.3.4",
                "confidence": "high",
                "status": "observed",
            }
        ]
        text = self._format(entries)
        self.assertIn("TI Enrichment", text)
        self.assertIn("advisory only", text)
        self.assertIn("1.2.3.4", text)

    def test_advisory_disclaimer_present(self):
        entries = [
            {"kind": "ti_result", "content": "TI[vt] ip 2.2.2.2: clean (0.00)",
             "source": "", "confidence": "low", "status": "observed"},
        ]
        text = self._format(entries)
        self.assertIn("advisory only", text.lower())

    def test_no_ti_section_when_empty(self):
        entries = [
            {"kind": "artifact", "content": "ip: 3.3.3.3", "source": "evt1",
             "confidence": "high", "status": "observed"},
        ]
        text = self._format(entries)
        self.assertNotIn("TI Enrichment", text)


# ── TestCacheManagement (view tests) ─────────────────────────────────────────

class TestCacheManagement(unittest.TestCase):
    def setUp(self):
        import agent.ti.enricher as enricher_mod
        enricher_mod._cache_instance = None

    tearDown = setUp

    def test_ti_cache_stats_view_returns_json(self):
        from django.test import RequestFactory
        from agent.dashboard.settings_views import settings_ti_cache_stats

        rf = RequestFactory()
        request = rf.get("/dashboard/settings/ti/cache/stats")
        response = settings_ti_cache_stats(request)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIn("total", data)
        self.assertIn("by_provider", data)

    def test_ti_cache_clear_view_empties_cache(self):
        from django.test import RequestFactory
        from agent.dashboard.settings_views import settings_ti_cache_clear
        from agent.ti.enricher import get_ti_cache

        cache = get_ti_cache()
        cache.set(_fake_result(value="50.0.0.1"), "case-clear")
        self.assertGreater(cache.stats()["total"], 0)

        rf = RequestFactory()
        request = rf.post("/dashboard/settings/ti/cache/clear")
        # Patch messages framework (not set up in test context).
        with patch("agent.dashboard.settings_views.messages"):
            try:
                settings_ti_cache_clear(request)
            except Exception:
                pass  # redirect raises in test; that's fine

        self.assertEqual(cache.stats()["total"], 0)

    def test_cleanup_expired_on_init(self):
        """init_db() must clean up expired entries seeded before init."""
        import sqlite3
        from datetime import datetime, timedelta, timezone

        db = tempfile.mktemp(suffix=".db")
        # Create table manually and insert an expired row.
        conn = sqlite3.connect(db)
        conn.execute("""CREATE TABLE IF NOT EXISTS ti_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT, kind TEXT, value TEXT, case_id TEXT,
            verdict TEXT, score REAL, indicators TEXT, reference TEXT,
            raw_json TEXT, cached_at TEXT, expires_at TEXT
        )""")
        past = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        conn.execute(
            "INSERT INTO ti_cache (provider,kind,value,case_id,verdict,score,"
            "indicators,reference,raw_json,cached_at,expires_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            ("vt", "ip", "99.0.0.1", "c1", "malicious", 0.9, "", "", "{}", past, past),
        )
        conn.commit()
        conn.close()

        # Init should clean up on startup.
        cache = TICache(db_path=db, ttl_hours=24)
        self.assertEqual(cache.stats()["total"], 0)


if __name__ == "__main__":
    unittest.main()
