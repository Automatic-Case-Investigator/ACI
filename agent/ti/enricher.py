"""TI enrichment orchestrator: cache, rate-limiting, board writes, lead creation."""
from __future__ import annotations

import asyncio
import logging
import threading
import time
from typing import Optional

from .base import TIProvider, TIResult
from .cache import TICache

log = logging.getLogger(__name__)


class _TokenBucket:
    """Simple token-bucket rate limiter."""

    def __init__(self, calls_per_minute: int) -> None:
        self._rate = max(calls_per_minute, 1) / 60.0
        self._tokens: float = float(max(calls_per_minute, 1))
        self._max: float = float(max(calls_per_minute, 1))
        self._last: float = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                self._tokens = min(
                    self._max,
                    self._tokens + (now - self._last) * self._rate,
                )
                self._last = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
            time.sleep(0.1)


class TIEnricher:
    """Enriches artifact batches against registered TI providers.

    Designed as a process-wide singleton (see `get_enricher()`).
    All blocking network I/O runs on thread-pool threads via
    `enrich_artifacts_async()`; the caller's async event loop is not blocked.
    """

    def __init__(
        self,
        providers: list[TIProvider],
        cache: TICache,
        calls_per_minute: int = 4,
    ) -> None:
        self._providers = providers
        self._cache = cache
        self._bucket = _TokenBucket(calls_per_minute)

    @property
    def cache(self) -> TICache:
        return self._cache

    def enrich_batch(
        self,
        artifacts: list,
        case_id: str,
        run_id: str,
        agent_name: str,
    ) -> list[TIResult]:
        """Synchronous enrichment — called from a thread-pool executor."""
        results: list[TIResult] = []

        for artifact in artifacts:
            for provider in self._providers:
                if not provider.supports(artifact.kind):
                    continue
                cached = self._cache.get(
                    provider.name, artifact.kind, artifact.value, case_id
                )
                if cached is not None:
                    results.append(cached)
                    continue
                self._bucket.acquire()
                result = provider.lookup(artifact.kind, artifact.value)
                self._cache.set(result, case_id)
                results.append(result)

        return results

    async def enrich_artifacts_async(
        self,
        artifacts: list,
        case_id: str,
        run_id: str,
        agent_name: str,
    ) -> list[TIResult]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            self.enrich_batch,
            artifacts,
            case_id,
            run_id,
            agent_name,
        )


# ── Module-level helpers ──────────────────────────────────────────────────────

def _verdict_to_confidence(verdict: str) -> str:
    return {"malicious": "high", "suspicious": "medium"}.get(verdict, "low")


def write_ti_results(
    results: list[TIResult],
    case_id: str,
    run_id: str,
    agent_name: str,
) -> list[TIResult]:
    """Write TI results to the board as kind='ti_result'.

    Returns the subset with verdict in ('malicious', 'suspicious') —
    these are the ones that should trigger investigation leads.
    """
    from aci_board import store
    store.init_db()

    for result in results:
        score_str = f"{result.score:.2f}" if result.score is not None else "n/a"
        indicators_str = f" — {result.indicators}" if result.indicators else ""
        content = (
            f"TI[{result.provider}] {result.artifact_kind} {result.artifact_value}: "
            f"{result.verdict} ({score_str}){indicators_str}"
        )
        dedup_key = (
            f"ti:{result.provider}:{result.artifact_kind}:{result.artifact_value.lower()}"
        )
        store.add_entry(
            case_id=case_id,
            run_id=run_id,
            agent_name=agent_name,
            kind="ti_result",
            content=content,
            source=result.reference,
            confidence=_verdict_to_confidence(result.verdict),
            status="observed",
            dedup_key=dedup_key,
        )

    return [r for r in results if r.verdict in ("malicious", "suspicious")]


def create_ti_leads(
    flagged: list[TIResult],
    case_id: str,
    run_id: str,
    agent_name: str,
) -> int:
    """Create investigation task leads for malicious/suspicious TI verdicts.

    Returns the count of leads created.
    """
    from aci_taskqueue import store as tq_store
    tq_store.init_db()

    created = 0
    for result in flagged:
        priority = 80 if result.verdict == "malicious" else 60
        score_str = f"{result.score:.2f}" if result.score is not None else "n/a"
        indicators_str = result.indicators or "(no specific indicators)"

        title = (
            f"TI: investigate {result.verdict} {result.artifact_kind} "
            f"{result.artifact_value} [{result.provider}]"
        )
        description = (
            f"Threat Intelligence flagged this artifact as **{result.verdict}**.\n\n"
            f"- Provider: {result.provider}\n"
            f"- Artifact: {result.artifact_kind} `{result.artifact_value}`\n"
            f"- Score: {score_str}\n"
            f"- Indicators: {indicators_str}\n"
            f"- Reference: {result.reference}\n\n"
            "This is advisory. Correlate against SIEM events for this case to confirm "
            "whether the flagged artifact is actively involved in the incident. "
            "If confirmed, update the Findings Board with a confirmed fact and escalate."
        )
        tq_store.create_task(
            case_id=case_id,
            run_id=run_id,
            agent_name=agent_name,
            title=title,
            description=description,
            priority=priority,
            origin="ti_enrichment",
        )
        created += 1

    return created


# ── Singleton factory ─────────────────────────────────────────────────────────

_enricher_instance: Optional[TIEnricher] = None
_cache_instance: Optional[TICache] = None
_enricher_lock = threading.Lock()
_cache_lock = threading.Lock()


def _build_cache() -> TICache:
    """Build TICache from effective settings (DB overrides env).

    The cache TTL is a shared cache-level setting (RuntimeConfig), not a per-TI-
    platform connection setting.
    """
    from django.conf import settings as dj_settings
    from agent.runtime.config.runtime_config import ti_cache_ttl_hours

    try:
        ttl = int(ti_cache_ttl_hours())
    except Exception:
        ttl = int(getattr(dj_settings, "TI_CACHE_TTL_HOURS", 24))

    db_path = getattr(dj_settings, "TI_CACHE_DB_PATH", "ti_cache.db")
    return TICache(db_path=db_path, ttl_hours=ttl)


def reset_ti_cache() -> None:
    """Drop the cached TICache/enricher singletons so they rebuild with fresh settings.

    Called when the cache TTL changes so the new value applies without a restart.
    """
    global _cache_instance, _enricher_instance
    with _cache_lock:
        _cache_instance = None
    with _enricher_lock:
        _enricher_instance = None


def get_ti_cache() -> Optional[TICache]:
    """Return the shared TICache instance (always available when DB path is set)."""
    global _cache_instance
    if _cache_instance is not None:
        return _cache_instance
    with _cache_lock:
        if _cache_instance is not None:
            return _cache_instance
        try:
            _cache_instance = _build_cache()
        except Exception as exc:
            log.warning("TI cache init failed: %s", exc)
            return None
    return _cache_instance


def get_enricher() -> Optional[TIEnricher]:
    """Return the process-wide TIEnricher, or None when TI is not configured.

    Returns None silently when VT_API_KEY is empty — no exception, no warning.
    """
    global _enricher_instance
    if _enricher_instance is not None:
        return _enricher_instance
    with _enricher_lock:
        if _enricher_instance is not None:
            return _enricher_instance

        try:
            from django.conf import settings as dj_settings
            from agent.runtime.config import resolve_settings

            defaults = {
                "api_key": getattr(dj_settings, "VT_API_KEY", ""),
                "base_url": getattr(dj_settings, "VT_BASE_URL", "https://www.virustotal.com"),
                "calls_per_minute": str(getattr(dj_settings, "TI_CALLS_PER_MINUTE", 4)),
            }
            try:
                effective = resolve_settings("aci-ti", defaults)
            except Exception:
                effective = defaults

            api_key = (effective.get("api_key") or "").strip()
            if not api_key:
                return None

            from .providers.virustotal import VirusTotalProvider

            provider = VirusTotalProvider(
                api_key=api_key,
                base_url=(effective.get("base_url") or "https://www.virustotal.com").strip(),
            )
            cache = get_ti_cache()
            if cache is None:
                return None

            calls_per_min = int(effective.get("calls_per_minute") or 4)

            _enricher_instance = TIEnricher(
                providers=[provider],
                cache=cache,
                calls_per_minute=calls_per_min,
            )
        except Exception as exc:
            log.warning("TI enricher init failed: %s", exc)
            return None

    return _enricher_instance
