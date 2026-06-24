"""VirusTotal API v3 TI provider."""
from __future__ import annotations

import json
from typing import Optional

import httpx

from ..base import TIProvider, TIResult


class VirusTotalProvider(TIProvider):
    """Enriches IPs, domains, and file hashes via VirusTotal API v3.

    File paths, process names, users, hosts, and commands are not supported
    (VT has no endpoint for those artifact kinds).
    """

    name = "virustotal"
    supported_kinds = frozenset({"ip", "domain", "sha256", "sha1", "md5"})

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://www.virustotal.com",
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")

    def _endpoint(self, kind: str, value: str) -> str:
        if kind == "ip":
            return f"{self._base_url}/api/v3/ip_addresses/{value}"
        if kind == "domain":
            return f"{self._base_url}/api/v3/domains/{value}"
        # sha256, sha1, md5
        return f"{self._base_url}/api/v3/files/{value}"

    def _gui_link(self, kind: str, value: str) -> str:
        if kind == "ip":
            return f"https://www.virustotal.com/gui/ip-address/{value}"
        if kind == "domain":
            return f"https://www.virustotal.com/gui/domain/{value}"
        return f"https://www.virustotal.com/gui/file/{value}"

    def _parse_response(self, kind: str, value: str, body: dict) -> TIResult:
        attrs = (body.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}

        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        total = malicious + suspicious + harmless + undetected

        if total > 0:
            score: Optional[float] = (malicious + 0.5 * suspicious) / total
        else:
            score = None

        if malicious >= 3:
            verdict = "malicious"
        elif suspicious >= 3 or malicious > 0:
            verdict = "suspicious"
        elif total > 0:
            verdict = "clean"
        else:
            verdict = "unknown"

        # Extract top-5 threat labels from individual engine results.
        results_map: dict = attrs.get("last_analysis_results") or {}
        labels: list[str] = []
        for engine_result in results_map.values():
            if not isinstance(engine_result, dict):
                continue
            label = engine_result.get("result")
            if label and label.lower() not in ("clean", "unrated", ""):
                labels.append(label)
        labels = sorted(set(labels))[:5]
        indicators = "; ".join(labels)

        return TIResult(
            provider=self.name,
            artifact_kind=kind,
            artifact_value=value,
            verdict=verdict,
            score=score,
            indicators=indicators,
            reference=self._gui_link(kind, value),
            raw={"last_analysis_stats": stats},
        )

    def lookup(self, kind: str, value: str) -> TIResult:
        url = self._endpoint(kind, value)
        try:
            with httpx.Client(timeout=10) as client:
                resp = client.get(url, headers={"x-apikey": self._api_key})
            if resp.status_code == 404:
                return TIResult(
                    provider=self.name,
                    artifact_kind=kind,
                    artifact_value=value,
                    verdict="unknown",
                    score=None,
                    indicators="not found in VT database",
                    reference=self._gui_link(kind, value),
                )
            if resp.is_error:
                return TIResult(
                    provider=self.name,
                    artifact_kind=kind,
                    artifact_value=value,
                    verdict="unknown",
                    score=None,
                    indicators=f"HTTP {resp.status_code}",
                    reference=self._gui_link(kind, value),
                )
            return self._parse_response(kind, value, resp.json())
        except Exception as exc:
            return TIResult(
                provider=self.name,
                artifact_kind=kind,
                artifact_value=value,
                verdict="unknown",
                score=None,
                indicators=str(exc)[:120],
                reference=self._gui_link(kind, value),
            )
