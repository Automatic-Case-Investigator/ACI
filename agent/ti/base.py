"""TI provider contract and result type."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class TIResult:
    """Advisory result from one provider for one artifact.

    `verdict` is the provider's categorical judgement: one of
    "malicious", "suspicious", "clean", or "unknown".
    `score` is a 0.0-1.0 normalised maliciousness score (None when unavailable).
    `indicators` cites the top threat labels from the provider (e.g. "trojan; c2").
    `reference` is the canonical URL the analyst can open for full detail.
    `raw` holds the provider-specific parsed sub-dict; excluded from hash/compare.
    """

    provider: str
    artifact_kind: str
    artifact_value: str
    verdict: str            # "malicious" | "suspicious" | "clean" | "unknown"
    score: Optional[float]  # 0.0–1.0; None when provider does not supply
    indicators: str         # "; ".join of top threat categories, "" if none
    reference: str          # permalink URL
    raw: dict = field(default_factory=dict, hash=False, compare=False)


class TIProvider(ABC):
    """Abstract base for all TI providers.

    Subclasses must set `name` (stable lower-case slug) and `supported_kinds`
    (the set of Artifact.kind values this provider can meaningfully enrich).
    """

    name: str
    supported_kinds: frozenset[str]

    @abstractmethod
    def lookup(self, kind: str, value: str) -> TIResult:
        """Blocking HTTP lookup. Called from a thread-pool executor.

        Must return a TIResult even on error (use verdict="unknown").
        Must NOT raise.
        """

    def supports(self, kind: str) -> bool:
        return kind in self.supported_kinds
