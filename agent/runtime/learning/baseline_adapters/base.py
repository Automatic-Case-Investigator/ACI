"""SIEM-agnostic adapter contract for behavioral baseline computation.

The baseline orchestrator (`agent/runtime/baselines.py`) knows nothing about any
particular SIEM. Everything SIEM-specific — connection, field names, query
language, and which features can be derived — lives behind this adapter.

A backend implements two operations:

- `discover_subjects(subject_type, days)` — enumerate the users/endpoints that
  have activity in the window, returning clean subject IDs.
- `compute_features(subject_type, subject_id, days)` — derive the behavioral
  features for one subject as a list of `FeatureResult`.

The orchestrator owns the SIEM-agnostic policy: subject-selection precedence,
the health gate (how many events make a baseline fresh / low_data / skipped),
and persistence to `BaselineSnapshot`.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class FeatureResult:
    """One computed feature for a subject.

    `feature` is a SIEM-agnostic name (e.g. "active_hours", "source_ips",
    "common_rules"). `value` is the JSON-serializable shape stored verbatim in
    `BaselineSnapshot.value`. `event_count` is the number of underlying events
    the feature was derived from — the orchestrator uses it for the health gate.
    """

    feature: str
    value: dict
    event_count: int


@runtime_checkable
class BaselineSIEMAdapter(Protocol):
    """A SIEM backend capable of supplying baseline data."""

    name: str

    def discover_subjects(self, subject_type: str, days: int) -> list[str]:
        """Return subject IDs of the given type with activity in the window."""
        ...

    def compute_features(self, subject_type: str, subject_id: str, days: int) -> list[FeatureResult]:
        """Return the behavioral features derivable for one subject."""
        ...
