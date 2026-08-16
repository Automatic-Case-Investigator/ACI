from __future__ import annotations

"""Deterministic normalization of tool-result batches into observation state.

Split from a single module; the submodules below own cohesive slices of the
original. Every public and private name is re-exported here so the historical
``from agent.runtime.graph.observation import X`` access pattern keeps working.
Contributor rule: the submodules own the names; this ``__init__`` only re-exports
them — never define new behavior here."""

from . import (
    trials,
    events,
    digest,
    pivots,
    signals,
    build,
)

_submodules = [
    trials,
    events,
    digest,
    pivots,
    signals,
    build,
]
for _m in _submodules:
    for _n in dir(_m):
        if not _n.startswith("__"):
            globals()[_n] = getattr(_m, _n)
del _m, _n, _submodules
