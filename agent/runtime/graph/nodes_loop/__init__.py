from __future__ import annotations

"""nodes_loop.py

Split from a single module; the submodules below own cohesive slices of the
original. Every public and private name is re-exported here so the historical
``from agent.runtime.graph.nodes_loop import X`` access pattern keeps working.
Contributor rule: the submodules own the names; this ``__init__`` only re-exports
them — never define new behavior here."""

from . import (
    _const,
    context,
    enrichment,
    nodes,
)

_submodules = [
    _const,
    context,
    enrichment,
    nodes,
]
for _m in _submodules:
    for _n in dir(_m):
        if not _n.startswith("__"):
            globals()[_n] = getattr(_m, _n)
del _m, _n, _submodules
