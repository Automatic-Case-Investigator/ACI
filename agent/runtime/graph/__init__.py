"""LangGraph agent graph (queue-driven loop shared by triage and investigation).

This package was split from a single 2223-line module; the submodules below own
cohesive slices of the original. Every public and private name is re-exported here
so the historical ``from agent.runtime.graph import X`` / ``graph._helper`` access
pattern (used across the runtime and the test suite) keeps working unchanged.

The same dynamic ``globals()`` re-export appears in the ``interpretation`` and
``nodes_flow`` sub-packages (and in ``runtime.orchestrator``). It exists so a module
can be split into a sub-package without touching a single import site or test.
Contributor rule: the submodules own the names; each ``__init__`` only re-exports
them — never define new behavior in an ``__init__``.
"""
from . import (
    state, sanitize, parsing, timeutil, toolio, board, validation, synthesis, leads,
    lead_model, observation, interpretation, nodes_loop, nodes_flow, builder,
)

_submodules = [
    state, sanitize, parsing, timeutil, toolio, board, validation, synthesis, leads,
    lead_model, observation, interpretation, nodes_loop, nodes_flow, builder,
]
for _m in _submodules:
    for _n in dir(_m):
        if not _n.startswith("__"):
            globals()[_n] = getattr(_m, _n)
del _m, _n, _submodules
