"""Mandatory post-tool reasoning for specialist agent tasks (the `interpret` node).

After every tool batch the `interpret` node normalizes the observation, updates a
compact per-task ledger, and decides the next action category. The ledger is the
durable memory that survives message compaction: `think` rebuilds the next prompt
from it, and the report writer reads its assimilated evidence at wrap-up.

The ledger deliberately keeps ONE field per concept (no parallel progress /
next-step / evidence-memory encodings): control flow keys only on `next_action`
plus the returned `status`; every other field is prose context for the model.

This package was split from a single ~1800-line module along its concern seams
(`_const`, `ledger`, `pivots`, `decisions`, `prompt`, `node`). Every public and
private name is re-exported here so the historical
`from agent.runtime.graph.interpretation import X` access pattern (used across the
runtime and the test suite) keeps working unchanged. Contributor rule: submodules
own the names; this `__init__` only re-exports them.
"""
from . import _const, ledger, pivots, decisions, prompt, node

_submodules = [_const, ledger, pivots, decisions, prompt, node]
for _m in _submodules:
    for _n in dir(_m):
        if not _n.startswith("__"):
            globals()[_n] = getattr(_m, _n)
del _m, _n, _submodules
