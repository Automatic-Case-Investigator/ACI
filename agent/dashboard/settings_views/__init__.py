"""Analyst-editable settings dashboard (split into cohesive view groups)."""
from . import rows, pages, agents, baselines, integrations

_submodules = [rows, pages, agents, baselines, integrations]
for _m in _submodules:
    for _n in dir(_m):
        if not _n.startswith("__"):
            globals()[_n] = getattr(_m, _n)
del _m, _n, _submodules
