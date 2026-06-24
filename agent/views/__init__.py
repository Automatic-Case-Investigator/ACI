"""Agent REST API views (runs / webhooks / public)."""
from . import public, runs, webhooks

_submodules = [public, runs, webhooks]
for _m in _submodules:
    for _n in dir(_m):
        if not _n.startswith("__"):
            globals()[_n] = getattr(_m, _n)
del _m, _n, _submodules
