"""Django ORM models for the agent app (runs / config / learning)."""
from . import runs, config, learning

_submodules = [runs, config, learning]
for _m in _submodules:
    for _n in dir(_m):
        if not _n.startswith("__"):
            globals()[_n] = getattr(_m, _n)
del _m, _n, _submodules
