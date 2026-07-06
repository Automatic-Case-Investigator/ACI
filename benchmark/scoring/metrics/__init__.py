"""Metric plugins. Every module here is auto-imported so its `@register` runs —
adding a metric is a matter of dropping a new file in this package, nothing else.
"""
import importlib
import pkgutil

for _module in pkgutil.iter_modules(__path__):
    importlib.import_module(f"{__name__}.{_module.name}")
