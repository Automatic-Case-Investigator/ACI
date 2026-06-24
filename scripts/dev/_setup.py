"""Shared Django bootstrap for the dev inspection tools.

Import this first from any script in ``scripts/dev/``:

    from _setup import django_setup
    django_setup()

It configures UTF-8 stdout (Windows cp1252 safety), puts the project root on
``sys.path``, points Django at ``aci.settings`` and calls ``django.setup()``.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Project root is two levels up from scripts/dev/_setup.py
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def django_setup() -> None:
    """Bootstrap Django so the ORM (agent.models) is importable."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass
    root = str(PROJECT_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
    import django

    django.setup()
