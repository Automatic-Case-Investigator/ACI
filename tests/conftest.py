"""Shared pytest bootstrap for the unified test tree.

Puts the project root on sys.path and configures Django once, before any test
module imports `agent.*`. Tests can also still be run as standalone scripts
(`python tests/unit/<subsystem>/test_x.py`) thanks to their own bootstrap, but
running the whole tree with `python -m pytest tests/unit tests/django` is the
supported path.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
os.environ.setdefault("SECRET_KEY", "test")

import django  # noqa: E402

django.setup()

# Connect the template-rendered signal etc. so Django TestCase response.context is
# captured when the suite is run under plain pytest (Django's own test runner does
# this via setup_test_environment(); pytest does not).
from django.test.utils import setup_test_environment  # noqa: E402

try:
    setup_test_environment()
except RuntimeError:
    pass  # already set up
