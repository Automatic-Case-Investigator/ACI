"""SOC memory provider (stdio subprocess).

Read-only access to curated patterns, baselines, and analyst feedback. The source
of truth is the Django `agent` app tables, so this provider points the server at
Django's default SQLite database; the server opens it read-only.
"""
from __future__ import annotations

import sys

from django.conf import settings

from .base import KIND_UTILITY, MCPProvider
from .registry import register


def _default_db_path() -> str:
    db = settings.DATABASES.get("default", {})
    return str(db.get("NAME", settings.BASE_DIR / "db.sqlite3"))


def _defaults() -> dict:
    return {"db_path": _default_db_path()}


def _build(resolved: dict, run_ctx: dict | None = None) -> dict:
    env = {"ACI_MEMORY_DB_PATH": str(resolved["db_path"])}
    if run_ctx:
        if run_ctx.get("case_id"):
            env["ACI_CASE_ID"] = str(run_ctx["case_id"])
        if run_ctx.get("run_id"):
            env["ACI_RUN_ID"] = str(run_ctx["run_id"])
        if run_ctx.get("agent_name"):
            env["ACI_AGENT_NAME"] = str(run_ctx["agent_name"])
    return {
        "command": sys.executable,
        "args": ["-m", "aci_memory.server"],
        "transport": "stdio",
        "env": env,
    }


register(MCPProvider(
    key="aci-memory",
    kind=KIND_UTILITY,
    setting_defaults=_defaults,
    build_config=_build,
))
