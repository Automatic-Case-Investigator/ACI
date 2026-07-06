"""Findings Board provider (stdio subprocess)."""
from __future__ import annotations

import sys

from django.conf import settings

from .base import KIND_UTILITY, MCPProvider
from .registry import register


def _defaults() -> dict:
    return {"db_path": getattr(settings, "BOARD_DB_PATH", str(settings.BASE_DIR / "board.db"))}


def _build(resolved: dict, run_ctx: dict | None = None) -> dict:
    env = {"BOARD_DB_PATH": str(resolved["db_path"])}
    if run_ctx:
        if run_ctx.get("case_id"):
            env["ACI_CASE_ID"] = str(run_ctx["case_id"])
        if run_ctx.get("run_id"):
            env["ACI_RUN_ID"] = str(run_ctx["run_id"])
        if run_ctx.get("agent_name"):
            env["ACI_AGENT_NAME"] = str(run_ctx["agent_name"])
    return {
        "command": sys.executable,
        "args": ["-m", "aci_board.server"],
        "transport": "stdio",
        "env": env,
    }


register(MCPProvider(
    key="aci-board",
    kind=KIND_UTILITY,
    setting_defaults=_defaults,
    build_config=_build,
    capabilities={
        "board_read_findings": ("list_entries",),
        "board_write_findings": ("add_entry",),
    },
))
