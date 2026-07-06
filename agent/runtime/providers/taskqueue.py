"""Task-queue provider (stdio subprocess)."""
from __future__ import annotations

import sys

from django.conf import settings

from .base import KIND_UTILITY, MCPProvider
from .registry import register


def _defaults() -> dict:
    return {"db_path": settings.TASKQUEUE_DB_PATH}


def _build(resolved: dict, run_ctx: dict | None = None) -> dict:
    env = {"TASKQUEUE_DB_PATH": str(resolved["db_path"])}
    # Inject the run's identity so the server can OWN queue scoping — the model must
    # not be able to file tasks under the wrong case/run/agent (see server.py).
    if run_ctx:
        if run_ctx.get("case_id"):
            env["ACI_CASE_ID"] = str(run_ctx["case_id"])
        if run_ctx.get("run_id"):
            env["ACI_RUN_ID"] = str(run_ctx["run_id"])
        if run_ctx.get("agent_name"):
            env["ACI_AGENT_NAME"] = str(run_ctx["agent_name"])
    return {
        "command": sys.executable,
        "args": ["-m", "aci_taskqueue.server"],
        "transport": "stdio",
        "env": env,
    }


register(MCPProvider(
    key="aci-taskqueue",
    kind=KIND_UTILITY,
    setting_defaults=_defaults,
    build_config=_build,
    capabilities={
        "queue_read_tasks": ("list_tasks", "get_task"),
        "queue_write_tasks": ("create_task", "update_task", "claim_next", "complete_task"),
    },
))
