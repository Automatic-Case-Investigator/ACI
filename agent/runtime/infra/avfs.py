from __future__ import annotations

from contextvars import ContextVar


_AVFS_AGENT_ID: ContextVar[str | None] = ContextVar("avfs_agent_id", default=None)


def bind_agent_id(agent_id: str):
    """Bind the resolved AVFS agent id for the current async run context."""
    try:
        from ..providers.avfs import cache_agent_id

        cache_agent_id(agent_id)
    except ModuleNotFoundError as exc:
        if exc.name != "django":
            raise
    return _AVFS_AGENT_ID.set(agent_id)


def reset_agent_id(token) -> None:
    _AVFS_AGENT_ID.reset(token)


def _home() -> str:
    agent_id = _AVFS_AGENT_ID.get()
    if not agent_id:
        from ..providers.avfs import resolved_agent_id

        agent_id = resolved_agent_id()
    return f"/home/{agent_id}"


def home_dir() -> str:
    """The agent's AVFS home directory (the `~` referenced in prompts)."""
    return _home()


def memory_dir() -> str:
    """Long-term, cross-case memory: learned patterns, false positives, baselines."""
    return f"{_home()}/memory"


def sessions_dir() -> str:
    """Per-run handoff notes (`<date>_<short_id>.md`) the AVFS prompt tells the agent
    to read first on start to resume prior work."""
    return f"{_home()}/sessions"


def tasks_dir() -> str:
    """Active work-in-progress notes the AVFS prompt manages under `tasks/<task_id>/`."""
    return f"{_home()}/tasks"


def knowledge_dir() -> str:
    """Reusable, long-lived knowledge by topic (`knowledge/<topic>.md`)."""
    return f"{_home()}/knowledge"


def workspace_dirs() -> list[str]:
    """The standard AVFS home folders advertised by the AVFS server prompt.

    Pre-creating these at run start makes the agent's prompt-directed reads of
    `~/sessions`, `~/tasks`, `~/memory`, `~/knowledge` return an empty listing
    instead of an ENOENT error (which previously cost a failing round-trip per task).
    """
    return [sessions_dir(), tasks_dir(), memory_dir(), knowledge_dir()]


def session_note_path(run_id: str, *, when=None) -> str:
    """Path for this run's session handoff note: `sessions/<date>_<short_id>.md`."""
    from datetime import datetime, timezone

    date = (when or datetime.now(timezone.utc)).strftime("%Y-%m-%d")
    short = (run_id or "run").split("-", 1)[0][:8]
    return f"{sessions_dir()}/{date}_{short}.md"


def case_dir(case_id: str) -> str:
    return f"{_home()}/cases/{case_id}"


def findings_dir(case_id: str) -> str:
    return f"{case_dir(case_id)}/findings"


def evidence_dir(case_id: str) -> str:
    return f"{case_dir(case_id)}/evidence"


def reports_dir(case_id: str) -> str:
    return f"{case_dir(case_id)}/reports"


def run_dir(agent_name: str, run_id: str) -> str:
    return f"{_home()}/{agent_name}/{run_id}"
