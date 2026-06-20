from __future__ import annotations

from django.conf import settings


def _home() -> str:
    return f"/home/{settings.AVFS_AGENT_ID}"


def home_dir() -> str:
    """The agent's AVFS home directory (the `~` referenced in prompts)."""
    return _home()


def memory_dir() -> str:
    """Long-term, cross-case memory: learned patterns, false positives, baselines."""
    return f"{_home()}/memory"


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
