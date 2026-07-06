"""Stage 5 — runner: submit N independent trials per entry point.

For a scenario's entry points, launches N headless agent runs each and writes each
run's report + verdict + metadata to
data/runs/<scenario>/<entry_point>/<trial>/{report.md, verdict.json, meta.json}.

Uses the same synchronous dispatch the REST API uses (`run_agent_sync`) after creating
an `AgentRun`. Trials are isolated by run_id (queue + board are run_id-scoped), so no
manual DB reset is needed between trials. Django is set up lazily so the scoring path
stays import-light.
"""
from __future__ import annotations

import json
import os
from pathlib import Path


def _django_setup():
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
    import django

    django.setup()


def _question_for(entry_point) -> str:
    if entry_point.case_id:
        return f"Triage and investigate case {entry_point.case_id}."
    if entry_point.anchor_event_id:
        return (
            f"Investigate the activity around event {entry_point.anchor_event_id} "
            f"and establish the full attack chain."
        )
    raise ValueError(f"entry point {entry_point.id!r} has neither case_id nor anchor_event_id")


def run(scenario: str, entry_point_id: str, trials: int, out_dir: str | Path,
        agent_name: str = "investigation") -> list[str]:
    _django_setup()
    from agent.models import AgentRun
    from agent.runtime.engine.run import run_agent_sync
    from ..scoring import ScenarioSpec
    from .score import scenario_spec_path

    spec = ScenarioSpec.from_yaml(scenario_spec_path(scenario))
    entry = next((e for e in spec.entry_points if e.id == entry_point_id), None)
    if entry is None:
        raise KeyError(f"entry point {entry_point_id!r} not in scenario {scenario!r}")
    case_id = entry.case_id or ""
    question = _question_for(entry)

    run_ids: list[str] = []
    for trial in range(1, trials + 1):
        run = AgentRun.objects.create(
            case_id=case_id, agent_name=agent_name, question=question, trigger="benchmark",
        )
        run_agent_sync(str(run.id), agent_name, case_id, question)  # blocks until done
        run.refresh_from_db()

        trial_dir = Path(out_dir) / scenario / entry_point_id / str(trial)
        trial_dir.mkdir(parents=True, exist_ok=True)
        (trial_dir / "report.md").write_text(run.result or "", encoding="utf-8")
        (trial_dir / "verdict.json").write_text(json.dumps(run.verdict or {}), encoding="utf-8")
        (trial_dir / "meta.json").write_text(json.dumps({
            "run_id": str(run.id), "scenario": scenario, "entry_point": entry_point_id,
            "trial": trial, "status": run.status, "agent_name": agent_name,
        }, indent=2), encoding="utf-8")
        run_ids.append(str(run.id))
    return run_ids
