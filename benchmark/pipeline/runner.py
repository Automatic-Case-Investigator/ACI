"""Stage 5 — runner: submit N independent trials per entry point.

For a scenario's entry points, launches N headless agent runs each and writes each
run's report + verdict + metadata to
data/runs/<scenario>/<entry_point>/<trial>/{report.md, verdict.json, meta.json}.

Uses the same live-session entry point as the dashboard, then waits for that session to
finish. Trials are isolated by the specialist run_id created inside the session, so no
manual DB reset is needed between trials. Django is set up lazily so the scoring path
stays import-light.

Each trial's `meta.json` includes a `tokens` block (summed input/output tokens and model
calls) captured via a LangChain callback attached to the model — so a calibration run
(`--trials 1`) yields an exact per-run token count for cost estimation.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import asyncio
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

try:
    from langchain_core.callbacks import AsyncCallbackHandler
except ModuleNotFoundError:  # keeps lightweight unit tests importable without LangChain
    class AsyncCallbackHandler:  # type: ignore[no-redef]
        pass


def _django_setup():
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
    import django

    django.setup()


class _TokenUsage(AsyncCallbackHandler):
    """Sums input/output tokens across every model call in a run.

    Async handler because the runtime invokes the model exclusively via `ainvoke`/
    `astream`; the async callback path fires `on_llm_end` natively. Reads `usage_metadata`
    off each generation's message (the same source `toolio._extract_input_tokens` uses),
    with `llm_output.token_usage` as a fallback.
    """

    def __init__(self) -> None:
        self.input = 0
        self.output = 0
        self.calls = 0
        self.by_session: dict[str, dict[str, int]] = {}

    def _accumulate(self, response) -> None:  # noqa: ANN001
        from agent.runtime.infra import logbus

        session_id = logbus.current_session() or ""
        counted = False
        input_tokens = output_tokens = calls = 0
        for generations in getattr(response, "generations", None) or []:
            for gen in generations:
                msg = getattr(gen, "message", None)
                usage = getattr(msg, "usage_metadata", None) if msg is not None else None
                if isinstance(usage, dict) and (usage.get("input_tokens") or usage.get("output_tokens")):
                    input_tokens += int(usage.get("input_tokens") or 0)
                    output_tokens += int(usage.get("output_tokens") or 0)
                    calls += 1
                    counted = True
        if not counted:
            token_usage = (getattr(response, "llm_output", None) or {}).get("token_usage") or {}
            if token_usage:
                input_tokens += int(token_usage.get("prompt_tokens") or token_usage.get("input_tokens") or 0)
                output_tokens += int(token_usage.get("completion_tokens") or token_usage.get("output_tokens") or 0)
                calls += 1
        if not calls:
            return
        self.input += input_tokens
        self.output += output_tokens
        self.calls += calls
        if session_id:
            bucket = self.by_session.setdefault(session_id, {"input": 0, "output": 0, "model_calls": 0})
            bucket["input"] += input_tokens
            bucket["output"] += output_tokens
            bucket["model_calls"] += calls

    async def on_llm_end(self, response, **kwargs) -> None:  # noqa: ANN001
        self._accumulate(response)


@contextmanager
def _capture_tokens():
    """Attach a token-usage callback to the model for the duration of one run.

    Patches `build_model` in the run module's namespace (it imported the name directly),
    so every model the run builds carries the callback. Fully restored on exit.
    """
    from agent.runtime.engine import run as _run_module
    from agent.runtime.orchestrator import driver as _orch_driver

    handler = _TokenUsage()
    originals = {
        _run_module: _run_module.build_model,
        _orch_driver: _orch_driver.build_model,
    }

    async def _patched_build_model():
        model = await originals[_run_module]()
        callbacks = list(getattr(model, "callbacks", None) or [])
        callbacks.append(handler)
        model.callbacks = callbacks
        return model

    async def _patched_orch_build_model():
        model = await originals[_orch_driver]()
        callbacks = list(getattr(model, "callbacks", None) or [])
        callbacks.append(handler)
        model.callbacks = callbacks
        return model

    _run_module.build_model = _patched_build_model
    _orch_driver.build_model = _patched_orch_build_model
    try:
        yield handler
    finally:
        _run_module.build_model = originals[_run_module]
        _orch_driver.build_model = originals[_orch_driver]


def _question_for(entry_point, alert_id: str | None = None, anchor_iso: str | None = None) -> str:
    """Build the triage question from a resolved TheHive ALERT id only.

    A TheHive *Case* is not a reliable target: only one alert (Fox's recon) has ever
    been promoted to a Case, and Cases are not recreated automatically on re-import —
    so anchoring an entry point to a case_id would silently break after every
    teardown/reload. A raw AMiner/Wazuh source id ("anchor_event_id") is not
    agent-actionable either: it is a matching key `_resolve_entry_alert` uses to find
    the live alert, not something the triage agent's tools (get_alert/get_case) can
    look up directly. The only identifier that is both reproducible across reloads and
    directly usable by the agent is the resolved live alert id.

    When a reliable incident timestamp is known (`anchor_iso`), it is stated as a
    neutral hint. A real SOAR alert carries its own occurrence time; surfacing it just
    restores that context the harness would otherwise strip. It is phrased as an
    approximate anchor, not a hard bound — how to widen/narrow the window is the
    agent's existing methodology, not something to prescribe here.
    """
    if alert_id:
        question = f"Triage and investigate alert {alert_id}."
        if anchor_iso:
            question += f" The alert corresponds to activity observed around {anchor_iso}."
        return question
    raise ValueError(
        f"entry point {entry_point.id!r}: no matching TheHive alert found for scenario "
        f"data currently loaded. Run `load-thehive --scenario <scenario>` to (re)load "
        f"the dataset, then retry."
    )


def _log(message: str, sink: Callable[[str], None] | None) -> None:
    if sink is not None:
        sink(message)


def _format_elapsed(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, sec = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h{minutes:02d}m{sec:02d}s"
    return f"{minutes}m{sec:02d}s"


def stderr_logger(message: str) -> None:
    print(f"[benchmark {datetime.now().strftime('%H:%M:%S')}] {message}", file=sys.stderr, flush=True)


@dataclass(frozen=True)
class _TrialSpec:
    scenario: str
    entry_point_id: str
    trial: int
    trials: int
    agent_name: str
    question: str
    alert_record: dict
    anchor_iso: str | None
    entry: object


@dataclass(frozen=True)
class _TrialResult:
    entry_point_id: str
    trial: int
    session_id: str


def _parse_anchor_ts(value: str | None) -> int | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.astimezone(timezone.utc).timestamp() * 1000)


def _epoch_ms_to_iso(value) -> str | None:  # noqa: ANN001
    """Epoch milliseconds → canonical ISO-8601 UTC (`...Z`), or None if not numeric."""
    try:
        ms = int(value)
    except (TypeError, ValueError):
        return None
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _resolve_anchor_iso(entry_point, alert_record: dict) -> str | None:
    """Best available incident timestamp (ISO-8601 UTC) to hand the agent as its time
    anchor.

    Precedence: the entry point's explicit `anchor_timestamp` from the scenario spec,
    else the resolved alert's `date` — the epoch-ms of the original event `@timestamp`
    preserved at import (see `_vendor/ait_thehive.epoch_ms`), NOT the import time. Both
    branches are normalised through the same epoch→ISO formatter so the emitted form is
    canonical. Returns None when neither is available, in which case the caller omits
    the time hint rather than inventing one.
    """
    configured = getattr(entry_point, "anchor_timestamp", None)
    if configured:
        return _epoch_ms_to_iso(_parse_anchor_ts(configured))
    return _epoch_ms_to_iso(alert_record.get("date"))


def _latest_manifest(scenario: str, data_root: Path) -> Path | None:
    manifests = data_root / "manifests"
    candidates: list[Path] = []
    for path in manifests.glob("thehive_manifest.*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if data.get("scenario") == scenario:
            candidates.append(path)
    return max(candidates, key=lambda p: p.stat().st_mtime) if candidates else None


def _records_from_manifest(path: Path | None) -> tuple[str, list[dict]]:
    if path is None or not path.exists():
        return "", []
    data = json.loads(path.read_text(encoding="utf-8"))
    records = [r for r in data.get("alerts") or [] if isinstance(r, dict)]
    return str(data.get("tag") or ""), records


def _query_alert_records_by_tag(tag: str) -> list[dict]:
    if not tag:
        return []
    from . import load_thehive

    url, api_key, verify_tls = load_thehive._resolve_connection()
    hive = load_thehive._th.TheHive(url, api_key, verify=verify_tls)
    records: list[dict] = []
    page = 0
    while True:
        res = hive._query([
            {"_name": "listAlert"},
            {"_name": "filter", "_field": "tags", "_value": tag},
            {"_name": "page", "from": page, "to": page + 500, "extraData": []},
        ])
        if not res:
            break
        for alert in res:
            records.append({
                "id": alert.get("_id") or alert.get("id") or "",
                "sourceRef": alert.get("sourceRef") or "",
                "date": alert.get("date"),
                "title": alert.get("title") or "",
                "tags": alert.get("tags") or [],
            })
        if len(res) < 500:
            break
        page += 500
    return records


def _alert_record(alert: dict) -> dict:
    return {
        "id": alert.get("_id") or alert.get("id") or "",
        "sourceRef": alert.get("sourceRef") or "",
        "date": alert.get("date"),
        "title": alert.get("title") or "",
        "tags": alert.get("tags") or [],
    }


def _query_alert_records_for_entry(entry_point) -> list[dict]:
    from . import load_thehive

    tag = ""
    if getattr(entry_point, "anchor_rule_id", None):
        tag = f"rule={entry_point.anchor_rule_id}"
    elif getattr(entry_point, "anchor_agent_id", None):
        tag = f"agent_id={entry_point.anchor_agent_id}"
    else:
        tag = load_thehive._th.IMPORT_TAG

    url, api_key, verify_tls = load_thehive._resolve_connection()
    hive = load_thehive._th.TheHive(url, api_key, verify=verify_tls)
    records: list[dict] = []
    page = 0
    while True:
        res = hive._query([
            {"_name": "listAlert"},
            {"_name": "filter", "_field": "tags", "_value": tag},
            {"_name": "page", "from": page, "to": page + 500, "extraData": []},
        ])
        if not res:
            break
        records.extend(_alert_record(alert) for alert in res)
        if len(res) < 500:
            break
        page += 500
    return records


def _query_alert_by_source_ref(source_ref: str) -> dict:
    if not source_ref:
        return {}
    from . import load_thehive

    url, api_key, verify_tls = load_thehive._resolve_connection()
    hive = load_thehive._th.TheHive(url, api_key, verify=verify_tls)
    alert_id = hive._find_id("wazuh_alert", source_ref)
    if not alert_id:
        return {}
    return {"id": alert_id, "sourceRef": source_ref}


def _tag_value(tags: list, prefix: str) -> str:
    for tag in tags or []:
        text = str(tag)
        if text.startswith(prefix):
            return text[len(prefix):]
    return ""


def _entry_source_ref(entry_point) -> str:
    return (
        getattr(entry_point, "anchor_source_ref", None)
        or getattr(entry_point, "anchor_event_id", None)
        or ""
    )


def _matches_entry(record: dict, entry_point) -> bool:
    source_ref = _entry_source_ref(entry_point)
    if source_ref and str(record.get("sourceRef") or "") == str(source_ref):
        return True

    anchor_ms = _parse_anchor_ts(getattr(entry_point, "anchor_timestamp", None))
    if anchor_ms is None:
        return False
    try:
        record_ms = int(record.get("date"))
    except (TypeError, ValueError):
        return False
    if abs(record_ms - anchor_ms) > 1000:
        return False
    tags = record.get("tags") or []
    rule_id = getattr(entry_point, "anchor_rule_id", None)
    agent_id = getattr(entry_point, "anchor_agent_id", None)
    if rule_id and _tag_value(tags, "rule=") != str(rule_id):
        return False
    if agent_id and _tag_value(tags, "agent_id=") != str(agent_id):
        return False
    return True


def _candidate_distance(record: dict, entry_point) -> int | None:
    source_ref = _entry_source_ref(entry_point)
    if source_ref and str(record.get("sourceRef") or "") == str(source_ref):
        return 0
    tags = record.get("tags") or []
    rule_id = getattr(entry_point, "anchor_rule_id", None)
    agent_id = getattr(entry_point, "anchor_agent_id", None)
    if rule_id and _tag_value(tags, "rule=") != str(rule_id):
        return None
    if agent_id and _tag_value(tags, "agent_id=") != str(agent_id):
        return None
    anchor_ms = _parse_anchor_ts(getattr(entry_point, "anchor_timestamp", None))
    if anchor_ms is None:
        return 0 if (rule_id or agent_id) else None
    try:
        return abs(int(record.get("date")) - anchor_ms)
    except (TypeError, ValueError):
        return None


def _resolve_entry_alert(entry_point, scenario: str, data_root: Path) -> dict:
    """Find the live TheHive ALERT matching this entry point (never a Case — see
    `_question_for`). Tries, in order: the latest load-thehive manifest's recorded
    records, a live query by that manifest's run tag, a live query by the entry's
    rule/agent tag, and a direct sourceRef lookup.

    Query failures (TheHive unreachable/auth) are tracked and re-raised rather than
    swallowed into an empty result — so a connectivity problem surfaces distinctly
    from "TheHive is reachable but this scenario's data is not loaded," which the
    caller (run(), via `_question_for`) reports with a different, actionable message.
    """
    query_error: Exception | None = None
    tag, records = _records_from_manifest(_latest_manifest(scenario, data_root))
    if not records and tag:
        try:
            records = _query_alert_records_by_tag(tag)
        except Exception as exc:  # noqa: BLE001
            query_error = exc
    if not records:
        try:
            records = _query_alert_records_for_entry(entry_point)
        except Exception as exc:  # noqa: BLE001
            query_error = query_error or exc
            records = []
    for record in records:
        if _matches_entry(record, entry_point) and record.get("id"):
            return record
    candidates = [
        (distance, record)
        for record in records
        for distance in [_candidate_distance(record, entry_point)]
        if distance is not None and record.get("id")
    ]
    if candidates:
        return min(candidates, key=lambda item: item[0])[1]
    source_ref = _entry_source_ref(entry_point)
    if source_ref:
        try:
            found = _query_alert_by_source_ref(source_ref)
            if found:
                return found
        except Exception as exc:  # noqa: BLE001
            query_error = query_error or exc
    if query_error is not None:
        raise RuntimeError(
            f"TheHive alert lookup failed for entry point {entry_point.id!r}: {query_error}"
        ) from query_error
    return {}


def _terminal_statuses(AgentRun) -> set[str]:  # noqa: ANN001
    return {
        AgentRun.STATUS_COMPLETED,
        AgentRun.STATUS_INCOMPLETE_BUDGET,
        AgentRun.STATUS_CANCELLED,
        AgentRun.STATUS_BLOCKED,
        AgentRun.STATUS_FAILED,
    }


def _wait_for_session(session_id: str, timeout_secs: int | float | None, *, AgentRun, is_processing) -> object:  # noqa: ANN001
    terminal = _terminal_statuses(AgentRun)
    started = time.monotonic()
    while True:
        run = AgentRun.objects.filter(id=session_id).first()
        if run is not None and run.status in terminal and not is_processing(session_id):
            return run
        if timeout_secs and time.monotonic() - started > timeout_secs:
            if run is not None:
                meta = dict(run.metadata or {})
                meta["benchmark_timeout_secs"] = timeout_secs
                run.metadata = meta
                run.status = AgentRun.STATUS_CANCELLED
                run.save(update_fields=["status", "metadata", "updated_at"])
            raise TimeoutError(f"benchmark session {session_id} timed out after {timeout_secs}s")
        time.sleep(1.0)


def _session_children(session_id: str, AgentRun) -> list:  # noqa: ANN001
    try:
        return list(AgentRun.objects.filter(metadata__session_id=session_id).order_by("-updated_at", "-created_at"))
    except Exception:
        return [
            run for run in AgentRun.objects.exclude(agent_name="orchestrator").order_by("-updated_at")[:200]
            if (run.metadata or {}).get("session_id") == session_id
        ]


def _report_run_for_session(session_run, children: list, agent_name: str):  # noqa: ANN001
    preferred = [
        run for run in children
        if run.agent_name == agent_name and (run.result or "").strip()
    ]
    if preferred:
        return preferred[0]
    with_result = [run for run in children if (run.result or "").strip()]
    if with_result:
        return with_result[0]
    return session_run


# ── Trial integrity ──────────────────────────────────────────────────────────
# A trial is only valid when the REQUESTED agent (e.g. investigation) actually ran
# to a result. An infra failure that falls back to the triage report must not be
# scored as a real (low-recall) trial — retry on transient errors, else mark invalid
# so aggregation excludes it. Deterministic validation; no bearing on agent reasoning.
_MAX_TRIAL_RETRIES = 2
_RESULT_STATUSES = frozenset({"completed", "incomplete_budget"})
_TRANSIENT_ERROR_RE = re.compile(
    r"connection error|connection reset|timed out|timeout|rate limit|overloaded|"
    r"temporarily unavailable|service unavailable|\b(429|500|502|503|504)\b",
    re.IGNORECASE,
)


def _target_run(children: list, agent_name: str):  # noqa: ANN001
    """The run for the REQUESTED agent (not a fallback), or None if it never ran."""
    matches = [r for r in children if r.agent_name == agent_name]
    return matches[0] if matches else None


def _trial_produced_result(target) -> bool:  # noqa: ANN001
    """Valid trial: the requested agent reached a result-bearing terminal state."""
    return (
        target is not None
        and getattr(target, "status", None) in _RESULT_STATUSES
        and bool((getattr(target, "result", "") or "").strip())
    )


def _is_transient_failure(target) -> bool:  # noqa: ANN001
    if target is None or getattr(target, "status", None) != "failed":
        return False
    return bool(_TRANSIENT_ERROR_RE.search(getattr(target, "error", "") or ""))


def _prepare_trial_specs(
    scenario: str,
    entry_point_ids: list[str],
    trials: int,
    out_dir: str | Path,
    agent_name: str,
    log: Callable[[str], None] | None,
) -> list[_TrialSpec]:
    from ..scoring import ScenarioSpec
    from .score import scenario_spec_path

    spec = ScenarioSpec.from_yaml(scenario_spec_path(scenario))
    entries = {e.id: e for e in spec.entry_points}
    data_root = Path(out_dir).parent

    prepared: list[_TrialSpec] = []
    for entry_point_id in entry_point_ids:
        entry = entries.get(entry_point_id)
        if entry is None:
            raise KeyError(f"entry point {entry_point_id!r} not in scenario {scenario!r}")
        alert_record = _resolve_entry_alert(entry, scenario, data_root)
        alert_id = str(alert_record.get("id") or "")
        anchor_iso = _resolve_anchor_iso(entry, alert_record)
        question = _question_for(entry, alert_id, anchor_iso)
        _log(
            f"entry_point={entry_point_id} trials={trials} agent={agent_name} "
            f"alert_id={alert_id or '-'} "
            f"source_ref={alert_record.get('sourceRef') or _entry_source_ref(entry) or '-'} "
            f"anchor_event_id={entry.anchor_event_id or '-'} "
            f"anchor_timestamp={anchor_iso or '-'} "
            f"question={question!r}",
            log,
        )
        for trial in range(1, trials + 1):
            prepared.append(_TrialSpec(
                scenario=scenario,
                entry_point_id=entry_point_id,
                trial=trial,
                trials=trials,
                agent_name=agent_name,
                question=question,
                alert_record=alert_record,
                anchor_iso=anchor_iso,
                entry=entry,
            ))
    return prepared


def _metadata_for_trial(spec: _TrialSpec) -> dict:
    return {
        "benchmark": {
            "scenario": spec.scenario,
            "entry_point": spec.entry_point_id,
            "trial": spec.trial,
            "agent_name": spec.agent_name,
            "alert_id": spec.alert_record.get("id") or "",
            "source_ref": spec.alert_record.get("sourceRef") or _entry_source_ref(spec.entry),
            "anchor_event_id": spec.entry.anchor_event_id or "",
            "anchor_source_ref": getattr(spec.entry, "anchor_source_ref", None) or "",
            "anchor_timestamp": spec.anchor_iso or "",
            "anchor_rule_id": getattr(spec.entry, "anchor_rule_id", None) or "",
            "anchor_agent_id": getattr(spec.entry, "anchor_agent_id", None) or "",
        }
    }


def _write_trial_artifacts(
    spec: _TrialSpec,
    out_dir: str | Path,
    session_id: str,
    session_run,  # noqa: ANN001
    report_run,  # noqa: ANN001
    target,  # noqa: ANN001  the REQUESTED agent's run (None if it never ran)
    tokens: dict[str, int],
) -> Path:
    trial_dir = Path(out_dir) / spec.scenario / spec.entry_point_id / str(spec.trial)
    trial_dir.mkdir(parents=True, exist_ok=True)
    trial_valid = _trial_produced_result(target)
    (trial_dir / "report.md").write_text(report_run.result or "", encoding="utf-8")
    (trial_dir / "verdict.json").write_text(json.dumps(report_run.verdict or {}), encoding="utf-8")
    (trial_dir / "meta.json").write_text(json.dumps({
        "run_id": str(report_run.id), "session_id": session_id,
        "live_session_url": f"/dashboard/{session_id}/",
        "scenario": spec.scenario, "entry_point": spec.entry_point_id,
        # `status` reflects the REQUESTED agent's outcome, not a fallback's — so a failed
        # investigation reads as failed, not as a completed low-recall trial.
        "trial": spec.trial,
        "status": getattr(target, "status", None) if target is not None else "missing",
        "trial_valid": trial_valid,
        "session_status": session_run.status,
        "report_agent": report_run.agent_name, "requested_agent_name": spec.agent_name,
        "alert_id": spec.alert_record.get("id") or "",
        "source_ref": spec.alert_record.get("sourceRef") or _entry_source_ref(spec.entry),
        "anchor_event_id": spec.entry.anchor_event_id or "",
        "anchor_source_ref": getattr(spec.entry, "anchor_source_ref", None) or "",
        "anchor_timestamp": spec.anchor_iso or "",
        "tokens": tokens,
    }, indent=2), encoding="utf-8")
    return trial_dir


async def _run_trial(
    spec: _TrialSpec,
    out_dir: str | Path,
    timeout_secs: int | float | None,
    usage: _TokenUsage,
    semaphore: asyncio.Semaphore,
    log: Callable[[str], None] | None,
) -> _TrialResult:
    from agent.models import AgentRun
    from agent.dashboard.runner import is_processing, start_session

    async with semaphore:
        started = time.monotonic()
        _log(
            f"start scenario={spec.scenario} entry_point={spec.entry_point_id} "
            f"trial={spec.trial}/{spec.trials}",
            log,
        )
        metadata = _metadata_for_trial(spec)
        attempt = 0
        while True:
            attempt += 1
            session_id = await asyncio.to_thread(start_session, spec.question, metadata=metadata)
            session_run = await asyncio.to_thread(
                _wait_for_session,
                session_id,
                timeout_secs,
                AgentRun=AgentRun,
                is_processing=is_processing,
            )
            children = await asyncio.to_thread(_session_children, session_id, AgentRun)
            target = _target_run(children, spec.agent_name)
            # Re-run only a transient infra failure of the requested agent; a valid
            # result, a non-transient failure, or exhausted retries all stop here.
            if (_trial_produced_result(target) or attempt > _MAX_TRIAL_RETRIES
                    or not _is_transient_failure(target)):
                break
            _log(
                f"retry scenario={spec.scenario} entry_point={spec.entry_point_id} "
                f"trial={spec.trial}/{spec.trials}: {spec.agent_name} run failed transiently "
                f"({(getattr(target, 'error', '') or '')[:60]}) — attempt {attempt}/{_MAX_TRIAL_RETRIES + 1}",
                log,
            )
        report_run = _report_run_for_session(session_run, children, spec.agent_name)
        tokens = usage.by_session.get(session_id) or {"input": 0, "output": 0, "model_calls": 0}
        trial_dir = await asyncio.to_thread(
            _write_trial_artifacts,
            spec,
            out_dir,
            session_id,
            session_run,
            report_run,
            target,
            tokens,
        )
        elapsed = _format_elapsed(time.monotonic() - started)
        _log(
            f"done scenario={spec.scenario} entry_point={spec.entry_point_id} "
            f"trial={spec.trial}/{spec.trials} session_id={session_id} "
            f"run_id={report_run.id} status={report_run.status} elapsed={elapsed} "
            f"live_ui=/dashboard/{session_id}/ "
            f"tokens=in:{tokens.get('input', 0)} out:{tokens.get('output', 0)} "
            f"calls:{tokens.get('model_calls', 0)} artifacts={trial_dir}",
            log,
        )
        return _TrialResult(spec.entry_point_id, spec.trial, session_id)


async def _run_trials_async(
    specs: list[_TrialSpec],
    out_dir: str | Path,
    timeout_secs: int | float | None,
    concurrency: int,
    usage: _TokenUsage,
    log: Callable[[str], None] | None,
) -> list[_TrialResult]:
    semaphore = asyncio.Semaphore(max(1, concurrency))
    tasks = [
        asyncio.create_task(_run_trial(spec, out_dir, timeout_secs, usage, semaphore, log))
        for spec in specs
    ]
    return await asyncio.gather(*tasks)


def run_many(
        scenario: str,
        entry_point_ids: list[str],
        trials: int,
        out_dir: str | Path,
        agent_name: str = "investigation",
        log: Callable[[str], None] | None = None,
        timeout_secs: int | float | None = None,
        concurrency: int = 4) -> dict[str, list[str]]:
    _django_setup()
    from agent.dashboard.events import install as install_dashboard_events

    install_dashboard_events()
    specs = _prepare_trial_specs(scenario, entry_point_ids, trials, out_dir, agent_name, log)

    with _capture_tokens() as usage:
        results = asyncio.run(_run_trials_async(
            specs,
            out_dir,
            timeout_secs,
            concurrency,
            usage,
            log,
        ))

    grouped: dict[str, list[tuple[int, str]]] = {ep: [] for ep in entry_point_ids}
    for result in results:
        grouped.setdefault(result.entry_point_id, []).append((result.trial, result.session_id))
    return {
        ep: [session_id for _, session_id in sorted(items)]
        for ep, items in grouped.items()
    }


def run(scenario: str, entry_point_id: str, trials: int, out_dir: str | Path,
        agent_name: str = "investigation",
        log: Callable[[str], None] | None = None,
        timeout_secs: int | float | None = None,
        concurrency: int = 4) -> list[str]:
    return run_many(
        scenario,
        [entry_point_id],
        trials,
        out_dir,
        agent_name=agent_name,
        log=log,
        timeout_secs=timeout_secs,
        concurrency=concurrency,
    )[entry_point_id]
