"""Stage 3 — load_wazuh: load the preprocessed dump into the Wazuh index via elasticdump.

The preprocessed dump is already OpenSearch-envelope shaped (each line is
`{"_index", "_id", "_score", "_source"}`), which is exactly `elasticdump`'s input
format, so this stage wraps that tool:

    elasticdump --type=data \
      --input=<preprocessed_dir>/<scenario>_wazuh.json \
      --output=https://<user>:<pass>@<wazuh-host>:9201

Prerequisite: `elasticdump` (Node: `npm install -g elasticdump`).

Notes that shape the metric/teardown design:
  * elasticdump PRESERVES each doc's `_id` from the file. The agent cites `_id`
    (`observation._EVENT_ID_KEYS` prefers it), so whether scenario `marker_event_ids`
    can ever match agent citations is decided in PREPROCESS (make `_id` deterministic),
    not here. Absent that, phase_recall matches on timestamp windows.
  * Teardown is SCENARIO-SCOPED, not a whole-index delete: the AIT scenarios are all
    2022 data, and the index name is date-derived (`wazuh-alerts-4.x-<year>-<month>-<day>`)
    with no scenario field of its own — two scenarios landing on the same calendar day
    would share an index. So teardown does a `_delete_by_query` filtered by `agent.id`
    (from the scenario's `host_map`, e.g. fox.yaml's `27`/`1`/`18`) rather than dropping
    the index outright.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time
import re
from collections import deque
from pathlib import Path

from ..progress import Progress


_ELASTICDUMP_SENT_RE = re.compile(r"\bsent\s+(\d+)\s+objects?\b", re.IGNORECASE)


def _elasticdump_command(args: list[str]) -> list[str]:
    exe = (
        shutil.which("elasticdump")
        or shutil.which("elasticdump.cmd")
        or shutil.which("elasticdump.bat")
    )
    if exe is None:
        raise RuntimeError("elasticdump not found on PATH; install with `npm install -g elasticdump`")
    if os.name == "nt" and os.path.splitext(exe)[1].lower() in {".cmd", ".bat"}:
        return [os.environ.get("COMSPEC", "cmd.exe"), "/c", exe, *args]
    return [exe, *args]


def run(scenario: str, preprocessed_dir: str | Path, output_url: str,
        progress: bool | None = None) -> dict:
    infile = Path(preprocessed_dir) / f"{scenario}_wazuh.json"
    if not infile.exists():
        raise FileNotFoundError(infile)
    cmd = _elasticdump_command(["--type=data", f"--input={infile}", f"--output={output_url}"])
    total = sum(1 for _ in infile.open("r", encoding="utf-8"))
    bar = Progress(f"load-wazuh {scenario}", total, enabled=progress)
    stdout_tail: deque[str] = deque(maxlen=80)
    sent = 0
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            stdout_tail.append(line)
            match = _ELASTICDUMP_SENT_RE.search(line)
            if match:
                sent += int(match.group(1))
                bar.update(sent, extra="elasticdump")
        returncode = proc.wait()
    finally:
        bar.close(extra=f"sent={sent}")
    stdout = "".join(stdout_tail)
    if returncode != 0:
        raise RuntimeError(f"elasticdump failed ({returncode}): {stdout[-2000:]}")
    return {"scenario": scenario, "input": str(infile), "stdout_tail": stdout[-2000:],
            "events": total, "sent": sent}


def _retry_after_seconds(response) -> float | None:
    value = response.headers.get("retry-after")
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        return None


def teardown(base_url: str, scenario: str, index_pattern: str = "wazuh-alerts-*",
             max_retries: int = 5, requests_per_second: int = -1,
             scroll_size: int = 500, slices: str | int = "auto",
             progress: bool | None = None, poll_interval: float = 1.0) -> dict:
    """Delete only this scenario's events (by `agent.id`, from its host_map), scoped to
    `index_pattern`. Falls back to a whole-index delete (with a warning) if the scenario
    has no host_map to scope by. Returns the delete_by_query response / status."""
    import httpx

    from ..scoring import ScenarioSpec
    from .score import scenario_spec_path

    spec = ScenarioSpec.from_yaml(scenario_spec_path(scenario))
    agent_ids = list(spec.host_map)
    base = base_url.rstrip("/")

    if not agent_ids:
        r = httpx.delete(f"{base}/{index_pattern}", verify=False, timeout=60)
        return {"mode": "whole_index_delete", "status_code": r.status_code, "warning":
                f"scenario {scenario!r} has no host_map; deleted ALL of {index_pattern}"}

    # ignore_unavailable / allow_no_indices: a teardown of not-yet-loaded data (no matching
    # index) is a success, not a 404 — so the "clean up first" step is safe on a fresh env.
    query = {"query": {"terms": {"agent.id": agent_ids}}}
    # slices=auto parallelizes the delete across shards server-side; requests_per_second=-1
    # lifts the throttle. Both make teardown fast (it is a bulk cleanup, not steady-state load).
    params = (
        "ignore_unavailable=true&allow_no_indices=true&conflicts=proceed"
        f"&refresh=true&slices={slices}&requests_per_second={requests_per_second}"
        f"&scroll_size={scroll_size}&wait_for_completion=false"
    )
    url = f"{base}/{index_pattern}/_delete_by_query?{params}"
    attempts = 0
    last_status = None
    while True:
        attempts += 1
        r = httpx.post(url, json=query, verify=False, timeout=120)
        last_status = r.status_code
        if r.status_code != 429:
            break
        if attempts > max_retries:
            break
        delay = _retry_after_seconds(r)
        if delay is None:
            delay = min(30.0, 2.0 ** (attempts - 1))
        time.sleep(delay)

    if last_status == 429:
        return {
            "mode": "delete_by_query",
            "scenario": scenario,
            "agent_ids": agent_ids,
            "status_code": last_status,
            "attempts": attempts,
            "error": "Wazuh returned 429 Too Many Requests after retries; rerun teardown after the cluster settles.",
        }
    if r.status_code >= 400:
        return {
            "mode": "delete_by_query",
            "scenario": scenario,
            "agent_ids": agent_ids,
            "status_code": r.status_code,
            "attempts": attempts,
            "error": r.text[-1000:],
        }
    body = r.json()
    task_id = body.get("task")
    if not task_id:
        return {"mode": "delete_by_query", "scenario": scenario, "agent_ids": agent_ids,
                "deleted": body.get("deleted"), "failures": body.get("failures"),
                "status_code": r.status_code, "attempts": attempts,
                "requests_per_second": requests_per_second, "scroll_size": scroll_size}

    bar = Progress(f"teardown-wazuh {scenario}", enabled=progress)
    task_attempts = 0
    while True:
        task_attempts += 1
        task = httpx.get(f"{base}/_tasks/{task_id}", verify=False, timeout=60)
        if task.status_code == 429 and task_attempts <= max_retries:
            delay = _retry_after_seconds(task) or min(30.0, 2.0 ** (task_attempts - 1))
            time.sleep(delay)
            continue
        if task.status_code >= 400:
            bar.close(extra=f"task_status={task.status_code}")
            return {
                "mode": "delete_by_query",
                "scenario": scenario,
                "agent_ids": agent_ids,
                "task": task_id,
                "status_code": task.status_code,
                "attempts": attempts,
                "task_attempts": task_attempts,
                "error": task.text[-1000:],
            }
        task_body = task.json()
        status = task_body.get("task", {}).get("status", {}) or {}
        deleted = int(status.get("deleted") or 0)
        total = status.get("total")
        total = int(total) if total is not None else None
        bar.update(deleted, total=total, extra=f"batches={status.get('batches', 0)}")
        if task_body.get("completed"):
            bar.close(extra=f"deleted={deleted}")
            response = task_body.get("response", {}) or {}
            return {
                "mode": "delete_by_query",
                "scenario": scenario,
                "agent_ids": agent_ids,
                "task": task_id,
                "deleted": response.get("deleted", deleted),
                "failures": response.get("failures", []),
                "status_code": r.status_code,
                "attempts": attempts,
                "task_attempts": task_attempts,
                "requests_per_second": requests_per_second,
                "scroll_size": scroll_size,
            }
        time.sleep(poll_interval)
