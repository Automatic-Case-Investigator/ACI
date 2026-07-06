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
  * Teardown: the AIT data is historical (2022), so the cleanest reset is dropping the
    dated benchmark indices.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


def run(scenario: str, preprocessed_dir: str | Path, output_url: str) -> dict:
    if shutil.which("elasticdump") is None:
        raise RuntimeError("elasticdump not found on PATH; install with `npm install -g elasticdump`")
    infile = Path(preprocessed_dir) / f"{scenario}_wazuh.json"
    if not infile.exists():
        raise FileNotFoundError(infile)
    cmd = ["elasticdump", "--type=data", f"--input={infile}", f"--output={output_url}"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"elasticdump failed ({proc.returncode}): {proc.stderr[-2000:]}")
    return {"scenario": scenario, "input": str(infile), "stdout_tail": proc.stdout[-2000:]}


def teardown(base_url: str, index_pattern: str = "wazuh-alerts-4.x-2022-*") -> int:
    """Drop the dated benchmark indices. Returns the HTTP status."""
    import httpx

    r = httpx.delete(f"{base_url.rstrip('/')}/{index_pattern}", verify=False, timeout=60)
    return r.status_code
