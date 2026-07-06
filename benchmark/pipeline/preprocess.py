"""Stage 2 — preprocess: raw AIT dumps -> merged Wazuh+AMiner dump + labels.

Produces <out_dir>/<scenario>_wazuh.json (OpenSearch-envelope docs, Wazuh + AMiner-
derived alerts interleaved by @timestamp) and <scenario>_aminer.labels.json (the AMiner
detector metadata sidecar, keyed by the synthesized `_source.id`).

Wraps the vendored, proven AIT preprocess logic (`_vendor/ait_preprocess.py`) so the
transformation is exactly the one that produced the current dataset. Input is the raw
per-scenario dumps `<raw_dir>/<scenario>_{wazuh,aminer}.json`.

The envelope `_id` is randomized per run by `make_id()`; since load_wazuh uses elasticdump
(which preserves the file's `_id`), that random id is what the agent ends up citing.
Making `_id` deterministic to anchor ground-truth event markers is a change to the
vendored `wrap()` — see the scenario spec's marker note.
"""
from __future__ import annotations

import os
from pathlib import Path

from ._vendor import ait_preprocess as _ap


def run(scenario: str, raw_dir: str | Path, out_dir: str | Path) -> dict:
    raw_dir, out_dir = Path(raw_dir), Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    wazuh_path = raw_dir / f"{scenario}_wazuh.json"
    if not wazuh_path.exists():
        raise FileNotFoundError(wazuh_path)
    aminer_path = raw_dir / f"{scenario}_aminer.json"
    aminer = str(aminer_path) if aminer_path.exists() else None

    _ap.OUTPUT_DIR = str(out_dir)  # vendored module writes relative to this
    os.makedirs(out_dir, exist_ok=True)
    return _ap.process_prefix(scenario, str(wazuh_path), aminer)
