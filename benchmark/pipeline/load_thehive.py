"""Stage 4 — load_thehive: create TheHive alerts from the preprocessed dump.

Wraps the vendored, proven AIT import logic (`_vendor/ait_thehive.py`) with one
deliberate change — the corrected admission rule:

    admit if (rule.level >= min_level) OR (is_anomaly AND not training_mode)

(The original gated both paths on rule.level, silently dropping the AMiner markers —
almost all level 0 — and with them the webshell / privesc / service_stop phases.)
Correlation rules are collapsed as before. Every alert is tagged for tag-based teardown.

Connection resolves from the dashboard `ProviderConfig` (aci-thehive) if not passed,
falling back to THEHIVE_URL / THEHIVE_API_KEY env vars.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import uuid
from pathlib import Path

from ._vendor import ait_thehive as _th


def _resolve_connection() -> tuple[str, str, bool]:
    url = os.environ.get("THEHIVE_URL")
    key = os.environ.get("THEHIVE_API_KEY")
    verify = True
    if not (url and key):
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
        import django

        django.setup()
        from agent.models.config import ProviderConfig

        s = ProviderConfig.objects.get(key="aci-thehive").settings
        url = url or f"{s['host'].rstrip('/')}:{s.get('port', '9000')}"
        key = key or s["api_key"]
        verify = str(s.get("verify_tls", "true")).lower() == "true"
    return url, key, verify


def run(
    scenario: str,
    preprocessed_dir: str | Path,
    *,
    min_level: int = 7,
    include_anomalies: bool = True,
    tag: str | None = None,
    manifest_dir: str | Path | None = None,
    url: str | None = None,
    api_key: str | None = None,
    verify_tls: bool = True,
) -> dict:
    preprocessed_dir = Path(preprocessed_dir)
    dump = preprocessed_dir / f"{scenario}_wazuh.json"
    labels = _th.load_labels(str(preprocessed_dir / f"{scenario}_aminer.labels.json"))

    run_id = tag or (_dt.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6])
    run_tag = _th.RUN_TAG_PREFIX + run_id

    rows = _th.selected_alerts(str(dump), labels, min_level, True, 0, include_anomalies)
    alerts = [_th.to_alert(src, run_tag, lbl) for src, lbl in rows]

    if not (url and api_key):
        url, api_key, verify_tls = _resolve_connection()
    hive = _th.TheHive(url, api_key, verify=verify_tls)

    created = existed = errors = 0
    ids: list[str] = []
    for a in alerts:
        status, info = hive.create_alert(a)
        if status in ("created", "exists"):
            created += status == "created"
            existed += status == "exists"
            if info:
                ids.append(info)
        else:
            errors += 1

    manifest_dir = Path(manifest_dir) if manifest_dir else preprocessed_dir.parent / "manifests"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest = manifest_dir / f"thehive_manifest.{run_id}.json"
    manifest.write_text(json.dumps({
        "run_id": run_id, "tag": run_tag, "scenario": scenario,
        "created": created, "existed": existed, "errors": errors, "alert_ids": ids,
    }, indent=2), encoding="utf-8")
    return {"run_id": run_id, "tag": run_tag, "selected": len(alerts),
            "created": created, "existed": existed, "errors": errors, "manifest": str(manifest)}


def teardown(tag: str, *, url: str | None = None, api_key: str | None = None,
             verify_tls: bool = True) -> int:
    if not (url and api_key):
        url, api_key, verify_tls = _resolve_connection()
    hive = _th.TheHive(url, api_key, verify=verify_tls)
    full_tag = tag if tag.startswith(_th.RUN_TAG_PREFIX) else _th.RUN_TAG_PREFIX + tag
    ids = hive.ids_by_tag(full_tag)
    return sum(1 for i in ids if hive.delete_alert(i))
