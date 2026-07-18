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
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from ..progress import Progress, Spinner
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
        if not url:
            url = (s.get("base_url") or "").strip()
            if not url and s.get("host"):
                url = f"{s['host'].rstrip('/')}:{s.get('port', '9000')}"
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
    progress: bool | None = None,
    workers: int = 32,
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
    records: list[dict] = []
    bar = Progress(f"load-thehive {scenario}", len(alerts), enabled=progress)
    try:
        if alerts:
            max_workers = max(1, min(workers, len(alerts)))
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = {pool.submit(hive.create_alert, alert): alert for alert in alerts}
                for fut in as_completed(futures):
                    alert = futures[fut]
                    status, info = fut.result()
                    if status in ("created", "exists"):
                        created += status == "created"
                        existed += status == "exists"
                        if info:
                            ids.append(info)
                            records.append({
                                "id": info,
                                "sourceRef": alert.get("sourceRef", ""),
                                "date": alert.get("date"),
                                "title": alert.get("title", ""),
                                "tags": alert.get("tags") or [],
                            })
                    else:
                        errors += 1
                    bar.advance(extra=f"created={created} exists={existed} errors={errors}")
    finally:
        bar.close(extra=f"created={created} exists={existed} errors={errors}")

    manifest_dir = Path(manifest_dir) if manifest_dir else preprocessed_dir.parent / "manifests"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest = manifest_dir / f"thehive_manifest.{run_id}.json"
    manifest.write_text(json.dumps({
        "run_id": run_id, "tag": run_tag, "scenario": scenario,
        "created": created, "existed": existed, "errors": errors,
        "alert_ids": ids, "alerts": records,
    }, indent=2), encoding="utf-8")
    return {"run_id": run_id, "tag": run_tag, "selected": len(alerts),
            "created": created, "existed": existed, "errors": errors, "manifest": str(manifest)}


def _ids_by_tag_with_progress(hive, tag: str, progress: Progress) -> list[str]:
    ids: list[str] = []
    page = 0
    while True:
        progress.update(len(ids), extra=f"querying tag page={page} found={len(ids)}", force=True)
        with Spinner(progress, f"querying tag page={page} found={len(ids)}"):
            if hasattr(hive, "_query"):
                res = hive._query([
                    {"_name": "listAlert"},
                    {"_name": "filter", "_field": "tags", "_value": tag},
                    {"_name": "page", "from": page, "to": page + 500, "extraData": []},
                ])
            else:
                res = [{"_id": i} for i in hive.ids_by_tag(tag)]
        if not res:
            break
        ids.extend(a["_id"] for a in res)
        ids = list(dict.fromkeys(ids))
        progress.update(len(ids), extra=f"found={len(ids)} page={page}", force=True)
        if len(res) < 500 or not hasattr(hive, "_query"):
            break
        page += 500
    return ids


def teardown(tag: str, *, url: str | None = None, api_key: str | None = None,
             verify_tls: bool = True, progress: bool | None = None,
             manifest_path: str | Path | None = None, workers: int = 32) -> int:
    if not (url and api_key):
        url, api_key, verify_tls = _resolve_connection()
    hive = _th.TheHive(url, api_key, verify=verify_tls)
    full_tag = tag if tag.startswith(_th.RUN_TAG_PREFIX) else _th.RUN_TAG_PREFIX + tag

    # Prefer the manifest's stored alert ids — they are recorded at load time, so the slow
    # paged tag-discovery query is skipped entirely. Only fall back to discovery when no
    # (usable) manifest is available.
    ids: list[str] = []
    manifest_note = ""
    if manifest_path:
        manifest = Path(manifest_path)
        if manifest.exists():
            data = json.loads(manifest.read_text(encoding="utf-8"))
            ids = list(dict.fromkeys(data.get("alert_ids") or []))
            manifest_note = f"manifest ids={len(ids)}"
        else:
            manifest_note = f"manifest missing: {manifest}"
    discover = Progress(f"discover-thehive {tag}", enabled=progress)
    if manifest_note:
        discover.update(len(ids), extra=manifest_note, force=True)
    if not ids:
        ids = _ids_by_tag_with_progress(hive, full_tag, discover)
    discover.close(extra=f"found={len(ids)}")

    # Delete in parallel: each delete is an independent DELETE request, and requests.Session
    # is safe across threads, so a small pool cuts wall-clock time by ~`workers`x.
    deleted = 0
    bar = Progress(f"teardown-thehive {tag}", len(ids), enabled=progress)
    try:
        if ids:
            with ThreadPoolExecutor(max_workers=max(1, min(workers, len(ids)))) as pool:
                for ok in pool.map(hive.delete_alert, ids):
                    deleted += bool(ok)
                    bar.advance(extra=f"deleted={deleted}")
    finally:
        bar.close(extra=f"deleted={deleted}")
    return deleted
