from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from benchmark.pipeline import load_thehive


class _Hive:
    def __init__(self):
        self.queried_tags = []
        self.deleted = []
        self.pages = [
            [{"_id": "tag-id"}],
        ]

    def _query(self, ops):
        tag = ops[1]["_value"]
        self.queried_tags.append(tag)
        return self.pages.pop(0) if self.pages else []

    def delete_alert(self, alert_id):
        self.deleted.append(alert_id)
        return True


class _CreateHive:
    def __init__(self):
        self.created_refs = []

    def create_alert(self, alert):
        self.created_refs.append(alert["sourceRef"])
        return "created", f"id-{alert['sourceRef']}"


class TheHiveTeardownTest(unittest.TestCase):
    def test_run_imports_alerts_with_thread_pool_and_writes_manifest(self):
        hive = _CreateHive()
        rows = [({"ref": f"r{i}"}, {}) for i in range(4)]

        def fake_to_alert(src, _run_tag, _label):
            return {"sourceRef": src["ref"]}

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "fox_wazuh.json").write_text("", encoding="utf-8")
            with patch.object(load_thehive._th, "load_labels", return_value={}), \
                    patch.object(load_thehive._th, "selected_alerts", return_value=rows), \
                    patch.object(load_thehive._th, "to_alert", side_effect=fake_to_alert), \
                    patch.object(load_thehive._th, "TheHive", return_value=hive):
                result = load_thehive.run(
                    "fox",
                    root,
                    tag="run-1",
                    manifest_dir=root / "manifests",
                    url="u",
                    api_key="k",
                    progress=False,
                    workers=2,
                )

            manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))

        self.assertEqual(result["created"], 4)
        self.assertEqual(result["errors"], 0)
        self.assertEqual(set(hive.created_refs), {f"r{i}" for i in range(4)})
        self.assertEqual(set(manifest["alert_ids"]), {f"id-r{i}" for i in range(4)})
        self.assertEqual(
            {row["sourceRef"]: row["id"] for row in manifest["alerts"]},
            {f"r{i}": f"id-r{i}" for i in range(4)},
        )

    def test_teardown_uses_manifest_ids_without_tag_lookup(self):
        hive = _Hive()
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "thehive_manifest.run-1.json"
            manifest.write_text(json.dumps({"alert_ids": ["a1", "a2", "a1"]}), encoding="utf-8")

            with patch.object(load_thehive, "_resolve_connection", return_value=("u", "k", True)), \
                    patch.object(load_thehive._th, "TheHive", return_value=hive):
                deleted = load_thehive.teardown("run-1", manifest_path=manifest, progress=False)

        self.assertEqual(deleted, 2)
        self.assertEqual(hive.deleted, ["a1", "a2"])
        self.assertEqual(hive.queried_tags, [])

    def test_teardown_falls_back_to_tag_lookup_without_manifest(self):
        hive = _Hive()
        with patch.object(load_thehive, "_resolve_connection", return_value=("u", "k", True)), \
                patch.object(load_thehive._th, "TheHive", return_value=hive):
            deleted = load_thehive.teardown("run-1", progress=False)

        self.assertEqual(deleted, 1)
        self.assertEqual(hive.deleted, ["tag-id"])
        self.assertEqual(hive.queried_tags, ["ait-import-run:run-1"])

    def test_teardown_accumulates_paged_tag_lookup(self):
        hive = _Hive()
        hive.pages = [
            [{"_id": f"a{i}"} for i in range(500)],
            [{"_id": "last"}],
        ]
        with patch.object(load_thehive, "_resolve_connection", return_value=("u", "k", True)), \
                patch.object(load_thehive._th, "TheHive", return_value=hive):
            deleted = load_thehive.teardown("run-1", progress=False)

        self.assertEqual(deleted, 501)
        # Deletion is parallel, so ORDER is not guaranteed — assert the full set instead.
        self.assertEqual(set(hive.deleted), {f"a{i}" for i in range(500)} | {"last"})
        self.assertEqual(hive.queried_tags, ["ait-import-run:run-1", "ait-import-run:run-1"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
