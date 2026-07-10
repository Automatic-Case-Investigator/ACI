from __future__ import annotations

import hashlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from zipfile import ZipFile

from benchmark.pipeline import acquire


def _zip_bytes() -> bytes:
    buf = io.BytesIO()
    with ZipFile(buf, "w") as zf:
        zf.writestr("ait_ads/fox_wazuh.json", '{"id": "fox"}\n')
        zf.writestr("ait_ads/fox_aminer.json", '{"id": "fox-aminer"}\n')
    return buf.getvalue()


class _Response:
    def __init__(self, payload=None, content: bytes = b""):
        self._payload = payload
        self._content = content

    def raise_for_status(self):
        return self

    def json(self):
        return self._payload

    def iter_bytes(self, _size):
        yield self._content

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


class AcquireTest(unittest.TestCase):
    def test_acquire_downloads_only_ait_ads_zip_and_extracts_raw_files(self):
        content = _zip_bytes()
        checksum = hashlib.md5(content).hexdigest()
        meta = {
            "files": [
                {
                    "key": "ait_ads.zip",
                    "checksum": f"md5:{checksum}",
                    "links": {"self": "https://example.test/ait_ads.zip"},
                },
                {
                    "key": "labels.csv",
                    "checksum": "md5:ignored",
                    "links": {"self": "https://example.test/labels.csv"},
                },
            ]
        }
        config = {
            "ait-ads": {
                "source": "zenodo",
                "record": "8263181",
                "files": ["ait_ads.zip"],
                "dest_subdir": ".",
                "extract": True,
                "strip_prefix": "ait_ads",
            }
        }
        stream_calls = []

        def fake_stream(method, url, **_kwargs):
            stream_calls.append((method, url))
            return _Response(content=content)

        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(acquire.httpx, "get", return_value=_Response(payload=meta)), \
                patch.object(acquire.httpx, "stream", side_effect=fake_stream):
            result = acquire.run(config, tmp)
            root = Path(tmp)

            self.assertEqual(stream_calls, [("GET", "https://example.test/ait_ads.zip")])
            self.assertIn("ait_ads.zip", result["ait-ads"])
            self.assertTrue((root / "ait_ads.zip").exists())
            self.assertTrue((root / "fox_wazuh.json").exists())
            self.assertTrue((root / "fox_aminer.json").exists())
            self.assertFalse((root / "labels.csv").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
