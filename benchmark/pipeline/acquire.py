"""Stage 1 — acquire: download the raw AIT-LDS dataset into data/raw/.

Driven by config/datasets.yaml. For a Zenodo dataset the record id is enough: the
Zenodo API lists the files and their md5 checksums, so download is checksum-verified
and idempotent (a file present with a matching checksum is skipped).
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import httpx

_ZENODO_API = "https://zenodo.org/api/records/{record}"


def _md5(path: Path) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _download_zenodo(record: str, dest: Path) -> list[str]:
    dest.mkdir(parents=True, exist_ok=True)
    meta = httpx.get(_ZENODO_API.format(record=record), timeout=60).raise_for_status().json()
    fetched: list[str] = []
    for entry in meta.get("files", []):
        name = entry.get("key") or entry.get("filename")
        url = entry.get("links", {}).get("self") or entry.get("links", {}).get("download")
        want = (entry.get("checksum") or "").removeprefix("md5:")
        out = dest / name
        if out.exists() and want and _md5(out) == want:
            fetched.append(f"{name} (cached)")
            continue
        with httpx.stream("GET", url, timeout=None, follow_redirects=True) as r:
            r.raise_for_status()
            with open(out, "wb") as f:
                for chunk in r.iter_bytes(1 << 20):
                    f.write(chunk)
        if want and _md5(out) != want:
            raise RuntimeError(f"checksum mismatch for {name}")
        fetched.append(name)
    return fetched


def run(datasets_config: dict, dest: str | Path) -> dict:
    dest = Path(dest)
    out: dict[str, list[str]] = {}
    for name, cfg in datasets_config.items():
        if cfg.get("source") == "zenodo" and cfg.get("record"):
            out[name] = _download_zenodo(str(cfg["record"]), dest / name)
        else:
            raise NotImplementedError(f"dataset {name!r}: only zenodo sources are supported")
    return out
