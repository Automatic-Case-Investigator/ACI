"""Stage 1 — acquire: download the raw AIT-ADS archive into data/raw/.

Driven by config/datasets.yaml. For a Zenodo dataset, the API lists the files and
their md5 checksums, so download is checksum-verified and idempotent. The benchmark
uses the single `ait_ads.zip` archive from Zenodo rather than per-scenario zips.
"""
from __future__ import annotations

import hashlib
import shutil
from pathlib import Path
from zipfile import ZipFile

import httpx

_ZENODO_API = "https://zenodo.org/api/records/{record}"


def _md5(path: Path) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _extract_zip(path: Path, dest: Path, strip_prefix: str = "") -> list[str]:
    extracted: list[str] = []
    prefix = strip_prefix.strip("/")
    with ZipFile(path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            member = Path(info.filename)
            if prefix:
                parts = member.parts
                if parts and parts[0] == prefix:
                    member = Path(*parts[1:])
            if not member.parts or any(part in {"", ".."} for part in member.parts) or member.is_absolute():
                continue
            out = dest / member
            out.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, out.open("wb") as f:
                shutil.copyfileobj(src, f)
            extracted.append(str(member))
    return extracted


def _download_zenodo(record: str, dest: Path, files: list[str] | None = None,
                     extract: bool = False, strip_prefix: str = "") -> list[str]:
    dest.mkdir(parents=True, exist_ok=True)
    meta = httpx.get(_ZENODO_API.format(record=record), timeout=60).raise_for_status().json()
    fetched: list[str] = []
    wanted = set(files or [])
    for entry in meta.get("files", []):
        name = entry.get("key") or entry.get("filename")
        if wanted and name not in wanted:
            continue
        url = entry.get("links", {}).get("self") or entry.get("links", {}).get("download")
        want = (entry.get("checksum") or "").removeprefix("md5:")
        out = dest / name
        if out.exists() and want and _md5(out) == want:
            fetched.append(f"{name} (cached)")
        else:
            with httpx.stream("GET", url, timeout=None, follow_redirects=True) as r:
                r.raise_for_status()
                with open(out, "wb") as f:
                    for chunk in r.iter_bytes(1 << 20):
                        f.write(chunk)
            if want and _md5(out) != want:
                raise RuntimeError(f"checksum mismatch for {name}")
            fetched.append(name)
        if extract and out.suffix == ".zip":
            extracted = _extract_zip(out, dest, strip_prefix=strip_prefix)
            fetched.append(f"{name} extracted ({len(extracted)} files)")
    if wanted:
        found = {item.split(" ", 1)[0] for item in fetched}
        missing = sorted(wanted - found)
        if missing:
            raise RuntimeError(f"Zenodo record {record} missing expected file(s): {missing}")
    return fetched


def run(datasets_config: dict, dest: str | Path) -> dict:
    dest = Path(dest)
    out: dict[str, list[str]] = {}
    for name, cfg in datasets_config.items():
        if cfg.get("source") == "zenodo" and cfg.get("record"):
            dataset_dest = dest / cfg.get("dest_subdir", name)
            out[name] = _download_zenodo(
                str(cfg["record"]),
                dataset_dest,
                files=cfg.get("files"),
                extract=bool(cfg.get("extract", False)),
                strip_prefix=str(cfg.get("strip_prefix", "")),
            )
        else:
            raise NotImplementedError(f"dataset {name!r}: only zenodo sources are supported")
    return out
