from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable, Iterable


class CitationValidationError(ValueError):
    pass


@dataclass(frozen=True)
class Citation:
    claim_id: str
    avfs_path: str = ""
    native_id: str = ""


def normalize_citations(raw: Iterable[dict] | dict) -> list[Citation]:
    if isinstance(raw, dict):
        items = raw.get("citations", [])
    else:
        items = raw
    citations: list[Citation] = []
    for idx, item in enumerate(items):
        if not isinstance(item, dict):
            raise CitationValidationError(f"citation {idx} must be an object")
        citations.append(Citation(
            claim_id=str(item.get("claim_id") or item.get("claim") or idx),
            avfs_path=str(item.get("avfs_path") or item.get("path") or ""),
            native_id=str(item.get("native_id") or item.get("event_id") or ""),
        ))
    return citations


def validate_citations(raw: Iterable[dict] | dict, exists: Callable[[str], bool]) -> list[dict]:
    validated: list[dict] = []
    for citation in normalize_citations(raw):
        if not citation.avfs_path and not citation.native_id:
            raise CitationValidationError(f"citation {citation.claim_id} has no AVFS path or native id")
        if citation.avfs_path and not exists(citation.avfs_path):
            raise CitationValidationError(
                f"citation {citation.claim_id} references missing AVFS path {citation.avfs_path}"
            )
        validated.append({
            "claim_id": citation.claim_id,
            "avfs_path": citation.avfs_path,
            "native_id": citation.native_id,
        })
    return validated


def render_citations_json(validated: list[dict]) -> str:
    return json.dumps({"citations": validated}, indent=2, sort_keys=True) + "\n"
