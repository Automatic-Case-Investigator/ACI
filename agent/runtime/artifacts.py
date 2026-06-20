"""Deterministic artifact extraction from retrieved event payloads."""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Artifact:
    kind: str
    value: str
    source: str = ""


_KEY_TYPES = {
    "srcip": "ip",
    "dstip": "ip",
    "src_ip": "ip",
    "dst_ip": "ip",
    "source.ip": "ip",
    "destination.ip": "ip",
    "client.ip": "ip",
    "server.ip": "ip",
    "ip": "ip",
    "sha256": "sha256",
    "file.hash.sha256": "sha256",
    "sha1": "sha1",
    "file.hash.sha1": "sha1",
    "md5": "md5",
    "file.hash.md5": "md5",
    "domain": "domain",
    "dns.question.name": "domain",
    "url.domain": "domain",
    "hostname": "host",
    "host.name": "host",
    "agent.name": "host",
    "computer_name": "host",
    "username": "user",
    "user.name": "user",
    "srcuser": "user",
    "dstuser": "user",
    "process.name": "process",
    "process.executable": "file",
    "file.path": "file",
    "target.file.path": "file",
}
# Keys whose VALUE is a shell/audit command line. The command itself is recorded
# as a `command` artifact, and file paths / IPs embedded in it are mined out as
# `file` / `ip` artifacts (these often never appear as structured fields).
_COMMAND_KEYS = (
    "command",
    "data.command",
    "audit.command",
    "data.audit.command",
    "data.audit.execve",
    "process.args",
    "process.command_line",
)
_EVENT_ID_KEYS = ("_id", "event.id", "event_id")
# Absolute file paths embedded in command strings (e.g. /var/spool/cron/crontabs/user).
_PATH_RE = re.compile(r"/(?:[\w.+-]+/)+[\w.+-]+")
# Bare IPv4/IPv6 literals embedded in command strings.
_IP_IN_TEXT_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b|\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")
# Cap how many embedded paths/IPs we mine from a single command to avoid flooding.
_MAX_EMBEDDED_PER_COMMAND = 8
_MAX_COMMAND_LEN = 512
_HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)


def _flatten(value, prefix: str = ""):
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            yield from _flatten(child, path)
    elif isinstance(value, list):
        for child in value:
            yield from _flatten(child, prefix)
    else:
        yield prefix.lower(), value


def _source_id(event: dict) -> str:
    flattened = dict(_flatten(event))
    for key in _EVENT_ID_KEYS:
        value = flattened.get(key)
        if value not in (None, ""):
            return str(value)
        for path, nested_value in flattened.items():
            if path.endswith(f".{key}") and nested_value not in (None, ""):
                return str(nested_value)
    return ""


def _normalize(kind: str, value) -> str | None:
    if not isinstance(value, (str, int)):
        return None
    text = str(value).strip()
    if not text or len(text) > 2048:
        return None
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            return None
    if kind in _HASH_LENGTHS:
        compact = text.lower()
        if len(compact) != _HASH_LENGTHS[kind] or not all(c in "0123456789abcdef" for c in compact):
            return None
        return compact
    if kind == "domain":
        candidate = text.rstrip(".").lower()
        return candidate if _DOMAIN_RE.fullmatch(candidate) else None
    return text


def _event_dicts(payload) -> list[dict]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("events", "hits", "results", "documents", "alerts"):
        items = payload.get(key)
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
        if key == "hits" and isinstance(items, dict):
            nested_hits = items.get("hits")
            if isinstance(nested_hits, list):
                return [item for item in nested_hits if isinstance(item, dict)]
    data = payload.get("data")
    if isinstance(data, (dict, list)):
        nested = _event_dicts(data)
        if nested:
            return nested
    # A single native event/document is eligible when it has an event identifier.
    return [payload] if _source_id(payload) else []


def _artifact_kind(key: str) -> str | None:
    if key in _KEY_TYPES:
        return _KEY_TYPES[key]
    matches = [
        (candidate, kind)
        for candidate, kind in _KEY_TYPES.items()
        if key.endswith(f".{candidate}")
    ]
    if not matches:
        return None
    return max(matches, key=lambda item: len(item[0]))[1]


def _is_command_key(key: str) -> bool:
    return key in _COMMAND_KEYS or any(
        key.endswith(f".{candidate}") for candidate in _COMMAND_KEYS
    )


def _mine_command(command: str, source: str) -> list[Artifact]:
    """Record a command line plus the file paths / IPs embedded in it."""
    text = command.strip()
    if not text:
        return []
    out: list[Artifact] = [Artifact("command", text[:_MAX_COMMAND_LEN], source)]
    seen: set[tuple[str, str]] = set()
    for match in _PATH_RE.findall(text)[:_MAX_EMBEDDED_PER_COMMAND]:
        key = ("file", match.lower())
        if key not in seen:
            seen.add(key)
            out.append(Artifact("file", match, source))
    for match in _IP_IN_TEXT_RE.findall(text)[:_MAX_EMBEDDED_PER_COMMAND]:
        normalized = _normalize("ip", match)
        if normalized is None:
            continue
        key = ("ip", normalized)
        if key not in seen:
            seen.add(key)
            out.append(Artifact("ip", normalized, source))
    return out


def extract_artifacts(raw: str) -> list[Artifact]:
    """Extract allow-listed artifact fields from event-shaped JSON only."""
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError):
        return []

    found: dict[tuple[str, str], Artifact] = {}
    for event in _event_dicts(payload):
        # The event id is provenance only — it is the `source` for real artifacts,
        # never an artifact itself (opaque ids are not pivotable).
        source = _source_id(event)
        for key, value in _flatten(event):
            # Command lines: record the command and mine embedded file paths / IPs.
            if _is_command_key(key) and isinstance(value, str):
                for artifact in _mine_command(value, source):
                    found.setdefault((artifact.kind, artifact.value.lower()), artifact)
                continue
            kind = _artifact_kind(key)
            if not kind:
                continue
            normalized = _normalize(kind, value)
            if normalized is None:
                continue
            found.setdefault((kind, normalized.lower()), Artifact(kind, normalized, source))
    return list(found.values())


def record_artifacts(
    raw: str,
    *,
    case_id: str,
    run_id: str,
    agent_name: str,
) -> list[Artifact]:
    """Persist extracted artifacts directly through the board repository."""
    artifacts = extract_artifacts(raw)
    if not artifacts:
        return []

    from aci_board import store

    store.init_db()
    for artifact in artifacts:
        store.add_entry(
            case_id=case_id,
            run_id=run_id,
            agent_name=agent_name,
            kind="artifact",
            content=f"{artifact.kind}: {artifact.value}",
            source=artifact.source,
            confidence="high",
            status="observed",
        )
    return artifacts
