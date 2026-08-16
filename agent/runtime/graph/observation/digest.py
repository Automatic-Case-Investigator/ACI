from __future__ import annotations

"""Evidence snapshots, digests, and orientation/volume facts."""

from .events import _clip, _event_dicts, _event_fields, _first_present, _source_id
from .trials import _EVENT_SNAPSHOT_TOOLS


# ── Evidence snapshots, digests, and orientation/volume facts ──
def _evidence_snapshots(tool_name: str, obj) -> list[dict]:
    """Extract compact, non-semantic event fields for model-side assimilation.

    This intentionally avoids judging whether a URL, command, or rule is malicious.
    Code only preserves the evidence-bearing fields that the interpreter needs in
    order to reason semantically without carrying full raw tool blobs forward.
    """
    if tool_name not in _EVENT_SNAPSHOT_TOOLS or not isinstance(obj, dict):
        return []
    events = _event_dicts(obj)

    out: list[dict] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        fields = _event_fields(event)
        snapshot = {
            "event_id": _source_id(event),
            "timestamp": _first_present(
                fields, ("timestamp", "@timestamp", "data.timestamp")
            ),
            "agent": _first_present(fields, ("agent.name", "agent", "host.name")),
            "rule_id": _first_present(fields, ("rule.id", "rule_id")),
            "rule_description": _first_present(
                fields, ("rule.description", "rule_desc", "description")
            ),
            "rule_groups": _first_present(fields, ("rule.groups",)),
            "rule_level": _first_present(fields, ("rule.level",)),
            "src_ip": _first_present(
                fields, ("data.srcip", "src_ip", "source.ip", "srcip")
            ),
            "dst_ip": _first_present(
                fields, ("data.dstip", "dst_ip", "destination.ip", "dstip")
            ),
            "status": _first_present(fields, ("data.id", "http.response.status_code")),
            "url": _first_present(fields, ("data.url", "url", "http.url", "request")),
            "user_agent": _first_present(
                fields, ("data.user_agent", "http.user_agent", "user_agent")
            ),
            "user": _first_present(
                fields, ("data.srcuser", "data.dstuser", "user.name", "user")
            ),
            "command": _first_present(
                fields,
                (
                    "data.command",
                    "data.audit.command",
                    "process.command_line",
                    "data.audit.exe",
                    "process.executable",
                ),
            ),
            "full_log": _clip(
                _first_present(fields, ("full_log", "message", "log", "raw")), 420
            ),
        }
        compact = {key: value for key, value in snapshot.items() if value}
        if compact:
            out.append(compact)
        if len(out) >= 8:
            break
    return out


def _digest_line(snapshot: dict) -> str:
    """One compact, human-readable line for a single event snapshot — the semantic
    fields an analyst reads first, in a fixed order. Empty fields are skipped so the
    line stays dense. This is pure formatting of the already-extracted snapshot; it
    carries no judgement about maliciousness."""
    parts: list[str] = []
    rule = " ".join(
        p
        for p in (
            snapshot.get("rule_id") and f"rule {snapshot['rule_id']}",
            snapshot.get("rule_description"),
        )
        if p
    )
    if rule:
        parts.append(rule)
    if snapshot.get("rule_groups"):
        parts.append(f"[{snapshot['rule_groups']}]")
    if snapshot.get("url"):
        url = snapshot["url"]
        parts.append(f"{url} →{snapshot['status']}" if snapshot.get("status") else url)
    elif snapshot.get("status"):
        parts.append(f"status {snapshot['status']}")
    if snapshot.get("command"):
        parts.append(f"cmd={snapshot['command']}")
    if snapshot.get("user"):
        parts.append(f"user={snapshot['user']}")
    if snapshot.get("src_ip") or snapshot.get("dst_ip"):
        flow = "→".join(
            p for p in (snapshot.get("src_ip"), snapshot.get("dst_ip")) if p
        )
        parts.append(flow)
    if (
        snapshot.get("full_log")
        and not snapshot.get("command")
        and not snapshot.get("url")
    ):
        parts.append(_clip(snapshot["full_log"], 160))
    return " | ".join(parts)


def _evidence_digest(snapshots: list[dict]) -> list[str]:
    """A short human-readable digest of the notable events in this batch, so the
    interpreter attends to WHAT was retrieved (paths, commands, statuses, users)
    rather than only how many hits came back."""
    out: list[str] = []
    seen: set[str] = set()
    for snapshot in snapshots:
        line = _digest_line(snapshot)
        if line and line not in seen:
            seen.add(line)
            out.append(line)
        if len(out) >= 8:
            break
    return out


def _extract_markdown_value(text: str, key: str) -> str:
    marker = f"| {key} |"
    for line in str(text or "").splitlines():
        if marker not in line:
            continue
        parts = [part.strip() for part in line.strip().strip("|").split("|")]
        if len(parts) >= 2:
            return parts[1]
    return ""


def _orientation_facts(tool_name: str, obj) -> list[dict]:
    """Extract compact orientation facts from non-event context tools.

    Orientation facts help the model carry case/alert pivots forward without
    pretending case records are SIEM events or copying full case descriptions into
    evidence snapshots.
    """
    if not isinstance(obj, dict):
        return []
    if tool_name == "get_case":
        description = str(obj.get("description") or "")
        fact = {
            "source": "case",
            "case_id": str(obj.get("_id") or obj.get("id") or ""),
            "title": _clip(obj.get("title"), 160),
            "alert_time": _extract_markdown_value(description, "@timestamp"),
            "host": _extract_markdown_value(description, "agent.name"),
            "host_ip": _extract_markdown_value(description, "agent.ip"),
            "src_ip": _extract_markdown_value(description, "data.srcip"),
            "url": _extract_markdown_value(description, "data.url"),
            "rule_id": _extract_markdown_value(description, "rule.id"),
            "rule_description": _extract_markdown_value(
                description, "rule.description"
            ),
        }
        compact = {key: value for key, value in fact.items() if value}
        return [compact] if compact else []
    if tool_name == "list_case_alerts":
        out: list[dict] = []
        for alert in (obj.get("alerts") or [])[:5]:
            if not isinstance(alert, dict):
                continue
            tags = alert.get("tags") or []
            tag_map = {}
            for tag in tags:
                if isinstance(tag, str) and "=" in tag:
                    key, value = tag.split("=", 1)
                    tag_map[key] = value
            fact = {
                "source": "alert",
                "alert_id": str(alert.get("_id") or ""),
                "title": _clip(alert.get("title"), 160),
                "alert_time": str(alert.get("date_iso") or ""),
                "source_ref": str(alert.get("sourceRef") or ""),
                "host": tag_map.get("agent_name", ""),
                "host_ip": tag_map.get("agent_ip", ""),
                "rule_id": tag_map.get("rule", ""),
            }
            compact = {key: value for key, value in fact.items() if value}
            if compact:
                out.append(compact)
        return out
    return []


def _volume_regimes(obj) -> list[dict]:
    if not isinstance(obj, dict):
        return []
    bursts = obj.get("bursts") or []
    out: list[dict] = []
    for burst in bursts[:8]:
        if not isinstance(burst, dict):
            continue
        regime = {
            "start": str(burst.get("start") or ""),
            "end": str(burst.get("end") or ""),
            "peak_count": int(burst.get("peak_count") or 0),
            "total": int(burst.get("total") or 0),
        }
        compact = {key: value for key, value in regime.items() if value not in ("", 0)}
        if compact:
            out.append(compact)
    return out


def _artifact_labels(artifacts: list[object]) -> list[str]:
    out: list[str] = []
    for artifact in artifacts or []:
        kind = getattr(artifact, "kind", "")
        value = getattr(artifact, "value", "")
        if kind and value:
            out.append(f"{kind}:{value}")
    return out[:12]


def _path_family(value: str) -> str:
    text = str(value or "").strip()
    if not text.startswith("/"):
        return ""
    parts = [part for part in text.split("/") if part]
    if len(parts) >= 2:
        return f"/{parts[0]}/*"
    if len(parts) == 1:
        return f"/{parts[0]}*"
    return ""
