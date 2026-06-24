"""Extract normalized alert metadata from TheHive case + alert payloads.

Produces the `alert_metadata` dict the pattern matcher consumes (see
`pattern_matcher` for the contract). This is deterministic parsing only — no LLM
— so the fast-triage pattern check happens before any model call.

TheHive's case-alert summary is intentionally compact (titles, severities, tags,
time range). Rule IDs and entities are most reliably recovered from tags, so the
tag parser below recognizes a few common shapes:

    "rule:2832", "rule_id=2832", "5710"      -> rule_id
    "user:backup", "username=svc"            -> user
    "path:/var/spool/cron", "file:/etc/x"    -> path
"""
from __future__ import annotations

import re

# A bare tag treated as a rule id if it is all digits and at least this long
# (Wazuh rule IDs are typically 3-6 digits; avoids catching severities like "1").
_MIN_BARE_RULE_LEN = 3

_KV_RE = re.compile(r"^\s*([a-zA-Z_]+)\s*[:=]\s*(.+?)\s*$")

_RULE_KEYS = {"rule", "rule_id", "ruleid", "sigid", "signature_id"}
_USER_KEYS = {"user", "username", "user_name", "account", "srcuser", "dstuser"}
_PATH_KEYS = {"path", "file", "filepath", "file_path", "filename"}


def _classify_tag(tag: str, out: dict) -> None:
    if not tag or not isinstance(tag, str):
        return
    m = _KV_RE.match(tag)
    if m:
        key, value = m.group(1).lower(), m.group(2).strip()
        if not value:
            return
        if key in _RULE_KEYS:
            out["rule_ids"].add(value)
        elif key in _USER_KEYS:
            out["users"].add(value)
        elif key in _PATH_KEYS:
            out["paths"].add(value)
        return
    # Bare numeric tag → likely a rule id.
    bare = tag.strip()
    if bare.isdigit() and len(bare) >= _MIN_BARE_RULE_LEN:
        out["rule_ids"].add(bare)


def extract_alert_metadata(case: dict | None, alerts: dict | None) -> dict:
    """Build the normalized alert_metadata dict from TheHive payloads.

    `case` is the get_case result; `alerts` is the list_case_alerts result. Either
    may be None/partial — extraction degrades gracefully to empty fields.
    """
    acc = {"rule_ids": set(), "users": set(), "paths": set()}
    titles: list[str] = []
    tags: set[str] = set()

    if isinstance(case, dict):
        for tag in case.get("tags") or []:
            tags.add(str(tag))
            _classify_tag(str(tag), acc)
        if case.get("title"):
            titles.append(str(case["title"]))

    if isinstance(alerts, dict):
        for group in alerts.get("groups") or []:
            if group.get("title"):
                titles.append(str(group["title"]))
            for tag in group.get("tags") or []:
                tags.add(str(tag))
                _classify_tag(str(tag), acc)
        for alert in alerts.get("alerts") or []:
            if alert.get("title"):
                titles.append(str(alert["title"]))
            for tag in alert.get("tags") or []:
                tags.add(str(tag))
                _classify_tag(str(tag), acc)

    return {
        "rule_ids": sorted(acc["rule_ids"]),
        "users": sorted(acc["users"]),
        "paths": sorted(acc["paths"]),
        "tags": sorted(tags),
        "titles": titles,
        # Named time windows and invalidator signals are not derivable from the
        # SOAR summary alone; left empty so condition checks stay conservative.
        "time_windows": [],
        "signals": [],
    }
