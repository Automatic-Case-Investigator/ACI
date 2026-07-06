from __future__ import annotations

import re


# Pivot-scoring ladders — how strongly a candidate pivot is preferred, ranked by the
# provenance of the evidence that produced it (`source`), the analytic role it plays
# (`role`), and its stated confidence. Shared by the interpret pivot selector
# (`interpretation`) and the observation deduper (`observation`) so the two never drift.
_PIVOT_SOURCE_SCORE = {"case": 1, "alert_aggregate": 2, "board_inference": 2, "raw_event": 4, "decoded_payload": 5}
_PIVOT_ROLE_SCORE = {"hypothesis": 1, "exemplar": 1, "anchor": 2, "discriminator": 4}
_PIVOT_CONF_SCORE = {"low": 1, "medium": 2, "high": 3}



def _extract_report_section(text: str, heading: str) -> str:
    """Return markdown section body for a `## heading`, or an empty string."""
    pattern = re.compile(
        rf"^\s*##\s+{re.escape(heading)}\s*$\n(.*?)(?=^\s*##\s+|\Z)",
        re.IGNORECASE | re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(text or "")
    return (match.group(1).strip() if match else "")


def _section_has_concrete_items(body: str) -> bool:
    text = (body or "").strip()
    if not text:
        return False
    normalized = re.sub(r"[\s.\-–—_]+", " ", text).strip().lower()
    if normalized in {"none", "none identified", "no evidence gaps", "no gaps"}:
        return False
    return bool(re.search(r"\w", normalized))


# Match the ## New Leads section header (h2, h3, or bold variant).
_NEW_LEADS_HEADER_RE = re.compile(
    r"(?:^|\n)(?:#{2,3}\s*|(?:\*\*))New Leads(?:\*\*)?\s*\n",
    re.IGNORECASE,
)

# Lead entries are no longer parsed by regex: extraction + validation is done by
# a model (see graph/lead_model.py) because the analyst's formatting is too
# inconsistent for a reliable grammar. Only the section header above is matched
# deterministically so the pivot node knows a New Leads section exists.

# Accept h2, h3, or bold variants — small models sometimes use ### or **...**
_HYPOTHESES_RE = re.compile(
    r"(?:^|\n)(?:#{2,3}\s*|(?:\*\*))Hypotheses(?:\*\*)?\s*\n",
    re.IGNORECASE,
)
_FINDINGS_RE = re.compile(
    r"(?:^|\n)(?:#{2,3}\s*|(?:\*\*))Findings(?:\*\*)?\s*\n",
    re.IGNORECASE,
)
_SECTION_HEADER_RE = re.compile(
    r"\n(?:#{2,6}\s+[^\n]+|\*\*[^\n*]+\*\*\s*)\n",
    re.IGNORECASE,
)


def _section_body(text: str, match: re.Match) -> str:
    """Return the body after a markdown section header until the next section."""
    rest = (text or "")[match.end():]
    next_header = _SECTION_HEADER_RE.search(rest)
    return rest[:next_header.start()] if next_header else rest


# The three sections every investigation per-task report must contain. The
# `## Findings` section is the only place grounded evidence (e.g. a reverse shell
# seen in a tool result) is recorded, so a malformed report silently loses
# evidence. We validate the shape syntactically and nudge the model to re-emit on
# failure.
_REQUIRED_SUMMARY_SECTIONS: tuple[tuple[str, re.Pattern], ...] = (
    ("Findings", _FINDINGS_RE),
    ("Hypotheses", _HYPOTHESES_RE),
    ("New Leads", _NEW_LEADS_HEADER_RE),
)

_TRIAGE_SUMMARY_RE = re.compile(
    r"(?:^|\n)(?:#{2,3}\s*|(?:\*\*))Triage Summary(?:\*\*)?\s*\n",
    re.IGNORECASE,
)
_KEY_EVIDENCE_RE = re.compile(
    r"(?:^|\n)(?:#{2,3}\s*|(?:\*\*))Key Evidence(?:\*\*)?\s*\n",
    re.IGNORECASE,
)
_INVESTIGATION_PLAN_RE = re.compile(
    r"(?:^|\n)(?:#{2,3}\s*|(?:\*\*))Investigation Plan(?:\*\*)?\s*\n",
    re.IGNORECASE,
)
_LIST_ITEM_RE = re.compile(r"^\s*(?:-\s+|\d+\.\s+).+$", re.MULTILINE)
_REQUIRED_TRIAGE_SECTIONS: tuple[tuple[str, re.Pattern], ...] = (
    ("Triage Summary", _TRIAGE_SUMMARY_RE),
    ("Key Evidence", _KEY_EVIDENCE_RE),
    ("Investigation Plan", _INVESTIGATION_PLAN_RE),
)


# A markdown header at the very start of a string (the section-header regexes
# above consume the trailing blank line, so the next header can sit flush at
# position 0 with no leading newline for _SECTION_HEADER_RE to anchor on).
_NEXT_HEADER_RE = re.compile(r"(?:^|\n)\s*(?:#{2,6}\s+\S|\*\*\S)")


def _missing_summary_sections(report: str) -> list[str]:
    """Return the names of required sections absent or empty in an investigation
    report. A section counts as present only if its header exists and its body
    carries at least one bullet (a literal '- None.' satisfies this — the model
    is told to use it for genuinely empty sections)."""
    text = report or ""
    missing: list[str] = []
    for name, pattern in _REQUIRED_SUMMARY_SECTIONS:
        match = pattern.search(text)
        if not match:
            missing.append(name)
            continue
        rest = text[match.end():]
        next_header = _NEXT_HEADER_RE.search(rest)
        body = rest[:next_header.start()] if next_header else rest
        if not _FACT_BULLET_RE.search(body):
            missing.append(name)
    return missing


def _missing_triage_sections(report: str) -> list[str]:
    """Return required triage sections absent or structurally empty.

    Triage Summary may be paragraph text. Key Evidence and Investigation Plan must
    contain at least one list item so raw JSON blobs or artifact dumps do not pass
    as a durable handoff report.
    """
    text = report or ""
    missing: list[str] = []
    for name, pattern in _REQUIRED_TRIAGE_SECTIONS:
        match = pattern.search(text)
        if not match:
            missing.append(name)
            continue
        rest = text[match.end():]
        next_header = _NEXT_HEADER_RE.search(rest)
        body = rest[:next_header.start()] if next_header else rest
        if name == "Triage Summary":
            if not _section_has_concrete_items(body):
                missing.append(name)
        else:
            if not _LIST_ITEM_RE.search(body):
                missing.append(name)
    return missing

# Regex to parse a bullet like "- Crontab modified at ... (event ...)."
# Grabs everything after the leading "- ".
_FACT_BULLET_RE = re.compile(r"^\s*-\s+(.+)$", re.MULTILINE)

# Placeholder bullets the model emits when a section has no content. Recording
# these as facts/hypotheses is noise, so both paths skip them.
_NONE_BULLETS = frozenset({
    "none", "none.", "none confirmed", "none confirmed.",
    "no facts confirmed", "no facts confirmed.",
    "no open hypotheses", "no open hypotheses.",
    "no new leads", "no new leads.",
})

# Placeholder "nothing found" bullets the model emits in many phrasings
# ("None confirmed in this task.", "No confirmed findings", "N/A", ...). These
# are honest per-task negatives but are pure noise once aggregated into the
# report's Key Findings / Confirmed Facts / Hypotheses lists, so they must be
# dropped there. Match on a normalized prefix so variants are all caught.
_NONE_PREFIXES = (
    "none confirmed", "no facts confirmed", "no confirmed", "no open hypotheses",
    "no new leads", "no open leads", "no hypotheses", "no findings",
)


def _is_none_bullet(text: str) -> bool:
    """True for placeholder 'nothing found' bullets in any common phrasing."""
    t = (text or "").strip().strip("-*• ").lower()
    if not t or t in _NONE_BULLETS or t in {"none", "none.", "n/a", "n/a."}:
        return True
    return any(t.startswith(p) for p in _NONE_PREFIXES)


def _is_provenance_only(content: str) -> bool:
    r"""True for facts that are just an event-id/timestamp with no actual claim.

    The model sometimes dumps `Event \`abc123\` - 2025-04-20T03:41:00Z` as a fact.
    After stripping event-id tokens and timestamps, nothing of substance remains,
    so it is provenance, not a finding. Keep the threshold low (<=1 content word)
    so real but terse facts are never dropped.
    """
    key = _normalize_fact_key(content)
    words = [w for w in re.findall(r"[a-z0-9]+", key) if w not in {"event", "id", "ids", "alert", "at"}]
    return len(words) <= 1


# A Wazuh-style event id: digits-bearing token (optionally `~`-prefixed or
# dotted), length >= 6, no path/space chars. Used to merge facts that are just
# rewordings of the SAME event while keeping facts about DIFFERENT events.
_EVENT_ID_TOKEN_RE = re.compile(r"^~?[A-Za-z0-9][A-Za-z0-9._-]{5,}$")


def _event_ids_in(content: str) -> frozenset[str]:
    ids: set[str] = set()
    for backtick, evid in _SOURCE_REF_RE.findall(_ascii_dashes(content)):
        ref = (backtick or evid).strip()
        if not ref or "/" in ref or " " in ref:
            continue  # paths, commands, cron lines are content, not event ids
        if any(ch.isdigit() for ch in ref) and _EVENT_ID_TOKEN_RE.match(ref):
            ids.add(ref.lower())
    return frozenset(ids)


def _fact_dedup_key(content: str) -> str:
    """Dedup key that merges rewordings of one event but keeps distinct events.

    Two facts collapse only when they cite the same event id(s); facts citing
    different ids (e.g. five PAM logins at five timestamps) stay separate. Facts
    with no event id fall back to volatility-stripped text.
    """
    ids = _event_ids_in(content)
    if ids:
        return "ids:" + ",".join(sorted(ids))
    return _normalize_fact_key(content)

# Markers the model prepends to a restated hypothesis, in any combination/order:
#   bold/emphasis (`**`/`__`), an entry id the board context showed it
#   (`[id=entry_..]`), and/or a status (`[Open]`/`[Confirmed]`/`[Refuted]`).
_STATUS_TOKEN_RE = re.compile(
    r"\[\s*(open|confirmed|refuted)\s*(?:/\s*[a-z]+\s*)?\]", re.IGNORECASE
)
_ID_MARKER_RE = re.compile(r"\[\s*id\s*=\s*[A-Za-z0-9_]+\s*\]", re.IGNORECASE)
_EMPH_RE = re.compile(r"\*\*|__")
# Bullets that are leads/questions, not hypotheses (claims). Skip these.
_NON_HYPOTHESIS_RE = re.compile(
    r"^(investigate|determine|check|retrieve|identify|examine|review|find out|"
    r"validate|verify|correlate|search for|look for|follow up|pivot on|"
    r"what|which|who|where|when|how|did|does|do|is|are|was|were)\b",
    re.IGNORECASE,
)
# Event-id tokens (backtick-wrapped or after "event"/"id") and ISO timestamps —
# volatile provenance that should not defeat fact/hypothesis dedup, and that we
# can harvest as a fact's `source`.
_SOURCE_REF_RE = re.compile(
    r"`([^`]+)`|\bevent[ _]?(?:id)?[:\s]+([A-Za-z0-9_\-]{6,})",
    re.IGNORECASE,
)
# Match an ISO datetime, optionally with fractional seconds and a (possibly
# space-separated) zone — model output writes "2025-04-20 03:41:00.570 Z".
_ISO_TS_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?\s*(?:Z|UTC|[+-]\d{2}:?\d{2})?"
)
# Unicode dashes (non-breaking hyphen, en/em dash, minus) and exotic spaces
# (nbsp, narrow/thin nbsp, word joiner) that the model emits in dates and
# timestamps and which otherwise defeat the ISO/dedup regexes above — e.g.
# "2025‑04‑20 03:41:00" has a narrow no-break space the `[T ]` class misses.
_CHAR_TRANSLATION = {ord(c): "-" for c in "‐‑‒–—―−"}
_CHAR_TRANSLATION.update(
    {cp: " " for cp in (
        0x00A0, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008,
        0x2009, 0x200A, 0x202F, 0x205F, 0x2060, 0xFEFF,
    )}
)


def _ascii_dashes(text: str) -> str:
    """Fold Unicode dashes/exotic spaces to ASCII so date/id regexes match."""
    return (text or "").translate(_CHAR_TRANSLATION)
# A "fact" that is just a list of event ids is provenance, not a finding.
_EVENT_ID_DUMP_RE = re.compile(r"^\s*event\s+ids?\s*[:\-]", re.IGNORECASE)
_IP_LITERAL_RE = re.compile(
    r"\b\d{1,3}(?:\.\d{1,3}){3}\b|\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"
)
_DOMAIN_LITERAL_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b",
    re.IGNORECASE,
)
_HASH_LITERAL_RE = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
_PATH_LITERAL_RE = re.compile(r"(?:~?/[\w.+@=-]+(?:/[\w.+@=-]+)+|~/[\w.+@=-]+(?:/[\w.+@=-]+)*)")
_JSON_EVENT_ID_RE = re.compile(
    r"""["'](?:_id|event[._]?id|event_id)["']\s*:\s*["']([^"']{6,})["']""",
    re.IGNORECASE,
)
_COMMAND_LITERAL_PATTERNS = (
    ("reverse-shell", re.compile(r"(/dev/tcp/|bash\s+-i|sh\s+-i|nc\s+-e|netcat)", re.IGNORECASE)),
)
# Long hex strings that may be hex-encoded shell commands (min 32 chars, even length).
_LONG_HEX_RE = re.compile(r"\b([0-9a-fA-F]{32,})\b")
_BRUTE_FORCE_RE = re.compile(
    r"\b(brute[ -]?force|failed ssh|failed password|authentication failure|auth(?:entication)? failed)\b",
    re.IGNORECASE,
)
_REVERSE_SHELL_RE = re.compile(
    r"(reverse shell|/dev/tcp/|sh\s+-i|bash\s+-i|nc\s+-e|netcat)",
    re.IGNORECASE,
)
_PERSISTENCE_RE = re.compile(r"\b(crontab|cron|persistence|scheduled task)\b", re.IGNORECASE)
_TROJAN_RE = re.compile(r"\b(trojaned|rootkit|known bad|malicious binary)\b", re.IGNORECASE)
_ANTI_FORENSIC_RE = re.compile(
    r"\b(wazuh-agent|agent restart|agent stopped|anti-forensic|tamper|impair defenses)\b",
    re.IGNORECASE,
)
_NEGATED_EVIDENCE_RE = re.compile(
    r"\b(no evidence of|no matching|no\s+.+\s+found|no\s+.+\s+returned|"
    r"not observed|without|refuted)\b",
    re.IGNORECASE,
)


def _strip_markers(text: str) -> tuple[str, str | None]:
    """Peel leading bold / [id=..] / [status] markers; return (clean, status).

    The small model mixes these in any order (e.g. `**[id=x]** [Refuted] ...`),
    so peel iteratively until none remain.
    """
    s = (text or "").strip()
    status: str | None = None
    changed = True
    while changed and s:
        changed = False
        s2 = s.lstrip("* _")
        if s2 != s:
            s, changed = s2, True
        m = _STATUS_TOKEN_RE.match(s)
        if m:
            status = m.group(1).lower()
            s, changed = s[m.end():].strip(), True
        m = _ID_MARKER_RE.match(s)
        if m:
            s, changed = s[m.end():].strip(), True
    return s.strip(), status


def _looks_like_lead(text: str) -> bool:
    """True when a bullet is a question/imperative (a lead), not a hypothesis."""
    t = (text or "").strip()
    return t.endswith("?") or bool(_NON_HYPOTHESIS_RE.match(t))


def _extract_source_refs(text: str) -> str:
    """Collect event-id tokens / ISO timestamps cited in a bullet, for `source`."""
    refs: list[str] = []
    for backtick, evid in _SOURCE_REF_RE.findall(text or ""):
        ref = (backtick or evid).strip()
        if ref and ref not in refs:
            refs.append(ref)
    for ts in _ISO_TS_RE.findall(text or ""):
        if ts not in refs:
            refs.append(ts)
    return ", ".join(refs)


def _lines_with_ips(text: str, pattern: re.Pattern) -> set[str]:
    ips: set[str] = set()
    for line in (text or "").splitlines():
        if pattern.search(line) and not _NEGATED_EVIDENCE_RE.search(line):
            ips.update(_IP_LITERAL_RE.findall(line))
    return ips


def _has_positive_pattern(text: str, pattern: re.Pattern) -> bool:
    return any(
        pattern.search(line) and not _NEGATED_EVIDENCE_RE.search(line)
        for line in (text or "").splitlines()
    )


# Active-compromise indicators that require immediate escalation when confirmed
# in ## Confirmed Facts with a cited event ID or timestamp.
_ACTIVE_COMPROMISE_INDICATORS_RE = re.compile(
    r"(reverse.?shell|/dev/tcp/|c2.{0,20}(connect|callback|destination)|"
    r"command.and.control|active.{0,15}exfiltrat|"
    r"trojaned|rootkit|malicious.{0,20}binary|"
    r"anti.?forensic|wazuh.agent.{0,20}(stop|restart|tamper)|impair.defens)",
    re.IGNORECASE,
)

_DANGLING_FACT_RE = re.compile(
    r"\b(?:inserts?|adds?|appends?|contains?)\s+(?:the\s+)?(?:line|command)\s*\.?$",
    re.IGNORECASE,
)


def _section_count(pattern: re.Pattern, text: str) -> int:
    return len(pattern.findall(text or ""))


def _normalize_fact_key(text: str) -> str:
    """Dedup key for a fact/hypothesis: drop markers and volatile provenance.

    Strips id/status markers and emphasis so a restated entry (with or without a
    `[id=..]`/`[Refuted]`/`**bold**` prefix) collapses onto the original.
    """
    cleaned = _ascii_dashes(text or "")
    cleaned = _ID_MARKER_RE.sub(" ", cleaned)
    cleaned = _STATUS_TOKEN_RE.sub(" ", cleaned)
    cleaned = _EMPH_RE.sub(" ", cleaned)
    cleaned = _SOURCE_REF_RE.sub(" ", cleaned)
    cleaned = _ISO_TS_RE.sub(" ", cleaned)
    # collapse leftover punctuation/whitespace and parenthetical provenance husks
    cleaned = re.sub(r"\(\s*(?:event|id|@?timestamp)?[ ,;:]*\)", " ", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"[\s`(),]+", " ", cleaned)
    return cleaned.strip().lower()
