from __future__ import annotations

import ipaddress
import re

from langchain_core.messages import ToolMessage

from ..infra.logbus import emit, src_label

from .parsing import (
    _ACTIVE_COMPROMISE_INDICATORS_RE,
    _ANTI_FORENSIC_RE,
    _BRUTE_FORCE_RE,
    _COMMAND_LITERAL_PATTERNS,
    _DOMAIN_LITERAL_RE,
    _EVENT_ID_TOKEN_RE,
    _FACT_BULLET_RE,
    _FINDINGS_RE,
    _HASH_LITERAL_RE,
    _IP_LITERAL_RE,
    _JSON_EVENT_ID_RE,
    _LONG_HEX_RE,
    _NEGATED_EVIDENCE_RE,
    _NEW_LEADS_HEADER_RE,
    _PATH_LITERAL_RE,
    _PERSISTENCE_RE,
    _REVERSE_SHELL_RE,
    _SOURCE_REF_RE,
    _TROJAN_RE,
    _ascii_dashes,
    _extract_source_refs,
    _has_positive_pattern,
    _is_none_bullet,
    _lines_with_ips,
    _section_body,
    _strip_markers,
)
from .state import AgentState


def _collect_escalation_facts(text: str) -> list[str]:
    """Return ## Findings bullets that signal active compromise with a cited event ID.

    Only fires when the fact is in ## Findings (not Hypotheses) AND contains
    an active-compromise indicator AND has at least one event ID or timestamp citation.
    This ensures escalation is triggered by raw evidence, not speculation.
    """
    cf_match = _FINDINGS_RE.search(text or "")
    if not cf_match:
        return []
    facts_block = _section_body(text, cf_match)
    results: list[str] = []
    for bullet in _FACT_BULLET_RE.finditer(facts_block):
        content, _ = _strip_markers(bullet.group(1).strip())
        if not content or _is_none_bullet(content):
            continue
        if _NEGATED_EVIDENCE_RE.search(content):
            continue
        if _ACTIVE_COMPROMISE_INDICATORS_RE.search(content) and _extract_source_refs(
            content
        ):
            results.append(content)
    return results


# Marker the decode layer stamps on any command it recovered from an encoded field
# (see analysis/artifacts.py: `[decoded] ...` / `[hex-decoded] ...`). It is only emitted
# AFTER `_looks_like_command` passes, so its presence already means "an attacker hid a
# shell command inside a URL/param" — high-signal and technique-agnostic.
_DECODED_COMMAND_MARKER_RE = re.compile(r"\[(?:hex-)?decoded\]", re.I)


def _cited_board_entries(
    entries: list[dict],
    *,
    kinds: tuple[str, ...],
    keep=None,
) -> list[str]:
    """Board entries of `kinds` as cited `"<content> [<source>]"` strings.

    Pure over a list of entries so every consumer can use it — the ones holding a
    `state` (escalation, verdict, interpret) and the ones that already fetched the
    board via `get_board` (report synthesis).

    Drops empty, placeholder, and negated content, de-dupes on content, and **ranks
    decoded commands ahead of everything else**. That ordering is load-bearing: every
    consumer caps the list, and a decoded `mysql … wp_users` credential dump is
    deterministic ground truth, whereas prose that merely *mentions* a reverse-shell
    token (often while narrating its ABSENCE) is the agent's fragile narration. The
    authoritative decoded artifacts must never be crowded out of the cap by prose.

    `keep` is an optional predicate over the content string. When given, an entry
    survives only if it is a decoded command **or** `keep(content)` is truthy —
    decoded commands are never gated, for the reason in `_board_compromise_facts`.
    """
    decoded: list[str] = []
    rest: list[str] = []
    seen: set[str] = set()
    for entry in entries:
        if entry.get("kind") not in kinds:
            continue
        content = (entry.get("content") or "").strip()
        if (
            not content
            or _is_none_bullet(content)
            or _NEGATED_EVIDENCE_RE.search(content)
        ):
            continue
        is_decoded_command = bool(_DECODED_COMMAND_MARKER_RE.search(content))
        if keep is not None and not is_decoded_command and not keep(content):
            continue
        key = content.lower()
        if key in seen:
            continue
        seen.add(key)
        src = (entry.get("source") or "").strip()
        item = f"{content} [{src}]" if src else content
        (decoded if is_decoded_command else rest).append(item)
    return decoded + rest


def _board_compromise_facts(state: AgentState) -> list[str]:
    """Compromise-relevant evidence sitting on the Findings Board — independent of whether
    the agent narrated it in its ## Findings.

    Two triggers, deliberately kept on the DETERMINISTIC side of the line:

    1. A decoded command. The decode layer recovers commands hidden in encoded fields and
       stamps them `[decoded]`/`[hex-decoded]` (only after `_looks_like_command`). Encoding a
       shell command into a URL parameter is itself the tell — the code's job is just to
       flag "a hidden command exists, account for it", NOT to judge which technique it is.
       Classifying it (reverse shell vs credential dump vs offline crack vs tool download)
       and linking it into the kill chain is the MODEL's job at interpret/synthesis, where
       it has the full board for context. We used to gate this through the narrow reverse-
       shell `_ACTIVE_COMPROMISE_INDICATORS_RE`, which silently dropped a decoded
       `mysql ... select * from wp_users` credential dump and a `wphashcrack.sh -u <user>`
       crack — the code was doing semantic gatekeeping and losing a real compromise.

    2. A narrative active-compromise indicator (reverse shell / C2 / anti-forensics) the
       agent or a fact bullet DID write out — the original behavior, retained.

    Negated evidence ("no ... found", "not observed") is excluded in both cases.

    Returns each item as `"<content> [<source event id>]"` so escalation/verdict keep the
    raw-evidence citation. Ordering (decoded first) and filtering live in
    `_cited_board_entries`; this adds only the compromise gate.
    """
    return _cited_board_entries(
        _board_entries_for_validation(state),
        kinds=("artifact", "fact"),
        keep=_ACTIVE_COMPROMISE_INDICATORS_RE.search,
    )


# Pivotable artifact kinds, ordered by how often the kind carries a chain onward
# rather than merely labelling it. Ordering is a deterministic display preference —
# whether any given artifact is worth pivoting on is the model's call, not this list's.
_PIVOTABLE_KINDS = (
    "cwd",
    "command",
    "file",
    "domain",
    "sha256",
    "sha1",
    "md5",
    "process",
    "user",
    "ip",
    "host",
)
_MAX_UNPIVOTED = 8
# The line on which a task declares what it investigates. Task descriptions also
# quote supporting evidence, so matching an artifact against the whole description
# would count "this task mentions the value as context" as "this task investigates
# it" — the exact citing-vs-pivoting confusion this signal exists to catch.
_TASK_PIVOT_LINE_RE = re.compile(r"^\s*[-*]?\s*pivots?\s*:(.*)$", re.IGNORECASE | re.M)


def _task_pivot_ground(tasks: list[dict]) -> str:
    """Ground the queue already covers: each task's title plus its declared pivots."""
    parts: list[str] = []
    for task in tasks or []:
        parts.append(str(task.get("title") or ""))
        parts.extend(_TASK_PIVOT_LINE_RE.findall(str(task.get("description") or "")))
    return "\n".join(p for p in parts if p)


def _unpivoted_artifacts(
    state: AgentState, report: str, covered: str = ""
) -> list[str]:
    """Confirmed artifacts the task CITED in its ## Findings but pivoted on in no lead.

    The deterministic floor behind the §4 artifact-pivot rule: "a confirmed artifact
    whose relationships were never examined is an incomplete pivot." §4 states that
    invariant; nothing computed it, which left the model to track set membership
    across cycles — bookkeeping it does badly and code does exactly.

    Artifacts come from the board, where the extractor already typed them from
    structured event fields, rather than from re-mining the prose. That is what
    generalises this: it previously mined IP literals out of findings bullets gated on
    an active-compromise regex, so it could only ever fire for reverse-shell/C2
    language about an IP. A root command whose working directory was a web upload
    path — cited in findings, pivoted on by nothing — matched neither half of that
    gate and passed silently (session b9615cf7).

    Precision comes from the two halves of §4.2's own definition of coverage. An
    artifact is reported only if the agent CITED it in its own ## Findings — keeping
    the signal about what this task established rather than re-flagging the whole
    run's board every task — and only if it is answered by nothing: no ## New Leads
    entry, and no task already queued or completed (`covered`). Without that second
    half the signal saturates: every sudo artifact reappears on every task, the
    reviewer learns the list is noise, and a guard that always fires stops being read.

    Being listed is not an accusation. The reviewer asks the agent to account for
    each one, and "expected, because X" is a complete answer.
    """
    text = report or ""
    f_match = _FINDINGS_RE.search(text)
    if not f_match:
        return []
    findings_lower = _section_body(text, f_match).lower()
    nl_match = _NEW_LEADS_HEADER_RE.search(text)
    leads_lower = _section_body(text, nl_match).lower() if nl_match else ""
    covered_lower = (covered or "").lower()

    by_kind: dict[str, list[str]] = {}
    seen: set[str] = set()
    for entry in _board_entries_for_validation(state):
        if entry.get("kind") != "artifact":
            continue
        content = (entry.get("content") or "").strip()
        kind, _, value = content.partition(": ")
        value = value.strip()
        if not value or kind not in _PIVOTABLE_KINDS:
            continue
        key = value.lower()
        if key in seen or key not in findings_lower:
            continue
        if key in leads_lower or (covered_lower and key in covered_lower):
            continue
        seen.add(key)
        by_kind.setdefault(kind, []).append(f"{kind}: {value}")

    out: list[str] = []
    for kind in _PIVOTABLE_KINDS:
        out.extend(by_kind.get(kind, []))
    return out[:_MAX_UNPIVOTED]


def _artifact_literals_in(text: str) -> set[str]:
    """Extract normalized artifact literals from text for evidence-bound checks."""
    artifacts: set[str] = set()
    raw = _ascii_dashes(text or "")
    for match in _IP_LITERAL_RE.findall(raw):
        try:
            artifacts.add(f"ip:{ipaddress.ip_address(match)}")
        except ValueError:
            continue
    for match in _DOMAIN_LITERAL_RE.findall(raw):
        candidate = match.rstrip(".").lower()
        if not _IP_LITERAL_RE.fullmatch(candidate):
            artifacts.add(f"domain:{candidate}")
    for match in _HASH_LITERAL_RE.findall(raw):
        artifacts.add(f"hash:{match.lower()}")
    for match in _PATH_LITERAL_RE.findall(raw):
        artifacts.add(f"path:{match.rstrip('.,;:').lower()}")
    for backtick, evid in _SOURCE_REF_RE.findall(raw):
        ref = (backtick or evid).strip()
        # Require at least one digit so field names (data.srcip, connect, socket)
        # don't get extracted as event IDs when backtick-wrapped.
        if (
            ref
            and "/" not in ref
            and " " not in ref
            and any(ch.isdigit() for ch in ref)
            and _EVENT_ID_TOKEN_RE.match(ref)
        ):
            artifacts.add(f"event:{ref.lower()}")
    for ref in _JSON_EVENT_ID_RE.findall(raw):
        ref = ref.strip()
        if ref and "/" not in ref and " " not in ref and _EVENT_ID_TOKEN_RE.match(ref):
            artifacts.add(f"event:{ref.lower()}")
    for name, pattern in _COMMAND_LITERAL_PATTERNS:
        if pattern.search(raw):
            artifacts.add(f"command:{name}")
    # Hex-encoded payloads: decode any long even-length hex token and extract
    # artifacts from the plaintext so that a model citing /dev/tcp/ or a C2 IP
    # from a decoded hex string isn't rejected by grounded-output validation.
    for hex_str in _LONG_HEX_RE.findall(raw):
        if len(hex_str) % 2 != 0:
            continue
        try:
            decoded = bytes.fromhex(hex_str).decode("ascii", errors="replace")
        except (ValueError, OverflowError):
            continue
        for name, pattern in _COMMAND_LITERAL_PATTERNS:
            if pattern.search(decoded):
                artifacts.add(f"command:{name}")
        for match in _IP_LITERAL_RE.findall(decoded):
            try:
                artifacts.add(f"ip:{ipaddress.ip_address(match)}")
            except ValueError:
                continue
    return artifacts


def _positive_artifact_literals(text: str) -> set[str]:
    artifacts: set[str] = set()
    for line in (text or "").splitlines():
        if _NEGATED_EVIDENCE_RE.search(line):
            continue
        artifacts.update(_artifact_literals_in(line))
    return artifacts


def _iter_leaf_strings(value) -> list[str]:
    if isinstance(value, dict):
        out: list[str] = []
        for child in value.values():
            out.extend(_iter_leaf_strings(child))
        return out
    if isinstance(value, list):
        out: list[str] = []
        for child in value:
            out.extend(_iter_leaf_strings(child))
        return out
    if isinstance(value, (str, int, float)):
        return [str(value)]
    return []


def _board_entries_for_validation(state: AgentState) -> list[dict]:
    try:
        from aci_board import store

        store.init_db()
        return store.list_entries(
            state["case_id"], state["run_id"], state["agent_name"]
        )
    except Exception as exc:
        emit(
            src_label(state["agent_name"]),
            "warning",
            "validation: board read failed",
            detail=str(exc),
        )
        return []


def _trusted_artifacts_for_validation(state: AgentState, messages: list) -> set[str]:
    """Artifacts the task conclusion may positively mention."""
    allowed: set[str] = set()
    task = state.get("current_task") or {}
    allowed.update(_artifact_literals_in(task.get("description") or ""))

    for message in messages or []:
        if isinstance(message, ToolMessage):
            allowed.update(
                _positive_artifact_literals(getattr(message, "content", "") or "")
            )

    for entry in _board_entries_for_validation(state):
        kind = entry.get("kind")
        status = entry.get("status")
        if kind == "artifact" or (kind == "fact" and status == "confirmed"):
            allowed.update(_artifact_literals_in(entry.get("content") or ""))
            allowed.update(_artifact_literals_in(entry.get("source") or ""))

    handoff = state.get("handoff") or {}
    if isinstance(handoff, dict):
        allowed.update(
            _artifact_literals_in(
                "\n".join(_iter_leaf_strings(handoff.get("artifacts") or {}))
            )
        )
    return allowed


def _artifact_display(token: str) -> str:
    return token.split(":", 1)[1] if ":" in token else token


def _derive_report_guardrails(
    artifacts: list[dict],
    facts: list[dict],
    hypotheses: list[dict],
    completed: list[dict],
) -> tuple[list[str], str]:
    """Deterministic SOC-quality hints for the final report synthesis.

    These are derived from already-recorded board/task text. They do not introduce
    new evidence; they prevent the narrative model from under-calling obvious
    correlations or severity floors.
    """
    evidence_hypotheses = [
        entry for entry in hypotheses if entry.get("status") == "confirmed"
    ]
    corpus_parts: list[str] = []
    for entry in [*artifacts, *facts, *evidence_hypotheses]:
        corpus_parts.append((entry.get("content") or "").strip())
        if entry.get("source"):
            corpus_parts.append(str(entry["source"]))
    for task in completed:
        corpus_parts.append((task.get("title") or "").strip())
        corpus_parts.append((task.get("summary") or "").strip())
    corpus = "\n".join(part for part in corpus_parts if part)

    attacker_ips = _lines_with_ips(corpus, _BRUTE_FORCE_RE)
    c2_ips = _lines_with_ips(corpus, _REVERSE_SHELL_RE)
    linked_ips = sorted(attacker_ips & c2_ips)

    has_reverse_shell = _has_positive_pattern(corpus, _REVERSE_SHELL_RE)
    has_persistence = _has_positive_pattern(corpus, _PERSISTENCE_RE)
    has_trojaned = _has_positive_pattern(corpus, _TROJAN_RE)
    has_anti_forensic = _has_positive_pattern(corpus, _ANTI_FORENSIC_RE)

    derived_findings: list[str] = []
    guidance: list[str] = []
    if linked_ips:
        ip_list = ", ".join(linked_ips)
        derived_findings.append(
            f"- Correlation: reverse-shell/C2 destination {ip_list} matches the "
            f"brute-force source {ip_list}; treat those threads as linked."
        )
        guidance.append(
            "A discovered reverse-shell/C2 destination matches the original brute-force "
            "source IP. State this as the decisive linkage when writing the verdict."
        )
    if has_reverse_shell:
        guidance.append(
            "Confirmed reverse-shell/C2 evidence is a confirmed compromise indicator, "
            "not merely suspicious local administration."
        )
    if has_reverse_shell and (has_persistence or has_trojaned or has_anti_forensic):
        guidance.append(
            "Severity floor: critical. Reverse shell plus persistence, trojaned binaries, "
            "or agent tampering requires immediate containment."
        )
    elif has_reverse_shell or has_trojaned:
        guidance.append(
            "Severity floor: high. Reverse shell or trojaned-binary evidence requires "
            "containment unless the facts explicitly refute compromise."
        )
    if has_anti_forensic:
        guidance.append("Call out security-agent tampering as anti-forensic activity.")

    return derived_findings, "\n".join(f"- {item}" for item in guidance)
