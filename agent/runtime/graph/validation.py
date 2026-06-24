from __future__ import annotations

import ipaddress

from langchain_core.messages import ToolMessage

from ..infra.logbus import emit, src_label

from .parsing import _ACTIVE_COMPROMISE_INDICATORS_RE, _ANTI_FORENSIC_RE, _BRUTE_FORCE_RE, _COMMAND_LITERAL_PATTERNS, _CONFIRMED_FACTS_RE, _DOMAIN_LITERAL_RE, _EVENT_ID_TOKEN_RE, _FACT_BULLET_RE, _HASH_LITERAL_RE, _IP_LITERAL_RE, _JSON_EVENT_ID_RE, _LONG_HEX_RE, _NEGATED_EVIDENCE_RE, _PATH_LITERAL_RE, _PERSISTENCE_RE, _REVERSE_SHELL_RE, _SOURCE_REF_RE, _TROJAN_RE, _ascii_dashes, _extract_source_refs, _has_positive_pattern, _is_none_bullet, _lines_with_ips, _section_body, _strip_markers
from .state import AgentState



def _collect_escalation_facts(text: str) -> list[str]:
    """Return confirmed-facts bullets that signal active compromise with a cited event ID.

    Only fires when the fact is in ## Confirmed Facts (not Hypotheses) AND contains
    an active-compromise indicator AND has at least one event ID or timestamp citation.
    This ensures escalation is triggered by raw evidence, not speculation.
    """
    cf_match = _CONFIRMED_FACTS_RE.search(text or "")
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
        if (
            _ACTIVE_COMPROMISE_INDICATORS_RE.search(content)
            and _extract_source_refs(content)
        ):
            results.append(content)
    return results


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
        if (ref and "/" not in ref and " " not in ref
                and any(ch.isdigit() for ch in ref)
                and _EVENT_ID_TOKEN_RE.match(ref)):
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
        return store.list_entries(state["case_id"], state["run_id"], state["agent_name"])
    except Exception as exc:
        emit(src_label(state["agent_name"]), "warning", "validation: board read failed", detail=str(exc))
        return []


def _trusted_artifacts_for_validation(state: AgentState, messages: list) -> set[str]:
    """Artifacts the task conclusion may positively mention."""
    allowed: set[str] = set()
    task = state.get("current_task") or {}
    allowed.update(_artifact_literals_in(task.get("description") or ""))

    for message in messages or []:
        if isinstance(message, ToolMessage):
            allowed.update(_positive_artifact_literals(getattr(message, "content", "") or ""))

    for entry in _board_entries_for_validation(state):
        kind = entry.get("kind")
        status = entry.get("status")
        if kind == "artifact" or (kind == "fact" and status == "confirmed"):
            allowed.update(_artifact_literals_in(entry.get("content") or ""))
            allowed.update(_artifact_literals_in(entry.get("source") or ""))

    handoff = state.get("handoff") or {}
    if isinstance(handoff, dict):
        allowed.update(_artifact_literals_in("\n".join(_iter_leaf_strings(handoff.get("artifacts") or {}))))
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
