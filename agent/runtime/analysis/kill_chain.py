"""MITRE ATT&CK kill-chain correlation (Fix #3).

Entity-level correlation answers "what is this IP/user connected to"; SOC analysts
also reason at the adversary-behavior level — which ATT&CK tactics have evidence and
which are gaps. This module turns a `correlate_techniques` result (techniques grouped
by `rule.mitre.id`, each carrying tactic(s)) into a kill-chain-ordered narrative plus
an explicit list of core phases with no evidence, which become investigative leads.
"""
from __future__ import annotations

import json

# ATT&CK Enterprise tactics in kill-chain order (Wazuh `rule.mitre.tactic` display names).
KILL_CHAIN_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# Phases whose ABSENCE is investigatively meaningful (a complete intrusion usually
# leaves evidence in most of these). Reconnaissance/Defense Evasion/Discovery/
# Collection are noisier/optional, so they are not flagged as gaps.
_CORE_PHASES = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Credential Access",
    "Lateral Movement",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# Concrete Wazuh pivots per ATT&CK tactic (Fix #2): a gap lead is only useful if it
# says WHAT to query. Bridges the ATT&CK phase to the telemetry that would confirm or
# rule it out. Linux-centric, aligned with the Wazuh playbooks in the MCP guidance.
TACTIC_PIVOTS = {
    "Initial Access": "first successful remote login — rule.groups authentication_success "
                      "(rule.id 5715) from an external data.srcip; correlate that srcip's auth trail",
    "Execution": "audit exec rule.id 80792; data.audit.command / data.audit.exe; decode "
                 "data.audit.proctitle (hex); full_log 'sh -i' / 'bash -i' / '/dev/tcp'",
    "Persistence": "cron rule.id 2830-2834 with syscheck.diff; pam session rule.id 5501; "
                   "syscheck.path for crontabs / authorized_keys / systemd units",
    "Privilege Escalation": "sudo rule.id 5401-5404; rule.groups sudo; unexpected uid=0 / "
                            "data.audit.euid=0 transitions",
    "Credential Access": "brute force rule.id 5710-5716 / rule.groups authentication_failed; "
                         "access to /etc/shadow; reused or harvested credentials",
    "Lateral Movement": "same data.srcuser on a DIFFERENT agent.name; outbound ssh; "
                        "authentication_success on other hosts",
    "Command and Control": "full_log '/dev/tcp' / reverse-shell strings; external data.dstip; "
                           "beaconing cadence via get_event_volume",
    "Exfiltration": "large data.bytes_out; external (non-RFC1918) data.dstip; bulk file reads",
    "Impact": "file deletion rule.id 553 with syscheck.event=deleted; service stop; "
              "encryption / ransomware indicators",
}

# Gap-lead priority per tactic. A gap lead is, by definition, speculative coverage
# of a phase with NO evidence yet — a "rule out" backstop, not the trace-forward of a
# confirmed finding. So these are deliberately ranked in the 50–74 backward/scoping
# band of instructions.md §7, NOT the 85–94 forward/active band. This guarantees a
# grounded model pivot extending a CONFIRMED artifact (lateral movement, C2, etc. at
# 85–94) outranks a generic gap backstop, instead of a speculative "rule out Impact"
# lead at 92 starving the queue ahead of a confirmed lateral-login follow-up. The
# relative order across tactics (forward/impact phases highest) is preserved within
# the band so the cap still drops the least-valuable gaps first.
TACTIC_PRIORITY = {
    "Impact": 68,
    "Exfiltration": 66,
    "Command and Control": 64,
    "Lateral Movement": 62,
    "Execution": 60,
    "Privilege Escalation": 58,
    "Persistence": 56,
    "Credential Access": 54,
    "Initial Access": 52,
}

# Cap on auto-generated gap leads per run, so a sparse kill chain cannot flood the queue.
MAX_GAP_LEADS = 4

# A gap that FOLLOWS confirmed activity is not a speculative "rule out" — it is a
# forward trace from an established foothold ("we know they got THIS far; what did they
# do next?"). Those deserve the forward/active band (instructions.md §7, 85–94) so the
# trace-forward outranks background rule-out backstops and is not dropped when budget
# runs short — the exact failure where an agent confirmed access but never established
# the execution/privesc that followed.
_FORWARD_TRACE_PRIORITY = 88


def pivots_for_tactic(tactic: str) -> str:
    return TACTIC_PIVOTS.get(tactic, "")


def gap_lead_specs(
    gaps: list[str], host: str, window_hint: str = "", observed: list[str] | None = None
) -> list[dict]:
    """Turn kill-chain GAP phases into concrete, prioritized lead specs (Fix #1/#2).

    Each spec carries a ready-to-run pivot (the technique→query playbook) so the lead
    is actionable, not a vague "investigate execution". A gap that comes AFTER a
    confirmed phase in kill-chain order is reframed as a high-priority FORWARD TRACE
    (a confirmed foothold demands establishing what was done next); a gap with no
    established activity before it stays a lower-priority rule-out backstop. Sorted by
    priority and capped at MAX_GAP_LEADS.
    """
    observed_orders = [_order_key(t) for t in (observed or [])]
    specs: list[dict] = []
    for tactic in gaps:
        pivots = pivots_for_tactic(tactic) or "search the relevant rule families and fields"
        # Forward trace: some confirmed phase precedes this gap in the kill chain.
        if any(o < _order_key(tactic) for o in observed_orders):
            specs.append({
                "tactic": tactic,
                "priority": _FORWARD_TRACE_PRIORITY,
                "title": f"Trace forward to {tactic} on {host}",
                "description": (
                    f"The kill chain for `{host}` has CONFIRMED activity in an earlier phase but "
                    f"NO evidence of **{tactic}**, the adjacent forward phase. A confirmed foothold "
                    f"is a starting point, not a conclusion — establish what the actor did next on "
                    f"this host (query {tactic}'s behaviour class), or record a confirmed negative "
                    f"with a capable search. Pivots: {pivots}. {window_hint}"
                ).strip(),
            })
        else:
            specs.append({
                "tactic": tactic,
                "priority": TACTIC_PRIORITY.get(tactic, 60),
                "title": f"Establish or rule out {tactic} on {host}",
                "description": (
                    f"The MITRE ATT&CK kill chain for `{host}` shows NO evidence of **{tactic}**, "
                    f"a core attack phase. Confirm whether it occurred or record a confirmed "
                    f"negative (telemetry searched, none found). Pivots: {pivots}. {window_hint}"
                ).strip(),
            })
    specs.sort(key=lambda s: -s["priority"])
    return specs[:MAX_GAP_LEADS]


def _order_key(tactic: str) -> int:
    try:
        return KILL_CHAIN_ORDER.index(tactic)
    except ValueError:
        return len(KILL_CHAIN_ORDER)


def summarize_kill_chain(result_raw) -> tuple[str, list[str], list[str]]:
    """Render a correlate_techniques result as a kill-chain board line.

    Returns (board_content, observed_tactics_in_order, gap_phases). When no
    ATT&CK-tagged events are present, returns an empty observed list and all core
    phases as gaps so the caller can decide whether to record/retry.
    """
    if isinstance(result_raw, str):
        try:
            r = json.loads(result_raw)
        except (TypeError, ValueError):
            r = None
    elif isinstance(result_raw, dict):
        r = result_raw
    else:
        r = None

    techniques = (r or {}).get("techniques") or []
    if not techniques:
        return ("kill-chain: no MITRE ATT&CK-tagged events found in window",
                [], list(_CORE_PHASES))

    by_tactic: dict[str, list[str]] = {}
    for t in techniques:
        label = str(t.get("id") or "?")
        name = t.get("technique")
        if name:
            label += f" {name}"
        label += f"×{t.get('count', 0)}"
        ids = t.get("event_ids") or []
        if ids:
            label += f"[{ids[0]}]"
        for tactic in (t.get("tactics") or ["(untagged)"]):
            by_tactic.setdefault(tactic, []).append(label)

    ordered_tactics = sorted(by_tactic, key=_order_key)
    parts = [f"{tac}[{', '.join(by_tactic[tac][:4])}]" for tac in ordered_tactics]
    observed = [t for t in ordered_tactics if t != "(untagged)"]
    gaps = [p for p in _CORE_PHASES if p not in by_tactic]

    content = f"kill-chain ({len(techniques)} techniques): " + "; ".join(parts)
    if gaps:
        content += (" || GAPS (core phases with no evidence — investigate or rule out): "
                    + ", ".join(gaps))
    return content[:1400], observed, gaps
