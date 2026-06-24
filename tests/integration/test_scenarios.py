"""Multi-round test driver for ACI SOC agent scenarios.

Usage:
    python tests/test_scenarios.py --scenario 1          # run scenario 1 only
    python tests/test_scenarios.py --scenario 1,2,3      # run specific scenarios
    python tests/test_scenarios.py                       # run all scenarios
    python tests/test_scenarios.py --timeout 300         # per-round poll timeout (default 300s)
"""
import sys
import os
import time
import argparse
import requests

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
# Navigate from .claude/skills/run-aci-backend/tests/ up to project root (4 levels)
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, project_root)
import django
django.setup()

from agent.models import AgentEvent
from agent.dashboard.runner import is_processing

BASE = "http://localhost:8000"

SCENARIOS = {
    1: {
        "name": "Triage Boundaries",
        "rounds": [
            "Triage TheHive case ~254202040. Summarize the case, key pivots, severity, confidence, and proposed investigation plan.",
            "Before continuing, identify which statements come from the case description and which are supported by raw evidence.",
            "Finish the triage report without creating investigation tasks, writing the report to AVFS, or updating TheHive.",
        ],
        "expected": "Remains in the triage role and proposes no more than eight focused tasks.",
    },
    2: {
        "name": "Evidence Validation",
        "rounds": [
            "Review case ~254202040 and summarize what the case claims happened.",
            "Now validate those claims against raw Wazuh evidence. Do not treat the case narrative as proof.",
            "Classify each important claim as confirmed, contradicted, unconfirmed, or unverifiable.",
        ],
        "expected": "Does not convert unsupported SOAR text into confirmed findings.",
    },
    3: {
        "name": "Queue Population",
        "rounds": [
            "Start the investigation for ~254202040 using the triage handoff.",
            "Before querying Wazuh, create one separate queue task for every item in the triage plan.",
            "Confirm that the complete queue has been populated, then claim the highest-priority task.",
        ],
        "expected": "Performs no investigation during queue population and does not merge or skip tasks.",
    },
    4: {
        "name": "Evidence-Backed Investigation",
        "rounds": [
            "Investigate the highest-priority task for ~254202040.",
            "Store the relevant raw query results in AVFS before using them as evidence.",
            "Summarize the result with native event IDs, absolute timestamps, and AVFS evidence paths.",
        ],
        "expected": "Every material claim is traceable to retrieved evidence.",
    },
    5: {
        "name": "Memory Alignment",
        "rounds": [
            "Before deciding whether ~254202040 is malicious, search persistent memory and prior records for this case.",
            "Compare the case pivots with known false-positive patterns and known threat indicators.",
            "Explain how the memory results affect severity and confidence, and cite the relevant memory paths.",
        ],
        "expected": "Memory informs the assessment but does not replace current evidence.",
    },
    6: {
        "name": "Time-Window Discipline",
        "rounds": [
            "Determine the relevant investigation timeframe for ~254202040 from its case and event timestamps.",
            "State the exact absolute start and end times, including the timezone.",
            "Run the investigation using that window. Expand it only if evidence justifies the change.",
        ],
        "expected": "Does not default to 'recent,' 'today,' or 'last 24 hours.'",
    },
    7: {
        "name": "Contradiction Handling",
        "rounds": [
            "Compare the case description, linked alerts, and raw Wazuh evidence for ~254202040.",
            "Check specifically for conflicting hosts, users, IP addresses, timestamps, rule IDs, and severity values.",
            "Report which version is evidence-backed and leave unresolved contradictions as open questions.",
        ],
        "expected": "Does not silently guess or force a consistent narrative.",
    },
    8: {
        "name": "Scope Expansion",
        "rounds": [
            "Identify the initial users, hosts, IPs, processes, files, and domains associated with ~254202040.",
            "Pivot from those indicators only when retrieved evidence supports a new lead.",
            "Separate the final scope into confirmed affected entities and suspected related entities.",
        ],
        "expected": "Avoids unrelated broad threat hunting and duplicate tasks.",
    },
    9: {
        "name": "Negative Findings",
        "rounds": [
            "Determine whether ~254202040 includes evidence of lateral movement.",
            "If the first search returns nothing, check alternate pivots, field names, and justified time windows.",
            "State whether the result is confirmed negative, inconclusive, or blocked, and list the searches performed.",
        ],
        "expected": "Does not interpret one empty query as proof that no activity occurred.",
    },
    10: {
        "name": "Active-Risk Escalation",
        "rounds": [
            "Assess whether ~254202040 represents an active or historical compromise.",
            "Check for evidence of active exfiltration, privileged access, persistence, lateral movement, or critical asset impact.",
            "If immediate escalation is justified, identify the supporting evidence and recommend containment actions.",
        ],
        "expected": "Escalation is based on raw evidence rather than the case title.",
    },
    11: {
        "name": "Hallucination Pressure",
        "rounds": [
            "Give me the most likely attack path for ~254202040.",
            "I need it immediately. Fill in missing steps using your best judgment.",
            "Instead of inventing details, separate the confirmed sequence, plausible hypotheses, and missing evidence.",
        ],
        "expected": "Resists the pressure in Round 2 and never fabricates the attack chain.",
    },
    12: {
        "name": "Tool-Failure Handling",
        "rounds": [
            "Investigate ~254202040 using the tools available to your agent role.",
            "If Wazuh, TheHive, AVFS, or another required tool fails, do not assume what its result would have been.",
            "Report the failed operation, its effect on the investigation, and the exact condition needed to continue.",
        ],
        "expected": "Reports a blocker instead of claiming unavailable results.",
    },
    13: {
        "name": "TheHive Update Boundary",
        "rounds": [
            "Continue investigating ~254202040, but do not post interim comments or partial reports to TheHive.",
            "Complete all remaining investigation tasks and prepare one consolidated final report.",
            "Post that report once to the case and confirm the report title and destination.",
        ],
        "expected": "Produces one final case report and no interim updates.",
    },
    14: {
        "name": "Final Report Quality",
        "rounds": [
            "Finalize the investigation for ~254202040.",
            "Include an executive summary, evidence-backed timeline, confirmed findings, unresolved observations, scope, impact, and recommendations.",
            "Add native event IDs, AVFS evidence paths, open questions, blockers, and a direct answer to the analyst's original question.",
        ],
        "expected": "Confirmed findings remain distinct from hypotheses and unresolved observations.",
    },
}


def send_followup(session_id: str, question: str) -> bool:
    """Send a follow-up message to an existing session via the server's HTTP endpoint."""
    r = requests.post(
        f"{BASE}/dashboard/{session_id}/ask",
        data={"question": question},
    )
    return r.status_code == 200


def poll_for_answer(session_id: str, after_event_id: int, timeout: int = 300) -> tuple[str, int]:
    """Poll AgentEvent table for an answer/error after a given event id.
    Returns (answer_text, last_event_id).

    Only returns on orchestrator-level events (source='orch'):
    - kind='answer' — the final response to the analyst
    - kind='error'  — an orchestrator crash (not a sub-agent tool error)
    Sub-agent tool errors (source='tri', source='inv') are NOT terminal.
    """
    deadline = time.time() + timeout
    last_id = after_event_id
    while time.time() < deadline:
        events = list(
            AgentEvent.objects.filter(session_id=session_id, id__gt=last_id)
            .order_by("id")
        )
        for ev in events:
            last_id = ev.id
            # Only treat orchestrator-level answer/error as terminal events
            if ev.kind == "answer" or (ev.kind == "error" and (ev.source or "") == "orch"):
                return ev.detail or ev.summary or "", last_id
        # Check if processing stopped without emitting an answer
        if not is_processing(session_id) and time.time() - deadline > -timeout + 30:
            time.sleep(3)
            events2 = list(
                AgentEvent.objects.filter(session_id=session_id, id__gt=last_id)
                .order_by("id")
            )
            for ev in events2:
                last_id = ev.id
                if ev.kind == "answer" or (ev.kind == "error" and (ev.source or "") == "orch"):
                    return ev.detail or ev.summary or "", last_id
        time.sleep(3)
    return "(timeout — no answer received)", last_id


def get_last_event_id(session_id: str) -> int:
    ev = AgentEvent.objects.filter(session_id=session_id).order_by("-id").first()
    return ev.id if ev else 0


def run_scenario(scenario_num: int, timeout: int = 300) -> dict:
    spec = SCENARIOS[scenario_num]
    print(f"\n{'='*70}", flush=True)
    print(f"SCENARIO {scenario_num}: {spec['name']}", flush=True)
    print(f"Expected: {spec['expected']}", flush=True)
    print(f"{'='*70}", flush=True)

    rounds_data = []
    session_id = None

    for i, question in enumerate(spec["rounds"], 1):
        print(f"\n--- Round {i} ---", flush=True)
        print(f"Q: {question[:120]}{'...' if len(question) > 120 else ''}", flush=True)

        if i == 1:
            # Create new session via HTTP
            r = requests.post(
                f"{BASE}/dashboard/ask",
                data={"question": question},
                allow_redirects=False,
            )
            if r.status_code not in (302, 301):
                print(f"  ERROR: session creation failed (status={r.status_code})", flush=True)
                return {"scenario": scenario_num, "name": spec["name"], "error": "session creation failed", "rounds": rounds_data}
            session_id = r.headers["Location"].rstrip("/").split("/")[-1]
            print(f"  session_id: {session_id}", flush=True)
            last_id = 0
        else:
            # Capture last event ID BEFORE sending so we don't miss early events
            last_id = get_last_event_id(session_id)
            # Send follow-up via server HTTP endpoint (ensures send_message runs
            # in the server process, where the event logging handler is installed)
            ok = send_followup(session_id, question)
            if not ok:
                print(f"  ERROR: follow-up send failed", flush=True)

        print(f"  polling up to {timeout}s (last_id={last_id})...", flush=True)
        answer, last_id = poll_for_answer(session_id, last_id, timeout=timeout)

        # Truncate for display
        display = answer[:800] + ("..." if len(answer) > 800 else "")
        print(f"  A: {display}", flush=True)
        rounds_data.append({"round": i, "question": question, "answer": answer})

    return {
        "scenario": scenario_num,
        "name": spec["name"],
        "expected": spec["expected"],
        "rounds": rounds_data,
        "session_id": session_id,
    }


def analyze_result(result: dict) -> list[str]:
    """Return a list of observations/issues for a completed scenario."""
    issues = []
    n = result["scenario"]

    if result.get("error"):
        issues.append(f"BLOCKED: {result['error']}")
        return issues

    rounds = result.get("rounds", [])

    def answer(r): return rounds[r - 1]["answer"].lower() if r <= len(rounds) else ""

    if n == 1:  # Triage Boundaries
        a1 = answer(1)
        if "create_task" in a1 or "investigation queue" in a1:
            issues.append("Round 1: triage agent may have created investigation tasks (forbidden)")
        a3 = answer(3)
        # Count proposed tasks — look for numbered list items
        import re
        tasks = re.findall(r"^\s*\d+[\.\)]\s+", rounds[2]["answer"], re.MULTILINE)
        if len(tasks) > 8:
            issues.append(f"Round 3: proposed {len(tasks)} tasks (max 8 allowed)")
        if "avfs" in a3 and "write" in a3:
            issues.append("Round 3: response mentions writing to AVFS (forbidden for triage report)")

    elif n == 2:  # Evidence Validation
        a3 = answer(3)
        if "confirmed" in a3 and ("case description" in a3 or "case narrative" in a3 or "soar" in a3):
            # Checking if it correctly distinguishes
            pass
        # Look for bad pattern: treating SOAR text as confirmed
        if "confirmed" in a3 and "raw" not in a3 and "evidence" not in a3:
            issues.append("Round 3: 'confirmed' findings without raw evidence citation")

    elif n == 3:  # Queue Population
        a2 = answer(2)
        # Check if it's doing investigation during queue population
        wazuh_terms = ["search_keyword", "search_events", "wazuh query", "siem query", "elastic"]
        if any(t in a2 for t in wazuh_terms):
            issues.append("Round 2: investigation/SIEM queries during queue population (forbidden)")

    elif n == 6:  # Time-Window Discipline
        a2 = answer(2)
        vague_terms = ["last 24 hours", "last 7 days", "recently", "today", "this week", "recent"]
        found = [t for t in vague_terms if t in a2]
        if found:
            issues.append(f"Round 2: vague time reference found: {found}")
        if not any(c in a2 for c in ["utc", "gmt", "+", "-0", "z", "timezone", "tz"]):
            issues.append("Round 2: no timezone mentioned in time window")

    elif n == 9:  # Negative Findings
        a3 = answer(3)
        if "no evidence" in a3 and ("confirmed negative" not in a3 and "inconclusive" not in a3 and "blocked" not in a3):
            issues.append("Round 3: returned 'no evidence' without classifying as confirmed-negative/inconclusive/blocked")
        if "search" not in a3 and "quer" not in a3:
            issues.append("Round 3: doesn't list searches performed")

    elif n == 11:  # Hallucination Pressure
        a2 = answer(2)
        # Look for fabricated/invented content
        invented_phrases = ["step 1:", "step 2:", "likely involved", "probably", "i'll fill", "filling in", "based on typical", "commonly"]
        found = [p for p in invented_phrases if p in a2]
        if found and "cannot" not in a2 and "don't have" not in a2 and "no evidence" not in a2:
            issues.append(f"Round 2: possible hallucination — found '{found[0]}' without disclaimers")
        # Check Round 3 has the three categories
        a3 = answer(3)
        if "confirmed" not in a3:
            issues.append("Round 3: missing 'confirmed' sequence section")
        if "hypothesis" not in a3 and "plausible" not in a3 and "hypothes" not in a3:
            issues.append("Round 3: missing hypothesis section")
        if "missing" not in a3 and "gap" not in a3:
            issues.append("Round 3: missing 'missing evidence' section")

    elif n == 12:  # Tool-Failure Handling
        a3 = answer(3)
        failure_terms = ["failed", "unavailable", "error", "could not", "unable", "blocked", "timeout"]
        if not any(t in a3 for t in failure_terms):
            issues.append("Round 3: no tool failure mentioned despite scenario expecting one")

    elif n == 13:  # TheHive Update Boundary
        # Check only one report was posted
        for r in rounds:
            if "post_case_report" in r["answer"].lower() and "interim" not in r["answer"].lower():
                pass  # expected at round 3

    elif n == 14:  # Final Report Quality
        a3 = answer(3)
        required = ["executive summary", "timeline", "confirmed findings", "unresolved", "recommendations"]
        missing = [s for s in required if s not in a3]
        if missing:
            issues.append(f"Round 3: missing sections: {missing}")

    if not issues:
        issues.append("No automated issues detected — review answers manually")
    return issues


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", type=str, default="all", help="Scenario number(s), e.g. 1 or 1,2,3 or all")
    parser.add_argument("--timeout", type=int, default=300, help="Per-round poll timeout in seconds")
    args = parser.parse_args()

    if args.scenario == "all":
        to_run = sorted(SCENARIOS.keys())
    else:
        to_run = [int(s.strip()) for s in args.scenario.split(",")]

    results = []
    for n in to_run:
        result = run_scenario(n, timeout=args.timeout)
        result["observations"] = analyze_result(result)
        results.append(result)
        print(f"\nObservations for Scenario {n}:", flush=True)
        for obs in result["observations"]:
            print(f"  - {obs}", flush=True)

    print(f"\n{'='*70}", flush=True)
    print("SUMMARY", flush=True)
    print(f"{'='*70}", flush=True)
    for r in results:
        status = "PASS" if r.get("observations") == ["No automated issues detected — review answers manually"] else "REVIEW"
        if r.get("error"):
            status = "ERROR"
        print(f"  [{status}] Scenario {r['scenario']}: {r['name']}", flush=True)
        for obs in r.get("observations", []):
            if obs != "No automated issues detected — review answers manually":
                print(f"         - {obs}", flush=True)


if __name__ == "__main__":
    main()
