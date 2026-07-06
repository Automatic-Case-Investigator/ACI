from __future__ import annotations

"""Lightweight seeder runner: parse triage handoff and create investigation tasks.

Task creation strategy
----------------------
Plan items are extracted deterministically from the ## Investigation Plan section
of the triage report and written to the task queue with direct `create_task` calls
— no model involvement for the core N-item loop. This guarantees exactly one task
per plan item regardless of model behaviour.

A second model pass runs after the direct creates to add any mandatory tasks that
the triage plan may have omitted (C2 destination pivots, initial-access vector),
and to verify the queue is complete via `list_tasks`.
"""

import json
import logging
import re

from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage

from ...agents.base import Handoff
from ...agents.registry import get_agent
from ..config.prompts import compose_system_prompt
from ..graph.toolio import _call, _invoke_bound_model, _is_error_tool_result, _tmap
from ..infra.logbus import emit, src_label

log = logging.getLogger(__name__)

_SEEDER_TOOLS = frozenset({"create_task", "list_tasks"})

# Locate the ## Investigation Plan (or ## New Leads) section body.
_PLAN_SECTION_RE = re.compile(
    r"(?:^|\n)##\s+(?:Investigation Plan|New Leads)\s*\n(.*?)(?=\n##\s+|\Z)",
    re.DOTALL | re.IGNORECASE,
)

# Each numbered item: "1. ..." up to the next "N. ..." or end-of-section.
_PLAN_ITEM_RE = re.compile(
    r"^\s*(\d+)\.\s+(.*?)(?=^\s*\d+\.\s+|\Z)",
    re.DOTALL | re.MULTILINE,
)

# Matches conditional title prefixes the triage model occasionally generates.
# "If any cron entry appears suspicious" → subject = "cron entry" → "Investigate cron entry"
_CONDITIONAL_TITLE_RE = re.compile(
    r"^(?:if|when|should|whenever)\s+(?:any|the|a|an|this)?\s*(.+?)\s+"
    r"(?:appears?|is|are|was|were|seem|looks?|exist|occur)\b",
    re.IGNORECASE,
)

# Priority keyword mapping — checked in order; first match wins.
_PRIORITY_RULES: list[tuple[int, list[str]]] = [
    (95, ["webshell", "reverse shell", "privilege escalation", "sudo", "command execution",
          "decoded", "payload", "encoded", "credential"]),
    (90, ["initial access", "successful login", "remote login", "ssh session", "pam session"]),
    (80, ["c2", "callback", "attacker-controlled", "attacker controlled"]),
    (75, ["persistence", "crontab", "cron", "startup", "scheduled task", "authorized_key",
          "syscheck", "fim", "file-integrity", "file integrity"]),
    (60, ["correlate", "session context", "privilege", "scope", "disposition"]),
]

_TEMPORAL_VOLUME_KEYWORDS = (
    "scan",
    "scanner",
    "flood",
    "brute force",
    "brute-force",
    "password spraying",
    "400 error",
    "404",
    "4xx",
    "5xx",
    "too broad",
    "truncated",
    "post-peak",
    "tail",
    "volume",
)

_SRC = src_label("seeder")


def _extract_plan_items(report: str) -> list[str]:
    """Return each numbered item body from ## Investigation Plan / ## New Leads."""
    m = _PLAN_SECTION_RE.search(report or "")
    if not m:
        return []
    section = m.group(1)
    return [body.strip() for _, body in _PLAN_ITEM_RE.findall(section) if body.strip()]


def _item_title(item: str) -> str:
    """Extract a clean task title from the first line of a plan item.

    The triage prompt requires bold imperative titles, but the model occasionally
    produces conditional phrases ("If any X appears suspicious…"). In that case,
    extract the subject and rewrite to an imperative title.
    """
    first = item.split("\n")[0].strip()
    first = re.sub(r"\*\*(.+?)\*\*", r"\1", first)
    first = first.strip("- ").strip()

    m = _CONDITIONAL_TITLE_RE.match(first)
    if m:
        subject = m.group(1).strip().rstrip(",;")
        return f"Investigate {subject}"

    return first


def _item_priority(item: str) -> int:
    """Infer task priority from keywords present in the plan item text."""
    text = item.lower()
    for priority, keywords in _PRIORITY_RULES:
        if any(kw in text for kw in keywords):
            return priority
    return 65  # default — context/correlation


def _augment_temporal_method(item: str, vicinity_hours: int) -> str:
    """Add temporal-profiling guidance to noisy investigation tasks."""
    text = item.lower()
    if "get_event_volume" in text:
        return item
    if not any(keyword in text for keyword in _TEMPORAL_VOLUME_KEYWORDS):
        return item
    guidance = (
        "\n\nTemporal method: Treat the case/alert timestamp as a starting hint, "
        f"not the timeline center. Call `get_event_volume` over the full configured "
        f"vicinity/task window (±{vicinity_hours} hours unless this task specifies "
        "a different absolute range) before sampling raw events. Use the resulting "
        "pre-anchor, peak, post-peak tail, quiet-gap, and resumed-activity windows "
        "to choose follow-up `search` calls; do not spend the task only sampling "
        "the densest bucket."
    )
    return item.rstrip() + guidance


async def run_seeder(
    handoff: Handoff,
    tools: list,
    model,
    vicinity_hours: int = 24,
) -> None:
    """Parse the triage handoff and populate the investigation task queue.

    Uses the investigation's active MCP tool session so tasks are stamped with
    the investigation's (run_id, agent_name) and are immediately claimable.
    """
    seeder_def = get_agent("seeder")
    if seeder_def is None:
        emit(_SRC, "error", "seeder agent definition not found; skipping seed")
        return

    tmap = _tmap(tools)
    create_fn = tmap.get("create_task")
    if create_fn is None:
        emit(_SRC, "error", "create_task tool not available; skipping seed")
        return

    # Imported lazily: graph/__init__ -> nodes_loop -> engine.seeder_runner.run_seeder
    # forms a cycle if this is imported at module level.
    from ..graph.leads import LeadCandidate, _task_ref, duplicate_existing_task

    seeder_tools = [t for name, t in tmap.items() if name in _SEEDER_TOOLS]

    # ── Phase 1: deterministic task creation from extracted plan items ──────────
    plan_items = _extract_plan_items(handoff.triage_report or "")
    emit(_SRC, "note", f"seeder: starting — {len(plan_items)} plan item(s) extracted")

    # Deterministic dedup backstop for Phase 2 (model-proposed) creates, reusing the
    # same signature/objective/title-similarity matcher the pivot node's lead
    # validator already trusts (leads.py). Seeded here with the Phase-1 direct
    # creates so a Phase-2 task that duplicates a plan item is also caught, then
    # grown as each Phase-2 create executes — so two create_task calls proposing
    # the same task within a single seeding pass cannot both land.
    created_refs: list[dict] = []

    direct_creates = 0
    for item in plan_items:
        title = _item_title(item)
        priority = _item_priority(item)
        description = _augment_temporal_method(item, vicinity_hours)
        result = await _call(create_fn, {
            "title": title,
            "description": description,
            "priority": priority,
        }, _dbg=_SRC)
        direct_creates += 1
        if _is_error_tool_result(result):
            emit(_SRC, "error", f"seeder: create_task failed for '{title}'", detail=result)
        else:
            emit(_SRC, "note", f"seeder: created '{title}' (P{priority})")
            created_refs.append(_task_ref({
                "title": title, "description": description, "status": "pending",
            }))

    # ── Phase 2: model pass for mandatory supplementary tasks ───────────────────
    # The model checks for mandatory tasks not covered by the plan (C2 destination
    # pivots, initial-access vector) and verifies completeness via list_tasks.
    # If the plan section was missing entirely, the model creates all tasks.
    system_prompt = compose_system_prompt(seeder_def.prompt_layers, {})
    human_content = _build_model_input(handoff, plan_items, direct_creates, vicinity_hours)

    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=human_content),
    ]

    bound = model.bind_tools(seeder_tools)
    max_steps = seeder_def.budget.max_steps
    max_tool_calls = seeder_def.budget.max_tool_calls
    tool_calls_made = direct_creates  # count direct creates toward limit

    consecutive_empty = 0
    for _step in range(max_steps):
        response = await _invoke_bound_model(bound, messages, "seeder")
        messages.append(response)

        tool_calls = getattr(response, "tool_calls", None) or []
        if not tool_calls:
            consecutive_empty += 1
            if consecutive_empty >= 2:
                break
            continue
        consecutive_empty = 0

        for tc in tool_calls:
            if tool_calls_made >= max_tool_calls:
                emit(_SRC, "note", f"seeder: reached max_tool_calls ({max_tool_calls})")
                return
            name = tc.get("name", "")
            args = tc.get("args", {})
            tool = tmap.get(name)
            if tool is None:
                content = f"Error: tool '{name}' is not available to the seeder."
                emit(_SRC, "error", f"seeder: unknown tool '{name}'")
            elif name == "create_task" and (dup := duplicate_existing_task(
                LeadCandidate(
                    title=str(args.get("title") or ""), pivots="",
                    evidence=str(args.get("description") or ""), priority=0,
                ),
                created_refs,
            )):
                content = f"Skipped: {dup} — not created."
                emit(_SRC, "note", f"seeder: skipped duplicate '{args.get('title', '')}' ({dup})")
            else:
                content = await _call(tool, args, _dbg=_SRC)
                tool_calls_made += 1
                if name == "create_task" and not _is_error_tool_result(content):
                    created_refs.append(_task_ref({
                        "title": str(args.get("title") or ""),
                        "description": str(args.get("description") or ""),
                        "status": "pending",
                    }))
            messages.append(ToolMessage(
                content=str(content),
                tool_call_id=tc["id"],
                name=name,
            ))

    emit(_SRC, "note",
         f"seeder: finished — {direct_creates} direct + "
         f"{tool_calls_made - direct_creates} model tool call(s)")


def _build_model_input(
    handoff: Handoff,
    plan_items: list[str],
    direct_creates: int,
    vicinity_hours: int,
) -> str:
    """Build the Phase 2 model prompt describing what was already created."""
    parts: list[str] = []

    if handoff.analyst_request:
        parts.append(f"**Analyst request:** {handoff.analyst_request}")
        parts.append("")

    parts.append(
        f"**Default vicinity window:** ±{vicinity_hours} hours. "
        "Apply this to any item that lacks an explicit absolute time window. For "
        "scan/flood/brute-force or other noisy temporal pivots, supplementary tasks "
        "must say to use `get_event_volume` over the full configured window before "
        "sampling raw events, then query pre-anchor, post-peak tail, quiet-gap, or "
        "resumed-activity subwindows as evidence dictates."
    )
    parts.append("")

    if handoff.artifacts:
        parts.append("## Carried artifacts")
        parts.append("```json")
        parts.append(json.dumps(handoff.artifacts, indent=2, default=str))
        parts.append("```")
        parts.append("")

    if direct_creates > 0:
        parts.append(
            f"## Already created ({direct_creates} task(s) — do NOT duplicate these)"
        )
        parts.append("")
        for i, item in enumerate(plan_items, 1):
            parts.append(f"{i}. {_item_title(item)}")
        parts.append("")
        parts.append(
            "## Your job\n"
            "1. Call `list_tasks` to confirm all tasks above exist.\n"
            "2. If any is missing, recreate it with `create_task`.\n"
            "3. Check the triage report below for high-value evidence paths NOT already queued. "
            "Prefer tasks that directly prove an adjacent activity stage on the affected asset "
            "over speculative broad pivots. A good supplementary task names the evidence type, "
            "entity, representation, and absolute time window it will test.\n"
            "4. Add a supplementary task only when the current queue lacks a direct-evidence path "
            "for one of these broad gaps: initial access, execution/payload semantics, privilege "
            "change, persistence, callback/C2, or blast radius. If a small scoped hit set is "
            "already mentioned, the task should retrieve and interpret representative raw events "
            "before broadening to another entity.\n"
            "5. Do NOT add tasks that duplicate what is already queued."
        )
    else:
        parts.append(
            "## Your job\n"
            "No tasks have been created yet. Read the investigation plan below and call "
            "`create_task` for every item — one task per numbered item. "
            "Do not create a single merged/summary task."
        )

    parts.append("")
    parts.append("## Triage report")
    parts.append("")
    parts.append(handoff.triage_report or "(no triage report text provided)")
    return "\n".join(parts)
