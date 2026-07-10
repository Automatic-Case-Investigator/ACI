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
from datetime import datetime, timezone

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

# Explicit per-item priority stated in the triage report, e.g. "- Priority: 85"
# (the triage `## Investigation Plan` format mandates a Priority line per item).
# Anchored on the word "priority" so a bare pivot number (rule.id=31151) can't match.
_EXPLICIT_PRIORITY_RE = re.compile(r"\bpriorit(?:y|ies)\b\s*[:=]?\s*\(?\s*(\d{1,3})\b", re.IGNORECASE)

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

# Timeline decomposition (Phase 1.5): cap how many candidates we surface, and their band.
_MAX_TIMELINE_SEGMENTS = 6
_TIMELINE_COVERAGE_PRIORITY = 70  # transition/scoping band — below confirmed-forward leads

# Absolute ISO-8601 timestamps the triage handoff cites, used to bound the incident span.
_ISO_TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})")


def _parse_iso_dt(text: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _incident_window(*texts: str) -> tuple[str, str] | None:
    """Bound the incident span [earliest, latest] from ISO timestamps cited across the
    triage handoff. Returns None when fewer than two distinct instants appear — there is
    nothing to decompose."""
    parsed = {d for t in texts for m in _ISO_TS_RE.finditer(t or "")
              if (d := _parse_iso_dt(m.group(0))) is not None}
    if len(parsed) < 2:
        return None
    def _iso(d: datetime) -> str:
        return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return _iso(min(parsed)), _iso(max(parsed))


async def _timeline_segment_specs(tmap: dict, window: tuple[str, str]) -> list[dict]:
    """Profile the incident window into its distinct activity bursts (deterministic).

    Code localizes *where in time* activity clusters; the model (per burst-task) does the
    semantic work of naming which phase each cluster is. Only returns segments when the
    profile found genuine temporal STRUCTURE (>=2 distinct bursts) — a single burst that
    fills the window is not a decomposition. Fail-open: any error yields no segments.
    """
    vol_fn = tmap.get("get_event_volume")
    if vol_fn is None:
        return []
    start, end = window
    try:
        raw = await _call(vol_fn, {"start_time": start, "end_time": end, "bins": 48}, _dbg=_SRC)
        data = json.loads(raw) if isinstance(raw, str) else raw
    except Exception:
        return []
    if not isinstance(data, dict) or data.get("error"):
        return []
    bursts = [b for b in (data.get("bursts") or []) if b.get("start") and b.get("end")]
    if len(bursts) < 2:
        return []
    return [{"start": b["start"], "end": b["end"]} for b in bursts[:_MAX_TIMELINE_SEGMENTS]]


def _timeline_coverage_description(segments: list[dict]) -> str:
    """Build one recall-preserving coverage task from all detected timeline candidates."""
    lines = [
        "A deterministic volume profile found multiple distinct activity candidates. "
        "Do not treat this map as a conclusion, and do not silently drop any candidate. "
        "For each candidate below, assign one disposition: covered by a cited finding, "
        "converted into a concrete New Lead, or ruled unrelated/benign with evidence.",
        "",
        "Timeline coverage candidates:",
    ]
    for idx, seg in enumerate(segments, 1):
        lines.append(f"{idx}. {seg['start']} to {seg['end']}")
    lines.extend([
        "",
        "Consolidate redundant side windows when they share the same objective, but preserve "
        "the candidate list and state the disposition for every window. Done when: every "
        "candidate above has a disposition with a supporting event/probe result, or an "
        "evidence-backed lead remains queued for the unresolved part.",
    ])
    return "\n".join(lines)


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
    """Return the task priority for a plan item.

    Prefer the priority the triage report explicitly stated for the item — the
    `## Investigation Plan` format mandates a `Priority: N` line per item, and the
    seeder must preserve that analyst-facing ranking rather than re-deriving its
    own. Keyword inference is only a fallback for items that state no priority
    (e.g. a malformed plan, or a `## New Leads` item that omitted it).
    """
    m = _EXPLICIT_PRIORITY_RE.search(item or "")
    if m:
        value = int(m.group(1))
        if 0 <= value <= 100:
            return value
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

    # ── Phase 1.5: deterministic timeline decomposition ─────────────────────────
    # The agent reliably covers the burst adjacent to its anchor but walks the rest of
    # the timeline only by chance, so mid-chain phases are missed at random. Split the
    # incident's time span into its distinct activity bursts and seed one task per burst,
    # making temporal coverage systematic rather than opportunistic. Code localizes the
    # bursts (deterministic); the model names each burst's phase (semantic). Fail-open —
    # no window or no multi-burst structure simply seeds nothing here.
    window = _incident_window(handoff.triage_report or "", handoff.analyst_request or "")
    segments = await _timeline_segment_specs(tmap, window) if window else []
    if segments:
        title = "Account for timeline coverage candidates across the incident window"
        description = _timeline_coverage_description(segments)
        result = await _call(create_fn, {
            "title": title, "description": description, "priority": _TIMELINE_COVERAGE_PRIORITY,
        }, _dbg=_SRC)
        if _is_error_tool_result(result):
            emit(_SRC, "error", "seeder: timeline coverage create_task failed", detail=result)
        else:
            emit(_SRC, "note",
                 f"seeder: timeline coverage map with {len(segments)} candidate(s) "
                 f"(P{_TIMELINE_COVERAGE_PRIORITY})")
            created_refs.append(_task_ref({
                "title": title, "description": description, "status": "pending",
            }))

    # ── Phase 2: model pass for mandatory supplementary tasks ───────────────────
    # The model checks for mandatory tasks not covered by the plan (C2 destination
    # pivots, initial-access vector) and verifies completeness via list_tasks.
    # If the plan section was missing entirely, the model creates all tasks.
    system_prompt = compose_system_prompt(seeder_def.prompt_layers, {})
    human_content = _build_model_input(handoff, plan_items, direct_creates, vicinity_hours, segments)

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
    timeline_segments: list[dict] | None = None,
) -> str:
    """Build the Phase 2 model prompt describing what was already created."""
    parts: list[str] = []

    if handoff.analyst_request:
        parts.append(f"**Analyst request:** {handoff.analyst_request}")
        parts.append("")
    if handoff.source_entity_id or handoff.source_entity_type:
        parts.append(
            f"**Source entity:** {handoff.source_entity_type or 'unknown'} "
            f"`{handoff.source_entity_id or 'unknown'}`"
        )
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

    if timeline_segments:
        parts.append("## Timeline coverage map already queued")
        parts.append(
            "A single coverage task already accounts for these candidates. Do not create "
            "one duplicate task per window; create supplementary tasks only for distinct "
            "evidence-backed objectives not covered by that map."
        )
        for i, seg in enumerate(timeline_segments, 1):
            parts.append(f"{i}. {seg['start']} to {seg['end']}")
        parts.append("")

    if direct_creates > 0 or timeline_segments:
        parts.append(
            f"## Already created ({direct_creates + (1 if timeline_segments else 0)} task(s) — do NOT duplicate these)"
        )
        parts.append("")
        for i, item in enumerate(plan_items, 1):
            parts.append(f"{i}. {_item_title(item)}")
        if timeline_segments:
            parts.append(f"{len(plan_items) + 1}. Account for timeline coverage candidates across the incident window")
        parts.append("")
        parts.append(
            "## Your job\n"
            "1. Call `list_tasks` to confirm all tasks above exist.\n"
            "2. If any is missing, recreate it with `create_task`.\n"
            "3. Check the triage report below for high-value evidence paths NOT already queued. "
            "Prefer tasks that directly prove an adjacent activity stage on the affected asset "
            "over speculative broad pivots. A good supplementary task names the evidence type, "
            "entity, representation, and absolute time window it will test.\n"
            "4. Add a supplementary task only when the report itself cites an indicator the queue "
            "does not yet pivot on (a named entity, an encoded/obfuscated artifact, an adjacent "
            "event class). Ground every task in evidence the report actually states — do not add a "
            "task to fill a phase the report never mentions (initial access, callback/C2, "
            "exfiltration, etc.); the platform already queues a deterministic establish-or-rule-out "
            "task for each missing phase, so a fabricated one only adds noise. If a small scoped "
            "hit set is already mentioned, the task should retrieve and interpret representative "
            "raw events before broadening to another entity.\n"
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
