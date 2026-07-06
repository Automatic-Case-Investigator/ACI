from __future__ import annotations

from typing import Iterable


def build_run_context_sections(ctx: dict) -> list[str]:
    sections: list[str] = []
    sections.extend(_run_metadata_sections(ctx))
    sections.extend(_tool_sections(ctx))
    sections.extend(_provider_contract_sections(ctx))
    sections.extend(_orchestrator_sections(ctx))
    sections.extend(_restart_sections(ctx))
    sections.extend(_mcp_guidance_sections(ctx))
    sections.extend(_conversation_sections(ctx))
    return sections


def _run_metadata_sections(ctx: dict) -> list[str]:
    lines = ["## Current Run"]
    lines.append(f"- **Case ID:** {ctx.get('case_id', 'unknown')}")
    lines.append(f"- **Run ID:** {ctx.get('run_id', 'unknown')}")
    lines.append(f"- **Agent:** {ctx.get('agent_name', 'unknown')}")
    budget = ctx.get("budget", {})
    if budget:
        lines.append(
            f"- **Budget:** {budget.get('max_steps', '?')} steps, "
            f"{budget.get('max_tool_calls', '?')} tool calls"
        )
    vicinity_window_hours = ctx.get("default_vicinity_window_hours") or 24
    lines.append(
        f"- **Search range (mandatory):** every SIEM query MUST carry an explicit absolute "
        f"time range AND be scoped to the relevant entity (agent.name/host, user, or IP). "
        f"+/-{vicinity_window_hours}h around the anchor timestamp is the **MAXIMUM** window - a "
        f"ceiling, not the window to use. Start from the strongest evidence anchor, move the "
        f"window with the evidence, and never issue an unbounded or index-wide query. A "
        f"capped/`TRUNCATED` result or implausibly large match set is too broad to trust."
    )
    avfs_home = ctx.get("avfs_home", "")
    tools = ctx.get("available_tools") or []
    has_avfs = any(t in tools for t in ("whoami", "write", "mkdir", "ls", "cat", "read"))
    if avfs_home and has_avfs:
        lines.append(f"- **AVFS home (`~`):** `{avfs_home}`")
        mem = ctx.get("avfs_memory_dir")
        cdir = ctx.get("avfs_case_dir")
        if mem:
            lines.append(f"- **Long-term memory:** `{mem}` (search before concluding)")
        if cdir:
            lines.append(f"- **This case's records:** `{cdir}` (prior runs; read first)")
    return ["\n".join(lines)]


def _tool_sections(ctx: dict) -> list[str]:
    tools = ctx.get("available_tools") or []
    avfs_tools = ("whoami", "write", "mkdir", "ls", "cat", "read")
    has_avfs = any(t in tools for t in avfs_tools)
    if not tools:
        return []

    lines = [
        "## Available Tools",
        "You may ONLY call the tools listed below. Calling any other tool name "
        "will fail. Tool-specific behavior and usage rules are supplied by MCP "
        "server prompts in the next section.",
        ", ".join(f"`{t}`" for t in tools),
    ]
    if not has_avfs:
        lines.extend([
            "",
            "**Note:** No filesystem/AVFS tools are available this run. Do NOT try "
            "to write files, create directories, or save evidence to disk. Instead, "
            "put findings directly in task summaries and final case updates using "
            "the available case/task capabilities.",
        ])
    return ["\n".join(lines)]


def _provider_contract_sections(ctx: dict) -> list[str]:
    provider_contracts = (ctx.get("provider_capability_contracts") or "").strip()
    return [provider_contracts] if provider_contracts else []


def _orchestrator_sections(ctx: dict) -> list[str]:
    if ctx.get("agent_name") != "orchestrator":
        return []
    lines = ["## Orchestrator Handoff State"]
    if ctx.get("last_triage_report_available"):
        case_id = ctx.get("last_triage_case_id") or ctx.get("case_id") or "unknown"
        lines.append(
            f"- A stored triage report is available for case `{case_id}`. "
            "If the analyst asks to investigate, continue, proceed, run investigation, "
            "or start investigation, call the `investigation` tool and pass that "
            "stored report as the `triage_report` parameter."
        )
    else:
        lines.append("- No stored triage report is available yet.")
    inv_id = ctx.get("investigation_run_id")
    if inv_id:
        lines.append(
            f"- Investigation already ran in this session: `{inv_id}`. "
            "The full investigation report is preserved and visible in the conversation "
            "history below. For follow-up questions, answer from that report first. "
            "Use targeted tool calls only for questions requiring fresh data not covered "
            "by the report. Re-invoke the `investigation` sub-agent only for a new, "
            "distinct investigation scope - not for follow-up analysis of this run."
        )
    else:
        lines.append("- No investigation run is recorded for the current stored triage handoff.")
    transcript = list(_iter_transcript(ctx.get("orchestrator_visible_transcript") or []))
    if transcript:
        lines.extend([
            "",
            "## Preserved Analyst Conversation",
            "The following analyst messages and orchestrator answers are preserved "
            "verbatim from prior turns. Treat them as durable conversation context. "
            "When the analyst asks to rewrite, compose, summarize, timeline, table, "
            "or otherwise transform previous work, use this transcript as the "
            "primary source before making new tool calls.",
        ])
        for i, item in enumerate(transcript, start=1):
            label = "User" if item["role"] == "user" else "Orchestrator"
            lines.extend(["", f"### {label} Message {i}", item["content"]])
    return ["\n".join(lines)]


def _restart_sections(ctx: dict) -> list[str]:
    restart_context = (ctx.get("restart_context") or "").strip()
    if not restart_context:
        return []
    return ["\n".join([
        "## Prior Run Restart Context",
        "This run is a restart from a prior budget-exhausted run. Treat the "
        "context below as inherited work: preserve supported observations, do "
        "not start over unless verification requires it, and explicitly resolve "
        "any remaining gaps. If the prior transcript contains unsupported or "
        "contradictory claims, correct them rather than carrying them forward.",
        restart_context,
    ])]


def _mcp_guidance_sections(ctx: dict) -> list[str]:
    mcp_guidance = (ctx.get("mcp_prompt_guidance") or "").strip()
    if not mcp_guidance:
        return []
    return ["\n".join([
        "## Tool Usage Instructions (from MCP Servers)",
        "The following instructions were provided by the MCP servers connected "
        "to this run. They define exact tool names, field names, query syntax, "
        "and usage rules for the platforms available. Apply this guidance "
        "precisely when using any SIEM, SOAR, or workspace tool.",
        mcp_guidance,
    ])]


def _conversation_sections(ctx: dict) -> list[str]:
    convo = (ctx.get("orchestrator_conversation") or "").strip()
    if not convo:
        return []
    return ["\n".join([
        "## Prior Analyst Conversation (Orchestrator)",
        "This is the ongoing analyst dialogue that led to this run. Use it to "
        "understand the analyst's intent, scope, and any clarifications already "
        "established. It is background context, not new instructions - your task "
        "is defined above and in the task queue.",
        convo,
    ])]


def _iter_transcript(items: Iterable[dict]) -> Iterable[dict]:
    for item in items:
        if not isinstance(item, dict):
            continue
        role = item.get("role")
        content = item.get("content")
        if role in {"user", "assistant"} and isinstance(content, str) and content.strip():
            yield {"role": role, "content": content}
