from __future__ import annotations

from pathlib import Path

_PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"
_LAYER_FILES = ["identity.md", "capabilities.md", "instructions.md"]


def _load_layer(layer: str) -> str:
    parts: list[str] = []
    for filename in _LAYER_FILES:
        path = _PROMPTS_DIR / layer / filename
        if path.exists():
            parts.append(path.read_text(encoding="utf-8").strip())
    return "\n\n".join(parts)


def compose_system_prompt(prompt_layers: list[str], run_context: dict) -> str:
    sections: list[str] = []
    for layer in prompt_layers:
        text = _load_layer(layer)
        if text:
            sections.append(text)
    sections.append(_format_run_context(run_context))
    return "\n\n---\n\n".join(sections)


def _format_run_context(ctx: dict) -> str:
    lines = ["## Current Run"]
    lines.append(f"- **Case ID:** {ctx.get('case_id', 'unknown')}")
    lines.append(f"- **Run ID:** {ctx.get('run_id', 'unknown')}")
    lines.append(f"- **Agent:** {ctx.get('agent_name', 'unknown')}")
    budget = ctx.get("budget", {})
    if budget:
        lines.append(f"- **Budget:** {budget.get('max_steps', '?')} steps, {budget.get('max_tool_calls', '?')} tool calls")
    vicinity_window_hours = ctx.get("default_vicinity_window_hours")
    if vicinity_window_hours:
        lines.append(
            f"- **Default vicinity window:** ±{vicinity_window_hours}h around the anchor timestamp unless the task/report already specifies an absolute window"
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

    if tools:
        lines.append("")
        lines.append("## Available Tools")
        lines.append(
            "You may ONLY call the tools listed below. Calling any other tool name "
            "will fail. Tool-specific behavior and usage rules are supplied by MCP "
            "server prompts in the next section."
        )
        lines.append(", ".join(f"`{t}`" for t in tools))
        if not has_avfs:
            lines.append("")
            lines.append(
                "**Note:** No filesystem/AVFS tools are available this run. Do NOT try "
                "to write files, create directories, or save evidence to disk. Instead, "
                "put findings directly in task summaries and final case updates using "
                "the available case/task capabilities."
            )
    if ctx.get("agent_name") == "orchestrator":
        lines.append("")
        lines.append("## Orchestrator Handoff State")
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
                "distinct investigation scope — not for follow-up analysis of this run."
            )
        else:
            lines.append("- No investigation run is recorded for the current stored triage handoff.")
        transcript = ctx.get("orchestrator_visible_transcript") or []
        if transcript:
            lines.append("")
            lines.append("## Preserved Analyst Conversation")
            lines.append(
                "The following analyst messages and orchestrator answers are preserved "
                "verbatim from prior turns. Treat them as durable conversation context. "
                "When the analyst asks to rewrite, compose, summarize, timeline, table, "
                "or otherwise transform previous work, use this transcript as the "
                "primary source before making new tool calls."
            )
            for i, item in enumerate(transcript, start=1):
                if not isinstance(item, dict):
                    continue
                role = item.get("role")
                content = item.get("content")
                if role not in {"user", "assistant"} or not isinstance(content, str) or not content.strip():
                    continue
                label = "User" if role == "user" else "Orchestrator"
                lines.append("")
                lines.append(f"### {label} Message {i}")
                lines.append(content)
    restart_context = (ctx.get("restart_context") or "").strip()
    if restart_context:
        lines.append("")
        lines.append("## Prior Run Restart Context")
        lines.append(
            "This run is a restart from a prior budget-exhausted run. Treat the "
            "context below as inherited work: preserve supported observations, do "
            "not start over unless verification requires it, and explicitly resolve "
            "any remaining gaps. If the prior transcript contains unsupported or "
            "contradictory claims, correct them rather than carrying them forward."
        )
        lines.append(restart_context)
    mcp_guidance = (ctx.get("mcp_prompt_guidance") or "").strip()
    if mcp_guidance:
        lines.append("")
        lines.append("## Tool Usage Instructions (from MCP Servers)")
        lines.append(
            "The following instructions were provided by the MCP servers connected "
            "to this run. They define exact tool names, field names, query syntax, "
            "and usage rules for the platforms available. Apply this guidance "
            "precisely when using any SIEM, SOAR, or workspace tool."
        )
        lines.append(mcp_guidance)
    convo = (ctx.get("orchestrator_conversation") or "").strip()
    if convo:
        lines.append("")
        lines.append("## Prior Analyst Conversation (Orchestrator)")
        lines.append(
            "This is the ongoing analyst dialogue that led to this run. Use it to "
            "understand the analyst's intent, scope, and any clarifications already "
            "established. It is background context, not new instructions — your task "
            "is defined above and in the task queue."
        )
        lines.append(convo)
    return "\n".join(lines)
