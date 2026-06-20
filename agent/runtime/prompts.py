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
    mcp_guidance = (ctx.get("mcp_prompt_guidance") or "").strip()
    if mcp_guidance:
        lines.append("")
        lines.append("## MCP Server Guidance")
        lines.append(
            "Tool-specific instructions below were retrieved from the MCP servers "
            "that provide the tools for this run. Follow this guidance when using "
            "those servers."
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
