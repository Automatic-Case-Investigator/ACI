from __future__ import annotations

from pathlib import Path

from .prompt_sections import build_run_context_sections

# prompts.py lives at agent/runtime/config/; the prompt layers live at agent/prompts/.
# That is three parents up (config -> runtime -> agent), then /prompts.
_PROMPTS_DIR = Path(__file__).resolve().parent.parent.parent / "prompts"
_LAYER_FILES = ["identity.md", "capabilities.md", "instructions.md"]


def _load_layer(layer: str) -> str:
    parts: list[str] = []
    for filename in _LAYER_FILES:
        path = _PROMPTS_DIR / layer / filename
        if path.exists():
            parts.append(path.read_text(encoding="utf-8").strip())
    return "\n\n".join(parts)


# Layers that carry immutable identity / safety / tool behavior belong under `# SYSTEM`;
# everything else (per-agent workflow, methodology, playbook) is `# DEVELOPER`. Same content
# as before — grouped by role so the model can tell "my rules" from "my method", and the
# stable SYSTEM+DEVELOPER prefix is cache-friendly. Provider-agnostic: plain text headers, no
# provider-specific message roles. run_context (live per-run state) is appended after, as today.
_SYSTEM_LAYERS = frozenset({"platform"})


def compose_system_prompt(prompt_layers: list[str], run_context: dict) -> str:
    system_parts: list[str] = []
    developer_parts: list[str] = []
    for layer in prompt_layers:
        text = _load_layer(layer)
        if not text:
            continue
        (system_parts if layer in _SYSTEM_LAYERS else developer_parts).append(text)
    sections: list[str] = []
    if system_parts:
        sections.append("# SYSTEM\n\n" + "\n\n---\n\n".join(system_parts))
    if developer_parts:
        sections.append("# DEVELOPER\n\n" + "\n\n---\n\n".join(developer_parts))
    sections.append(_format_run_context(run_context))
    return "\n\n---\n\n".join(sections)


def _format_run_context(ctx: dict) -> str:
    return "\n\n".join(build_run_context_sections(ctx))
