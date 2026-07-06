# Prompt Composition

Prompt composition is intentionally layered:

- platform-agnostic agent identity, capabilities, and reasoning method live in
  `agent/prompts/`;
- runtime context assembly lives in `agent.runtime.config.prompts` and
  `agent.runtime.config.prompt_sections`;
- provider capability contracts are rendered separately from core reasoning
  instructions;
- MCP-specific tool semantics come from MCP server prompts, not from the core
  agent prompt;
- orchestrator-specific prompt behavior lives under
  `agent.runtime.orchestrator/`.

The run-context composer keeps these responsibilities separate:

- run metadata and budgets;
- tool availability;
- provider capability contracts;
- orchestrator handoff/session context;
- restart/resume inherited context;
- MCP guidance;
- preserved analyst conversation.

This boundary keeps the agent prompt portable while allowing provider-specific
guidance to evolve independently.

### Role altitude ladder

The assembled prompt is organized as an altitude ladder of headed sections, carried
entirely inside the standard LangChain message types (no provider-specific "developer"
role) so it runs identically on the self-hosted OpenAI-compatible endpoint:

- The `SystemMessage` (`compose_system_prompt`) opens with a `# SYSTEM` section
  (immutable identity / safety / tool behavior — the `platform` layer) followed by a
  `# DEVELOPER` section (per-agent workflow and methodology — the remaining layers).
- Each node's `HumanMessage` carries a `# USER` section (the current task) followed by
  a `# CONTEXT` section (live board/queue state and evidence).

The section headers are plain text, so the four-part structure is provider-agnostic:
it degrades to ordinary prompt text on any `ChatModel` while giving a stronger model a
clear identity/method/task/state separation.
