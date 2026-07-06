# Contributing to ACI

Thanks for contributing. ACI is a SOC investigation agent built as a **thin deterministic
harness around a strong general-purpose reasoning core**. Most of what makes it good is
*how it reasons*, not how much special-case code it accumulates — so the way you approach a
change matters as much as the change itself. This document describes the development
philosophy we hold contributions to, and the practical conventions of the codebase.

The full architectural philosophy lives in
[docs/architecture/overview.md](docs/architecture/overview.md); this is the contributor-facing
distillation.

## Development philosophy

The runtime's job is to provide structure, durable state, tooling, validation, and policy
boundaries. The model's job is to interpret, plan, prioritize, synthesize, and communicate.
When the system fails, prefer fixes that improve its **general** reasoning and reusable
workflow over patches that only handle one historical case.

1. **Optimize for broad capability, not edge-case accumulation.**
   Treat each failure as evidence of a broader weakness in reasoning, workflow, tool
   affordances, or state handling. A fix that raises quality across many incidents beats
   narrow logic that only addresses one manifestation. If you catch yourself writing
   `if <this specific case>`, stop and ask what general weakness it points to.

2. **Improve prompts before adding orchestration code.**
   If the failure is about interpretation, planning, uncertainty handling, prioritization,
   or communication, improve the prompt and method first. Add code only when the requirement
   is deterministic, cannot be expressed reliably in prompting, or must hold regardless of
   model quality.

3. **Favor methodology over prescriptions.**
   Teach the model *how to reason* — identify assumptions, separate facts from inferences,
   anchor on evidence, explain uncertainty, verify before concluding — rather than adding
   long lists of hard-coded "if X do Y" rules. Prefer general reframing over hard-coded
   examples in prompts (no baked-in file extensions, paths, IPs, or rule IDs unless the
   situation is genuinely deterministic).

4. **Split semantic work from deterministic work.**
   Use the **LLM** for ambiguity resolution, planning, prioritization, summarization,
   contextual judgment, and evidence synthesis. Use **code** for routing, validation,
   parsing, formatting, state transitions, retries, caching, persistence, budgets,
   cancellation, and capability exposure. Do not ask the model to do what an algorithm can
   do exactly; do not encode semantic judgment as brittle regex.

5. **Keep the agent layer platform-agnostic.**
   Core prompts describe reasoning method, not Wazuh/TheHive/vendor quirks. Backend-specific
   query syntax, field names, and tool semantics belong in the MCP/provider guidance, so new
   integrations can be added without rewriting agent cognition. Agents reason in terms of
   stable capability roles (`search_events`, `fetch_event`, `read_case`, …); providers map
   those onto their own tool names.

6. **Separate capabilities from policy.**
   Reasoning architecture answers "how does the agent investigate well?" Policy answers
   "what is allowed?", "when may it act?", "what limits apply?" Keep authorization, safety
   constraints, and execution boundaries out of the reasoning loop.

7. **Prefer simple, explainable architecture.**
   When multiple solutions exist, choose the simpler one unless the extra complexity yields
   substantial *general* benefit. Every new node, state field, prompt exception, or adapter
   must justify its ongoing maintenance cost. Reduce accumulated complexity where you can.

### Practical decision order

When designing a fix or feature, apply this order and stop at the first that fits:

1. Reasoning/interpretation failure → improve prompts and method.
2. Reusable-workflow failure → improve the graph or phase structure.
3. Backend/tool-shape problem → improve the MCP/provider contract.
4. Genuinely deterministic → solve it in code.
5. Does the change generalize? If not, avoid it unless it protects correctness, safety, or
   durability.

## Working with the codebase

- **Harness vs. reasoning.** `agent/runtime/` is the harness: orchestration entrypoints,
  graph assembly, state, provider contracts, deterministic guarantees. Keep cognition in the
  prompt layers under `agent/prompts/`, kept modular (identity / capabilities / methodology /
  run-context / provider guidance stay conceptually separate).
- **File placement.** Entry points live higher in the tree; specialized helpers, transforms,
  and validators live deeper. Large modules are split into concern-scoped sub-packages
  (e.g. `graph/interpretation/`, `graph/nodes_flow/`).
- **The graph re-export contract.** Sub-packages under `agent/runtime/graph/` (and
  `runtime/orchestrator/`) re-export every public and private name through their `__init__.py`
  via a dynamic `globals()` loop, so `from agent.runtime.graph import X` and `graph._helper`
  keep resolving after a module is split. **Rule: submodules own the names; an `__init__`
  only re-exports — never define new behavior there.**
- **Refactors are behavior-preserving.** Reorganizing code should not change behavior. Move
  code verbatim, wire imports, and prove equivalence with the test suite before layering
  behavioral changes on top.
- **MCP-specific content** (query syntax, field names, tool mechanics) belongs with the MCP
  server or provider, not in the platform-agnostic agent prompt.

## Testing

All unit/Django tests run offline — no LLM, Wazuh, TheHive, or AVFS required. Run the suite
before every commit and ensure your change introduces **no new failures**:

```bash
PYTHONPATH=. python -m pytest tests/unit tests/django -q
```

- New behavior needs a test; a bug fix should come with a test that fails before it.
- Service-dependent end-to-end tests live in `tests/integration/` and are excluded from the
  offline run.
- See [docs/guides/operations.md](docs/guides/operations.md) for the test layout and
  individual-file commands.

## Changing prompts

Prompt changes are real changes — treat them with the same care as code.

- Prefer general methodology over hard-coded examples (see philosophy #3).
- Keep the agent prompt layers platform-agnostic; put backend quirks in provider guidance.
- The prompt-layer tests pin token budgets and key strings; keep them green, and only update
  a pinned string when a reorganization legitimately moves it.

## Submitting changes

1. Branch off `main` (do not commit directly to it).
2. Make the change; keep refactors and behavioral changes in separate commits where practical.
3. Run the offline suite and confirm no new failures.
4. Write a clear, imperative commit message describing *what* changed and *why*.
5. Open a pull request describing the problem, the approach, and how you verified it.

## Documentation

Documentation lives in [`docs/`](docs/README.md), organized by subsystem. If your change
alters the runtime shape, a graph node, the prompt structure, configuration, or the API,
update the corresponding doc in the same change.
