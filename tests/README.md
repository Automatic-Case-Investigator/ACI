# Test Suite Layout

The suite is organized by execution level first, then by subsystem.

## Top-Level Buckets

- `unit/` — fast, local unit tests grouped by subsystem.
- `django/` — Django `TestCase` / request-level tests.
- `integration/` — broader scenario and runtime tests.

## Unit Subsystems

- `unit/analysis/` — deterministic analysis helpers, memory, verdict parsing, query memoization.
- `unit/config/` — agent definitions, prompt layers, settings overrides, tool visibility, workflow policy.
- `unit/graph/` — LangGraph node behavior, observation/interpretation/reflection, report synthesis, pivots.
- `unit/orchestrator/` — orchestrator session, checkpointing, streaming/publication behavior.
- `unit/providers/` — MCP/provider adapters and Wazuh query behavior.
- `unit/ti/` — threat-intelligence enrichment and cache behavior.

Run examples:

```bash
PYTHONPATH=. python -m pytest tests/unit/graph/test_observation_gating.py -q
PYTHONPATH=. python -m pytest tests/unit/providers -q
PYTHONPATH=. python -m pytest tests/unit tests/django -q
```
