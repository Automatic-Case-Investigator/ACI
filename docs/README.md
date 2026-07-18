# ACI Documentation

Documentation for the Autonomous Case Investigator, organized by subsystem.

## Architecture

How the system is designed, one document per subsystem.

- [Overview](architecture/overview.md) — system overview, top-level diagram, and design philosophy.
- **Runtime** — the agent engine:
  - [Agent Graph](architecture/runtime/agent-graph.md) — runtime entry, agent registry, the queue-driven node loop, and status/failure handling.
  - [Prompt Composition](architecture/runtime/prompts.md) — layered prompts and the SYSTEM/DEVELOPER/USER/CONTEXT role ladder.
  - [Queue & Model Streaming](architecture/runtime/queue-and-streaming.md) — task-queue semantics and live model streaming.
- [Orchestrator](architecture/orchestrator.md) — public reasoning before tools and session publication.
- [MCP & Tool Policy](architecture/tools.md) — providers, capability contracts, and Wazuh query robustness.
- [Findings Board](architecture/findings-board.md) — board entry kinds and board-driven compromise detection.
- [AVFS Workspace](architecture/workspace.md) — the durable case workspace.
- [Workflows & Webhooks](architecture/automation.md) — automation policy and triggers.

## Reference

Look-up material that isn't owned by a single subsystem.

- [Configuration](reference/configuration.md) — all environment variables and settings.
- [API](reference/api.md) — the REST API endpoints.

## Guides

How to run and work on the system.

- [Getting Started](guides/getting-started.md) — install, configure, and run.
- [Connecting With SOC Technologies](guides/connecting-with-soc-technologies.md) — per-platform setup for Wazuh, TheHive, and VirusTotal.
- [Operations](guides/operations.md) — testing, development, and troubleshooting.

## Project

Living project documents.

- [Current State](project/current-state.md) — current runtime shape and implementation snapshot.
- [SOC Agent Rubric](project/soc-rubric.md) — the evaluation rubric.
