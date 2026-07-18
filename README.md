# ACI — Autonomous Case Investigator

**ACI** is a SOC (Security Operations Center) agent platform that automates alert triage and multi-step incident investigation using agentic AI. Built on Django 5, LangGraph, MCP, and WebSocket-driven real-time streaming, ACI transforms raw SIEM/SOAR alerts into structured, evidence-backed incident reports.

Most AI SOC tools optimize for speed across the full alert-to-response lifecycle — triage, enrichment, risk scoring, containment. ACI's focus is different: deeper investigation before conclusion. It breaks a case into discrete investigation tasks, runs iterative SIEM queries, preserves intermediate evidence, and anchors every finding to retrieved log events rather than case narrative. The result is a traceable investigation record — what happened, which evidence supports it, which claims are still unconfirmed, and what follow-up is needed — that analysts, responders, and auditors can independently verify.

## Features

- **Live reasoning stream**: Real-time visibility into agent intent, tool calls, and results via WebSocket dashboard
- **Task-driven investigation**: Cases are decomposed into discrete, prioritized tasks worked one at a time, keeping investigation focused and progress auditable
- **Evidence-anchored findings**: Confirmed facts, working hypotheses, and extracted artifacts are tracked across tasks and tied to specific retrieved log events
- **MCP tool ecosystem**: Pluggable integrations with SIEM, SOAR, workspace, and memory providers via Model Context Protocol
- **Durable analyst session state**: Orchestrator conversations, specialist handoffs, resumes, and restarts are persisted back into the analyst-visible session state

## Getting Started

To install, configure, and run ACI (dashboard or REST API), see
[Getting Started](docs/guides/getting-started.md). For the system diagram, repository
layout, and design philosophy, see the [Architecture Overview](docs/architecture/overview.md).

## Documentation

Full documentation lives in [`docs/`](docs/README.md), organized by subsystem.

**Guides**

- [Getting Started](docs/guides/getting-started.md) — prerequisites, installation, configuration, running.
- [Connecting With SOC Technologies](docs/guides/connecting-with-soc-technologies.md) — connecting Wazuh, TheHive, and VirusTotal.
- [Operations](docs/guides/operations.md) — testing, development, troubleshooting.

**Architecture**

- [Overview](docs/architecture/overview.md) — system diagram, repository layout, and design philosophy.
- [Runtime & Agent Graph](docs/architecture/runtime/agent-graph.md) — the queue-driven node loop.
- [Prompt Composition](docs/architecture/runtime/prompts.md) — layered prompts and the role ladder.
- [Queue & Model Streaming](docs/architecture/runtime/queue-and-streaming.md)
- [Orchestrator](docs/architecture/orchestrator.md)
- [MCP & Tool Policy](docs/architecture/tools.md)
- [Findings Board](docs/architecture/findings-board.md)
- [AVFS Workspace](docs/architecture/workspace.md)
- [Workflows & Webhooks](docs/architecture/automation.md)

**Reference**

- [Configuration](docs/reference/configuration.md) — all environment variables and settings.
- [API](docs/reference/api.md) — REST endpoints.

**Project**

- [Current State](docs/project/current-state.md) — current runtime shape, built-in providers, and workflows.
- [SOC Agent Rubric](docs/project/soc-rubric.md) — the investigation quality rubric.

**Contributing & configuration**

- [Contribution Guide](CONTRIBUTION.md) — development philosophy and conventions.
- [Agent Prompts](agent/prompts/) — triage, investigation, and orchestrator instructions.
- [Sample Configuration](sample.env) — environment variable template.

## License

(License information to be added)
