# AVFS Workspace Indexing

AVFS is the durable workspace for case artifacts, evidence, findings, reports,
and memory. Successful AVFS writes trigger `agent.workspace.avfs_writer`, which
updates:

- the nearest directory's `memory.md`;
- concise parent `memory.md` indexes up to the case, run, or memory root.

Each `memory.md` contains:

- `# Memory`
- `## Purpose`
- `## Files`
- `## Child Directories`
- `## Notes`

Parent indexes summarize child directories rather than duplicating every nested
artifact. This keeps AVFS browsable for future agents and analysts while raw
payloads remain stored once under stable paths.
