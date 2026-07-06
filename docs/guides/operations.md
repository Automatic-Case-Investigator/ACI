# Operations

## Testing

All tests run offline (no LLM, Wazuh, TheHive, or AVFS needed):

```bash
# Full offline suite
PYTHONPATH=. python -m pytest tests/unit tests/django -q

# Individual test files
PYTHONPATH=. python -m pytest tests/unit/graph/test_graph_stub.py -v
PYTHONPATH=. python -m pytest tests/unit/analysis/test_verdict_parsing.py -v
```

Tests live under `tests/unit/` (graph logic, per-task self-review, Findings Board +
board-driven compromise detection, seeder dedup, Wazuh query-shape guards, provider
contracts, prompt composition, verdict parsing, alert metadata, feedback loop, TI
enrichment, orchestrator lifecycle) and `tests/django/` (settings and resume/session
behavior). Local helper scripts are documented in `scripts/dev/README.md`.

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `ModuleNotFoundError: No module named 'aci_taskqueue'` | `pip install -e aci-mcp-servers/aci-taskqueue` |
| `RuntimeError: Failed to load MCP instructions for aci-wazuh` | Wazuh is unreachable or `WAZUH_URL`/`WAZUH_PASSWORD` is wrong |
| `grep_semantic failed: {ok: false, error: ...}` | AVFS container not running or `AVFS_AUTH_TOKEN` is the literal `change-me-avfs-token` |
| `add_case_comment` 404 from TheHive | Tool was removed; old sessions may have fired this. New runs use `post_case_report` only |
| `parsing_exception: Unknown key for START_OBJECT in [time_range]` from Wazuh | Model double-wrapped the search request. The client auto-unwraps this |
| Search result has a `note` about `should` being "SCORING-ONLY" | The query's `should` clause has no `must`/`minimum_should_match`, so it did not actually filter — see [SIEM Query Robustness](../architecture/tools.md#siem-query-robustness-wazuh) |
| Investigation results from one `agent.name` look inconsistent across runs | `agent.name` may not be unique in this index — check `agent.id` cardinality before trusting a name-scoped query as one host |
| Django migration errors on startup | Run `python manage.py migrate` |
| Empty investigation report | Local LLM may be too small or out of context; use a 13B+ model |

## Development

### Debug scripts

Local inspection scripts are in `scripts/dev/`:

```bash
python scripts/dev/inspect_events.py --session <id> --latest 30
python scripts/dev/poll.py --session <session_id>
python scripts/dev/submit.py --question "Triage case ~247152824" --poll
```

### Making changes

1. Create a feature branch
2. Update tests if needed (`tests/unit/`, `tests/django/`)
3. Run the offline test suite to verify no regressions:
   ```bash
   PYTHONPATH=. python -m pytest tests/unit tests/django -q
   ```
4. Commit with a clear message
