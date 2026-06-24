# Dev inspection tools

Parametrized replacements for the old one-off `check_*.py` / `poll_*.py` /
`submit_*.py` / `get_event.py` scripts that used to clutter the project root.
Run them from the **project root** so Django resolves `aci.settings`:

```bash
python scripts/dev/inspect_events.py --session <id> --latest 30
python scripts/dev/inspect_events.py --run <id> --count
python scripts/dev/inspect_events.py --source inv --session <id> --kind error --full
python scripts/dev/inspect_events.py --event 12345           # single event, full detail
python scripts/dev/inspect_events.py --runs --agent triage   # recent runs

python scripts/dev/poll.py --run <run_id> --max-wait 600
python scripts/dev/poll.py --session <session_id>

python scripts/dev/submit.py --question "Triage case ~247152824"
python scripts/dev/submit.py --session <id> --question "investigate this case" --poll
```

| Tool | Replaces | Purpose |
|---|---|---|
| `inspect_events.py` | all `check_*.py`, `get_event.py` | Query `AgentEvent` / `AgentRun` by session/run/event, filter by source/kind, counts |
| `poll.py` | `poll_run.py`, `poll_session.py` | Stream new events until a run/session finishes |
| `submit.py` | `submit_new.py`, `submit_followup.py` | POST a question (new or follow-up), optionally poll |
| `_setup.py` | (shared) | Django bootstrap used by the above |

The original scripts are preserved unchanged under `_archive/` for reference.
