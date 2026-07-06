# Workflows And Webhooks

Automatic workflows exist, but are globally disabled by default and gated by
runtime settings plus per-trigger enablement.

Supported bindings:

- `new_case` -> `triage`
- `new_alert` -> `triage`

Configured triggers expose:

```text
POST /api/agent/webhooks/<trigger_id>/
```

The compatibility endpoint remains:

```text
POST /api/agent/webhooks/thehive/
```
