# API Reference

### Agent Runs

#### Start a run
```
POST /api/agent/runs/
Authorization: Bearer <token>
Content-Type: application/json

{
  "agent_name": "investigation",
  "case_id": "~254202040",
  "question": "What happened?"
}

Response: { "run_id": "...", "status": "queued" }
```

#### Get run status
```
GET /api/agent/runs/<run_id>/
Authorization: Bearer <token>

Response: {
  "run_id": "...",
  "status": "completed",
  "result": "...",
  "error": null
}
```

#### Get run events
```
GET /api/agent/runs/<run_id>/events/
Authorization: Bearer <token>

Response: [
  { "id": 1, "kind": "note", "source": "orchestrator", "summary": "..." },
  ...
]
```

#### Cancel a run
```
POST /api/agent/runs/<run_id>/cancel/
Authorization: Bearer <token>
```

#### Resume a run
```
POST /api/agent/runs/<run_id>/resume/
Authorization: Bearer <token>
```

When the resumed run belongs to an interactive orchestrator session, completion
is republished into analyst-visible session state through the same specialist
publication path used by orchestrator-triggered completions and restarts.

### Task Queue

```
GET    /api/agent/cases/<case_id>/queues/<agent_name>/tasks/?run_id=<run_id>
POST   /api/agent/cases/<case_id>/queues/<agent_name>/tasks/
PATCH  /api/agent/cases/<case_id>/queues/<agent_name>/tasks/<task_id>/
DELETE /api/agent/cases/<case_id>/queues/<agent_name>/tasks/<task_id>/
```

### Workspace & Reports

```
GET /api/agent/cases/<case_id>/workspace/
GET /api/agent/cases/<case_id>/reports/latest/
```
