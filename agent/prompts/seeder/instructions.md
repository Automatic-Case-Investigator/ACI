## Task: Verify and complete the investigation queue

The core investigation tasks have already been created directly from the triage report's `## Investigation Plan`. Your job is to **verify** completeness and **add** any mandatory tasks that the plan omitted.

**Step 1 — Verify.** Call `list_tasks` once. Check that every task listed in the "Already created" section exists. If any is missing, recreate it with `create_task`.

**Step 2 — Cover both ends of the chain.** An alert sits in the *middle* of an attack chain, and triage plans commonly drill the alert's own phase while omitting its two ends. Read the triage report and add a task for either end that is not already queued:

- **Entry point (backward / how the actor got in).** If the report shows any access, login, remote-session, or execution activity but no queued task establishes the initial-access vector, add *'Establish initial access vector — source IP and earliest suspicious login session.'* Priority 85.

- **External destination (forward / where it reaches out).** If the report shows any outbound, callback, reverse-shell, or exfiltration indicator pointing at an external address or domain — decode any encoded command first, since a reverse shell is rarely literal — but no queued task pivots on that destination, add a task. **Never write a placeholder into the title** (no `<addr>`, `<ip>`, or similar bracketed stand-in — a task titled with a literal placeholder is unusable). Two cases:
  - The report already names a concrete address/domain: title it on that exact value, e.g. "Investigate attacker-controlled destination 203.0.113.7 — pivot to all SIEM events to/from it (connection, SSH, HTTP) within the configured vicinity window." Priority 90.
  - The report only describes an indicator *type* (e.g. "an encoded callback was observed" with no decoded address yet): phrase the task as the discovery itself, e.g. "Decode the embedded payload and identify the attacker-controlled destination it calls back to, then pivot SIEM events to/from that address." Priority 90.

**Every task carries a completion contract.** Include a `Done when: <observable outcome>` line in each task description you create — what must be TRUE for the task to be finished, checkable against retrieved evidence (e.g. "Done when: the decoded callback destination is named with its supporting event ID"), never an activity ("investigate", "look into"). If stating the criterion honestly requires several unrelated clauses, that is a sign the task bundles several questions — split it, one verifiable outcome per task.

**Step 3 — Stop.** Do not add tasks that duplicate what is already queued. Do not invent tasks beyond the plan items and the two endpoint categories above. A single `list_tasks` call followed by at most one or two `create_task` calls is the expected output.

**When `create_task` fails:** read the error, propose a task that achieves the same investigative goal by an allowed method, and call `create_task` immediately with the revised parameters.

Do NOT run any SIEM queries, read files, or start investigating. Only call `create_task` and `list_tasks`.

**Fallback — missing plan section:** If the "Already created" section says "No tasks have been created yet", the triage report contained no parseable `## Investigation Plan`. In that case, read the full triage report and call `create_task` for every distinct investigative question raised — one task per question. Do not collapse multiple questions into a single generic task.
