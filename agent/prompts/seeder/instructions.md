## Task: Verify and complete the investigation queue

The core investigation tasks have already been created directly from the triage report's `## Investigation Plan`. Your job is to **verify** completeness and **add** any mandatory tasks that the plan omitted.

**Step 1 — Verify.** Call `list_tasks` once. Check that every task listed in the "Already created" section exists. If any is missing, recreate it with `create_task`.

**Step 2 — Cover both ends of the chain, but only where the report gives you evidence.** An alert sits in the *middle* of an attack chain, and triage plans commonly drill the alert's own phase while omitting its two ends. For each end, add a task **only when the triage report actually cites an indicator for it**, and derive that task from the specific indicator the report names — never from a generic template. Do **not** presume an indicator the report does not mention: an unobserved phase is a gap, and the platform already queues a deterministic "establish or rule out `<phase>`" task for missing phases, so fabricating a speculative task here only adds noise.

- **Entry point (backward / how the actor got in).** If the report cites access, login, remote-session, or execution activity but nothing queued establishes how the actor first got in, add one task to establish the initial-access vector — grounded in the host, user, and time the report names (the earliest suspicious session and its source). Priority ~85.

- **External destination (forward / where it reaches out).** Add a task here **only if the report actually cites an outbound, callback, reverse-shell, or exfiltration indicator** — either a named destination, or an encoded/obfuscated command whose destination is not yet resolved. Ground the task in what the report names:
  - It names a concrete address/domain → pivot on that exact value across the relevant SIEM event classes within the window.
  - It cites only an encoded/obfuscated artifact (destination unresolved) → decode *that specific artifact* and pivot on the destination it resolves to.
  Never write a bracketed placeholder (`<addr>`, `<ip>`) into a title, and if the report cites no such indicator at all, add nothing here — do not invent a decode/callback task where no encoded artifact or callback was observed. Priority ~90.

**Every task carries a completion contract.** Include a `Done when: <observable outcome>` line in each task description you create — what must be TRUE for the task to be finished, checkable against retrieved evidence (e.g. "Done when: the decoded callback destination is named with its supporting event ID"), never an activity ("investigate", "look into"). If stating the criterion honestly requires several unrelated clauses, that is a sign the task bundles several questions — split it, one verifiable outcome per task.

**Step 3 — Stop.** Do not add tasks that duplicate what is already queued. Do not invent tasks beyond the plan items and the two endpoint categories above. A single `list_tasks` call followed by at most one or two `create_task` calls is the expected output.

**When `create_task` fails:** read the error, propose a task that achieves the same investigative goal by an allowed method, and call `create_task` immediately with the revised parameters.

Do NOT run any SIEM queries, read files, or start investigating. Only call `create_task` and `list_tasks`.

**Fallback — missing plan section:** If the "Already created" section says "No tasks have been created yet", the triage report contained no parseable `## Investigation Plan`. In that case, read the full triage report and call `create_task` for every distinct investigative question raised — one task per question. Do not collapse multiple questions into a single generic task.
