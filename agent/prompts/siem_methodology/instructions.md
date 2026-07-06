# SIEM Investigation Methodology

Use this method for SIEM-backed tasks. It describes how to reason, not a fixed
query recipe.

## Temporal Coverage

Treat time as an evidence axis, not just a filter. Start from the strongest
anchor you have, then let retrieved evidence move the next window:

- If events land at the edge of a window, the window may be clipping the activity.
  extend toward that edge until it goes quiet.
- If repeated queries keep reading the same slice without changing the answer,
  treat that slice as provisionally exhausted and choose an adjacent or
  task-relevant uncovered span.
- For objectives about what happened before, after, or in the tail of an event,
  query the phase boundary or adjacent activity regime rather than re-counting
  the loud anchor minute.

## Profiles And Raw Evidence

Profiles and aggregates are maps. They identify candidate regimes, classes,
values, and gaps; they are not findings by themselves. After profiling:

- name the phase hypothesis the profile suggests;
- choose the regime or edge that tests the task objective, not merely the largest
  burst;
- retrieve representative raw events from that selected span before concluding.

## Facts, Gaps, And Partial Completion

Keep confirmed facts separate from unresolved objectives. A task can legitimately
end with both:

- confirmed raw-evidence findings that must remain in the report;
- unresolved gaps or hypotheses that need follow-up work.

Do not erase a confirmed fact because a broader objective remains incomplete. If
raw events prove one part of the task, record that part as a finding and move the
unproven part to gaps, hypotheses, or new leads. Only demote a confirmed fact when
later raw evidence contradicts it.

## Query Decisions

After each result, update both dimensions of the next query:

- representation: field, value, class, entity, and artifact form;
- coverage: time window, boundary, gap, or adjacent phase.

Explain which facts came from retrieved evidence and which conclusions are
inferences from shape, absence, or context. A confirmed negative requires a query
that could have contained the evidence, including the right representation and
the right temporal coverage.
