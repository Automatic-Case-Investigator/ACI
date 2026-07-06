# SOC Agent Response Quality Rubric

Applies to triage and investigation agent outputs. Each axis is scored **1–5**.
A weighted aggregate score of **≥4.0 on every axis** is the quality target.

Auto-cap rules are listed per axis. An auto-cap sets a hard ceiling regardless of
other qualities in the response.

---

## Axis 1 — Evidence Discipline

*Does the agent ground every claim in evidence it actually retrieved? Does it
correctly classify Confirmed vs. SOAR-only vs. Unverifiable, and avoid
inventing facts?*

| Score | Description |
|---|---|
| **5** | Every factual claim names the retrieved artifact (event ID, `full_log` line, alert id, AVFS path, or board entry). Confirmed/SOAR-only/Unverifiable labels are used correctly throughout. No invented identifiers, timestamps, hostnames, or sequences. Under analyst pressure to fill gaps, the agent explicitly refuses and separates confirmed from plausible from missing. |
| **4** | Minor omissions: one or two facts lack a citation but are not fabricated. Evidence classification is correct for all high-stakes claims. |
| **3** | Some facts cited without retrieval basis or classified as Confirmed when only SOAR-only evidence exists. No outright fabrication. |
| **2** | Multiple Confirmed labels applied to SOAR-only or description-only claims. Citations frequently absent. Partial invention (reconstructed timestamps, inferred event IDs). |
| **1** | Widespread fabrication: event IDs, hostnames, timestamps, or command lines invented. Agent invents facts under analyst pressure. |

**Auto-caps:**
- Any fabricated identifier, hostname, timestamp, or raw event field → **max 2**.
- Triage labels a whole evidence table or section "Confirmed" when no raw alerts were pulled → **max 3**.
- Agent invents data when asked to "fill gaps" instead of refusing → **max 1**.

---

## Axis 2 — Method

*Does the agent investigate systematically: right time windows, correct pivot
selection, exhausting alternatives before declaring a negative, and stopping
when the evidence is spent?*

| Score | Description |
|---|---|
| **5** | Uses the full absolute time window supplied by triage (does not silently narrow). Tries alternate field names and broader windows before declaring "no evidence." After three genuinely different attempts with no results, stops and records a confirmed negative. Does not re-run the same query rephrased. Triage pulls at most four representative raw alerts chosen by risk priority, not exhaustive enumeration. |
| **4** | Mostly systematic; one missed broadening attempt or one slightly narrowed window that did not affect the finding. |
| **3** | Occasionally narrows time windows without justification, or declares a negative after only one attempt, or runs the same query twice hoping for a different result. |
| **2** | Consistently narrow or arbitrary windows. Negative findings declared after a single query. Investigation pivots are vague or recycled from case descriptions rather than raw evidence. |
| **1** | No discernible search strategy. Windows are invented or relative. Pivots are copied verbatim from the case title. Negative findings are asserted without any search attempt. |

**Auto-caps:**
- Investigation uses `list_case_alerts` as its primary evidence source instead of `search`/`profile_field`/`search_keyword` → **max 3**.
- Agent attempts to `cat` or `ls` a path on a monitored host via AVFS → **max 3**.
- Agent creates more follow-up leads on the same absent evidence after three failed attempts → **max 3**.

---

## Axis 3 — Judgment

*Does the agent reason correctly from evidence to conclusions: right verdict,
correct actor attribution, establishing initial access, not overstating or
understating severity, and maintaining calibrated confidence?*

| Score | Description |
|---|---|
| **5** | Verdict (tp/fp/inconclusive/needs\_investigation) matches the evidence weight and definitions strictly. Initial access vector is established for any authentication or session case: source IP retrieved, matched against C2/callback address, and attribution stated. Temporal gaps are flagged explicitly. Causal claims in the executive summary are supported by the report's own evidence; no walk-back contradictions. Confidence labels match evidence class. |
| **4** | Verdict is correct. Initial access established but attribution is incomplete (e.g. source IP found but not compared to C2). One minor overstatement ("confirmed" for a plausible but unverified connection). |
| **3** | Verdict is defensible but confidence over- or under-stated. Initial access partially covered but source IP not retrieved. One causal claim in the summary is walked back in Open Gaps without reconciliation. |
| **2** | Verdict is incorrect or arbitrary (e.g. `tp` because the alert fired, not because malicious evidence was confirmed; or `fp` without confirming benign context). Initial access not addressed. Multiple overstatements. |
| **1** | Verdict contradicts the evidence. Major causal leaps stated as confirmed findings. Severity wildly mismatched to evidence. |

**Auto-caps:**
- Investigation concludes without establishing the initial access vector for a case involving a login/authentication event → **max 3**.
- Triage returns `tp` or `fp` with empty `supporting_evidence` → **max 2** (should be auto-demoted to `inconclusive`).
- Executive summary asserts a causal chain that Open Gaps explicitly walks back → **max 3**.
- Large temporal gap (>4 hours) between alert clusters not flagged → **max 3**.

---

## Axis 4 — IR Value

*Does the output give the SOC analyst something actionable: useful scope/impact
assessment, specific recommendations, and a final report they can act on?*

| Score | Description |
|---|---|
| **5** | Final report contains verdict, executive summary, chronological timeline, confirmed findings with raw evidence citations, unresolved observations clearly separated, affected-scope table, impact assessment, and prioritized containment/remediation recommendations. Escalation triggered immediately on confirmed active compromise with supporting event IDs. Investigation plan (triage) or recommendations (investigation) are specific and proportional to threat. |
| **4** | All major report sections present. One recommendation is vague or the timeline has a minor gap. No false escalations or missed escalations. |
| **3** | Report is mostly complete but missing one required section (e.g. scope table or open questions). Recommendations present but not prioritized. Escalation missed for a finding that warranted it, or triggered on SOAR-only evidence without raw event confirmation. |
| **2** | Report is skeletal: missing timeline, scope, or impact. Recommendations are generic ("investigate further," "monitor the host"). Investigation plan proposed items that are forensic actions rather than log queries, without appropriate framing. |
| **1** | No usable findings. No recommendations. Final message is a prose summary without structure. Analyst cannot act on the output. |

**Auto-caps:**
- Investigation completes without posting the final report to the case system → **max 3**.
- Triage proposes more than eight investigation items without merging or dropping → **max 4** (overly noisy plan).
- Active compromise confirmed by raw evidence but escalation was not triggered during investigation → **max 2**.

---

## Axis 5 — Communication

*Is the output correctly structured, complete, and unambiguous? Do headings,
labels, and section formats match the required templates?*

| Score | Description |
|---|---|
| **5** | Triage report contains the required `## Triage Summary`, `## Key Evidence`, and `## Investigation Plan` sections plus the fenced JSON verdict at the end. Every investigation task answer contains exactly the three required sections, in order — `## Findings`, `## Hypotheses`, `## New Leads` — with no separate "Confirmed Facts" header; `## Findings` is itself the system of record for grounded evidence. Hypotheses are claims (not questions), stated as single positive sentences, with `[Confirmed]`/`[Refuted]` prefixes applied correctly. None-bullets and placeholder text absent from final output. |
| **4** | Structure is correct but one section uses a non-standard heading or has a minor formatting slip (e.g. one hypothesis phrased as a question; one `None confirmed.` placeholder that slipped through). |
| **3** | One required section missing from the triage report. Investigation tasks occasionally use freeform headings ("Task Completion Update") instead of the template. Hypothesis contains a question or a double-negative refuted claim. |
| **2** | Multiple required sections absent. Freeform prose used instead of template structure in multiple tasks. `[Confirmed]` and `[Refuted]` labels applied to the wrong hypotheses (marks a claim confirmed when evidence disproves it, or refuted when evidence supports it). |
| **1** | No structure. Output is a single prose paragraph. Required JSON verdict absent. `## Findings` header absent from investigation task answers. |

**Auto-caps:**
- `[Confirmed]` applied to a hypothesis where the cited evidence disproves the claim, or `[Refuted]` applied where evidence supports it → **max 2** (inverted status is worse than missing status).
- Triage report missing the fenced JSON verdict block → **max 3**.
- Investigation task answer omits `## Findings` header → facts silently lost from Findings Board; **max 3** for that task.

---

## Axis 6 — Tool Fluency

*Does the agent select and call tools correctly, use the findings board for
pivoting and hypothesis tracking, and respect tool-use policies?*

| Score | Description |
|---|---|
| **5** | Triage calls `search_patterns`, `get_baselines`, and `search_feedback` before finalising a verdict, and cites results. Triage pulls raw alert bodies for representative groups only (max 4), not all alerts. Investigation uses `search`/`profile_field`/`search_keyword` for evidence; never `list_case_alerts`. Board artifacts are used as pivots in New Leads. Hypothesis updates go through `update_entry` (by entry id) rather than re-adding duplicate rows. `claim_next` and `complete_task` are not called manually during `think`. The seeder agent's queue-population pass creates all entries before the investigation queue is worked. |
| **4** | Mostly correct. One tool used suboptimally (e.g. `search_feedback` not called, or board queried redundantly, or one hypothesis re-added rather than updated). No critical policy violations. |
| **3** | `search_patterns`/`search_feedback` not called before verdict. Board not used for pivoting. Hypothesis entries duplicated on the board. `list_case_alerts` called once inside an investigation task. |
| **2** | Multiple policy violations: `list_case_alerts` used as investigation's primary evidence source; board tools ignored entirely; `claim_next` called manually causing queue routing errors; seed task completes before creating all queue entries. |
| **1** | Agent ignores tool guidance entirely. Calls tools with wrong parameters, hallucinates tool names, or stalls indefinitely without producing a verdict (timeout). |

**Auto-caps:**
- Agent stalls or times out without producing any verdict or report → **max 1**.
- `claim_next` called manually during `think`, causing tasks to be marked claimed without executing → **max 2**.
- Pattern name cited in `matched_patterns` that `search_patterns` did not return in this run → **max 2** (fabricated pattern match).

---

## Scoring Summary

| Axis | Weight | Target |
|---|---|---|
| Evidence Discipline | 20% | ≥4 |
| Method | 15% | ≥4 |
| Judgment | 25% | ≥4 |
| IR Value | 20% | ≥4 |
| Communication | 10% | ≥4 |
| Tool Fluency | 10% | ≥4 |

**Weighted score = Σ(axis score × weight)**

A response passes quality review when:
- Weighted score ≥ 4.0, **and**
- No single axis scores below 3, **and**
- No auto-cap is triggered on Evidence Discipline or Judgment (those indicate
  a fundamentally unreliable response regardless of other axis scores).

---

## Quick-Reference: Common Failure → Auto-Cap Table

| Failure | Affected Axis | Cap |
|---|---|---|
| Fact fabricated (any) | Evidence Discipline | 2 |
| Fabrication under analyst pressure | Evidence Discipline | 1 |
| Triage marks table Confirmed without raw alert pull | Evidence Discipline | 3 |
| Initial access vector not established (login/auth case) | Judgment | 3 |
| `tp`/`fp` with empty `supporting_evidence` | Judgment | 2 |
| Exec summary contradicts Open Gaps section | Judgment | 3 |
| `list_case_alerts` used for investigation evidence | Method / Tool Fluency | 3 |
| `cat` on monitored host path via AVFS | Method | 3 |
| Agent stalls / times out | Tool Fluency | 1 |
| `[Confirmed]`/`[Refuted]` labels inverted | Communication | 2 |
| Triage JSON verdict block absent | Communication | 3 |
| `## Findings` header absent from task answer | Communication | 3 |
| Pattern name cited not returned by `search_patterns` | Tool Fluency | 2 |
