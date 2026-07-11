from __future__ import annotations

import asyncio
import json
import os
import sys
import unittest

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, project_root)
import django  # noqa: E402

django.setup()

from agent.runtime.graph.builder import _route_interpret, _route_think, _route_use_tools  # noqa: E402
from agent.runtime.graph.interpretation import _NO_PROGRESS_BRAKE_CYCLES, interpret  # noqa: E402
from agent.runtime.graph.nodes_loop import _MAX_TASK_TOOL_CALLS  # noqa: E402
from agent.runtime.graph.observation import build_observation  # noqa: E402
from langchain_core.language_models import BaseChatModel  # noqa: E402
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage  # noqa: E402


def _run(coro):
    return asyncio.run(coro)


class ObservationRoutingTest(unittest.TestCase):
    def test_use_tools_routes_to_interpret(self):
        self.assertEqual(_route_use_tools({"status": ""}), "interpret")

    def test_cancelled_use_tools_finishes(self):
        self.assertEqual(_route_use_tools({"status": "cancelled"}), "finish")

    def test_ready_interpret_routes_to_assess(self):
        self.assertEqual(_route_interpret({
            "status": "ready_to_assess",
            "steps": 1,
            "max_steps": 10,
            "tool_calls_made": 1,
            "max_tool_calls": 10,
        }), "assess")

    def test_continue_interpret_routes_to_think(self):
        self.assertEqual(_route_interpret({
            "status": "needs_more_work",
            "steps": 1,
            "max_steps": 10,
            "tool_calls_made": 1,
            "max_tool_calls": 10,
        }), "think")

    def test_per_task_cap_routes_to_assess_even_with_cleared_messages(self):
        # The interpret->think continuation returns messages=[]; the per-task cap must
        # still fire on the deterministic counter, or a task loops unbounded (session
        # 8c1cd9ae ran 86 calls on one task because a ToolMessage-presence guard defeated
        # the cap after every continuation).
        state = {
            "agent_name": "investigation",
            "messages": [],  # cleared by the continuation rebuild
            "steps": 30,
            "max_steps": 60,
            "tool_calls_made": 50 + _MAX_TASK_TOOL_CALLS,
            "max_tool_calls": 200,
            "task_call_floor": 50,  # task_calls == _MAX_TASK_TOOL_CALLS
        }
        self.assertEqual(_route_think(state), "assess")

    def test_under_cap_still_routes_to_use_tools_on_tool_calls(self):
        state = {
            "agent_name": "investigation",
            "messages": [AIMessage(content="", tool_calls=[{"id": "1", "name": "search", "args": {}}])],
            "steps": 5,
            "max_steps": 60,
            "tool_calls_made": 60,
            "max_tool_calls": 200,
            "task_call_floor": 55,  # task_calls == 5, under the cap
        }
        self.assertEqual(_route_think(state), "use_tools")


class ObservationNormalizationTest(unittest.TestCase):
    def test_truncated_search_becomes_truncated_signal(self):
        obs = build_observation([{
            "name": "search",
            "raw": json.dumps({
                "total": 10000,
                "total_relation": "gte",
                "truncated": True,
                "events": [{"_id": "e1"}],
            }),
            "artifacts": [],
        }], objective="find event")
        self.assertIn("TRUNCATED", obs["signals"])

    def test_saturated_volume_becomes_saturated_signal(self):
        obs = build_observation([{
            "name": "get_event_volume",
            "raw": json.dumps({"total": 42, "saturated": True}),
            "artifacts": [],
        }], objective="profile tail")
        self.assertIn("SATURATED", obs["signals"])

    def test_multi_regime_volume_becomes_multi_regime_signal(self):
        obs = build_observation([{
            "name": "get_event_volume",
            "raw": json.dumps({
                "total": 1000,
                "saturated": True,
                "bursts": [
                    {"start": "2022-01-18T12:17:30Z", "end": "2022-01-18T12:40:00Z", "peak_count": 300, "total": 600},
                    {"start": "2022-01-19T09:00:00Z", "end": "2022-01-19T10:00:00Z", "peak_count": 900, "total": 1200},
                ],
            }),
            "artifacts": [],
        }], objective="pick burst")
        self.assertIn("MULTI_REGIME", obs["signals"])
        self.assertNotIn("SATURATED", obs["signals"])
        self.assertEqual(len(obs["volume_regimes"]), 2)
        self.assertEqual(obs["volume_regimes"][0]["start"], "2022-01-18T12:17:30Z")

    def test_entity_flood_becomes_flooded_signal(self):
        obs = build_observation([{
            "name": "search",
            "raw": json.dumps({
                "total": 10000,
                "rule_groups_breakdown": [{"group": "ids", "count": 745000}],
                "events": [{"_id": "e1"}],
            }),
            "artifacts": [],
        }], objective="scope flood")
        self.assertIn("FLOODED", obs["signals"])

    def test_orientation_only_becomes_orientation_signal(self):
        obs = build_observation([{
            "name": "get_case",
            "raw": json.dumps({"id": "~1"}),
            "artifacts": [],
        }], objective="read case")
        self.assertIn("ORIENTATION_ONLY", obs["signals"])

    def test_repeated_no_findings_becomes_no_new_evidence(self):
        prior = build_observation([{
            "name": "search",
            "raw": json.dumps({"total": 0, "events": []}),
            "artifacts": [],
        }], objective="same objective")
        current = build_observation([{
            "name": "search",
            "raw": json.dumps({"total": 0, "events": []}),
            "artifacts": [],
        }], prior_observation=prior, objective="same objective")
        self.assertIn("NO_NEW_EVIDENCE", current["signals"])

    def test_search_events_emit_compact_evidence_snapshots(self):
        obs = build_observation([{
            "name": "search",
            "raw": json.dumps({
                "total": 1,
                "events": [{
                    "_id": "e1",
                    "timestamp": "2022-01-18T12:24:26Z",
                    "agent.name": "wazuh-client",
                    "rule.id": "30301",
                    "rule.description": "Apache error",
                    "data.srcip": "172.17.130.196",
                    "data.url": "/wp-content/themes/go/admin.php",
                    "full_log": "php7:error script admin.php not found",
                }],
            }),
            "artifacts": [],
        }], objective="drill scan tail")
        self.assertEqual(obs["evidence_snapshots"][0]["event_id"], "e1")
        self.assertEqual(obs["evidence_snapshots"][0]["rule_id"], "30301")
        self.assertIn("admin.php", obs["evidence_snapshots"][0]["url"])

    def test_evidence_digest_and_summary_carry_event_semantics(self):
        obs = build_observation([{
            "name": "search",
            "raw": json.dumps({
                "total": 8,
                "events": [{
                    "_id": "e1",
                    "rule.id": "5304",
                    "rule.description": "User successfully changed UID",
                    "rule.groups": "audit",
                    "data.srcuser": "www-data",
                    "data.dstuser": "phopkins",
                    "full_log": "su[28816]: + /dev/pts/1 www-data:phopkins",
                }],
            }),
            "artifacts": [],
        }], objective="trace execution")
        # The digest carries the actual event meaning, not just a count.
        self.assertTrue(obs["evidence_digest"])
        digest = obs["evidence_digest"][0]
        self.assertIn("5304", digest)
        self.assertIn("User successfully changed UID", digest)
        # The propagated summary (fallback channel) now carries semantics, not "8 hit(s)" alone.
        self.assertIn("top:", obs["summary"])
        self.assertIn("5304", obs["summary"])

    def test_no_digest_when_batch_has_no_events(self):
        obs = build_observation([{
            "name": "profile_field",
            "raw": json.dumps({"values": [{"key": "web", "doc_count": 10}]}),
            "artifacts": [],
        }], objective="profile")
        self.assertEqual(obs["evidence_digest"], [])

    def test_time_windows_extract_from_supported_tool_args(self):
        obs = build_observation([
            {
                "name": "search",
                "args": {
                    "time_range": {
                        "from": "2022-01-18T12:19:10Z",
                        "to": "2022-01-18T12:24:30Z",
                    },
                },
                "raw": json.dumps({"total": 0, "events": []}),
                "artifacts": [],
            },
            {
                "name": "profile_field",
                "args": {
                    "field": "rule.id",
                    "query": {
                        "bool": {"filter": [
                            {"range": {"@timestamp": {
                                "gte": "2022-01-18T12:24:30Z",
                                "lte": "2022-01-18T12:30:00Z",
                            }}}
                        ]}
                    },
                },
                "raw": json.dumps({"values": [{"key": "web", "doc_count": 10}]}),
                "artifacts": [],
            },
            {
                "name": "get_event_volume",
                "args": {
                    "start_time": "2022-01-18T12:30:00Z",
                    "end_time": "2022-01-18T12:40:00Z",
                },
                "raw": json.dumps({"total": 42}),
                "artifacts": [],
            },
        ], objective="track coverage")
        self.assertEqual(
            [(w["tool"], w["from"], w["to"]) for w in obs["time_windows"]],
            [
                ("search", "2022-01-18T12:19:10Z", "2022-01-18T12:24:30Z"),
                ("profile_field", "2022-01-18T12:24:30Z", "2022-01-18T12:30:00Z"),
                ("get_event_volume", "2022-01-18T12:30:00Z", "2022-01-18T12:40:00Z"),
            ],
        )
        self.assertEqual(
            [(q["tool"], q["focus"]) for q in obs["query_focuses"]],
            [("profile_field", "profile:rule.id")],
        )

    def test_time_window_extraction_ignores_malformed_windows(self):
        obs = build_observation([{
            "name": "search",
            "args": {"time_range": {"from": "not-a-date", "to": "2022-01-18T12:24:30Z"}},
            "raw": json.dumps({"total": 0, "events": []}),
            "artifacts": [],
        }], objective="track coverage")
        self.assertEqual(obs["time_windows"], [])

    def test_prompt_surfaces_notable_events_block(self):
        from agent.runtime.graph.interpretation import _prompt
        obs = build_observation([{
            "name": "search",
            "raw": json.dumps({
                "total": 2,
                "events": [{
                    "_id": "e1", "rule.id": "31108",
                    "rule.description": "Ignored URLs", "rule.groups": "web",
                    "data.url": "/wp-content/uploads/2022/01/x.php", "data.id": "200",
                }],
            }),
            "artifacts": [],
        }], objective="find webshell")
        text = _prompt({"title": "t"}, {"objective": "find webshell"}, obs, "")
        self.assertIn("Notable events retrieved this batch", text)
        self.assertIn("/wp-content/uploads/2022/01/x.php", text)

    def test_case_context_emits_orientation_facts_not_event_snapshots(self):
        obs = build_observation([{
            "name": "get_case",
            "raw": json.dumps({
                "_id": "~1",
                "title": "Multiple web server 400 error codes from same source ip.",
                "description": (
                    "### @timestamp\n| key | val |\n| @timestamp | 2022-01-18T12:19:10.000000Z |\n"
                    "### Agent\n| key | val |\n| agent.ip | 10.35.35.206 |\n| agent.name | wazuh-client |\n"
                    "### Data\n| key | val |\n| data.srcip | 172.17.130.196 |\n| data.url | /wp-content/create_account |\n"
                    "### Rule\n| key | val |\n| rule.id | 31151 |\n"
                ),
            }),
            "artifacts": [],
        }], objective="triage")
        self.assertEqual(obs["evidence_snapshots"], [])
        self.assertEqual(obs["orientation_facts"][0]["case_id"], "~1")
        self.assertEqual(obs["orientation_facts"][0]["src_ip"], "172.17.130.196")
        self.assertEqual(obs["orientation_facts"][0]["rule_id"], "31151")

    def test_case_url_becomes_exemplar_pivot_candidate(self):
        obs = build_observation([{
            "name": "get_case",
            "raw": json.dumps({
                "_id": "~1",
                "title": "Multiple web server 400 error codes from same source ip.",
                "description": (
                    "### Data\n| key | val |\n| data.srcip | 172.17.130.196 |\n"
                    "| data.url | /wp-content/create_account |\n"
                    "### Rule\n| key | val |\n| rule.id | 31151 |\n"
                ),
            }),
            "artifacts": [],
        }], objective="triage")
        url_pivot = next(item for item in obs["pivot_candidates"] if item["field"] == "url")
        self.assertEqual(url_pivot["source_level"], "case")
        self.assertEqual(url_pivot["role"], "exemplar")
        self.assertEqual(url_pivot["confidence"], "low")
        self.assertEqual(url_pivot["broader_alternative"], "/wp-content/*")

    def test_raw_event_url_becomes_discriminator_pivot_candidate(self):
        obs = build_observation([{
            "name": "search",
            "raw": json.dumps({
                "total": 1,
                "events": [{
                    "_id": "e1",
                    "timestamp": "2022-01-18T12:24:26Z",
                    "agent.name": "wazuh-client",
                    "data.srcip": "172.17.130.196",
                    "data.url": "/wp-content/themes/go/admin.php",
                    "full_log": "php7:error script admin.php not found",
                }],
            }),
            "artifacts": [],
        }], objective="drill scan tail")
        url_pivot = next(item for item in obs["pivot_candidates"] if item["field"] == "url")
        self.assertEqual(url_pivot["source_level"], "raw_event")
        self.assertEqual(url_pivot["role"], "discriminator")
        self.assertEqual(url_pivot["confidence"], "high")


class _StubModel(BaseChatModel):
    def __init__(self, payload: dict):
        super().__init__()
        self._payload = payload

    @property
    def _llm_type(self):
        return "interpret-stub"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        raise NotImplementedError

    async def ainvoke(self, messages, **kwargs):
        return AIMessage(content=json.dumps(self._payload))


class InterpretContractTest(unittest.TestCase):
    def _state(self, observation: dict, retries: int = 0):
        return {
            "run_id": "run-1",
            "case_id": "~1",
            "agent_name": "investigation",
            "question": "investigate",
            "handoff": None,
            "current_task": {"title": "Check callback", "description": "Investigate callback"},
            "last_completed_task": None,
            "messages": [],
            "steps": 1,
            "tool_calls_made": 1,
            "max_steps": 10,
            "max_tool_calls": 10,
            "default_vicinity_window_hours": 24,
            "status": "",
            "final_answer": "",
            "ctx_tokens": 0,
            "verdict": None,
            "pivot_tasks_created": 0,
            "task_call_floor": 0,
            "escalation_posted": False,
            "reflection_retries": 0,
            "reflection_evidence_at_last_nudge": -1,
            "last_findings_verification": None,
            "last_confirmed_findings": [],
            "completed_task_titles": [],
            "task_ledger": {
                "objective": "Check callback",
                "hypothesis": "",
                "next_action": "retrieve_specific_event",
                "next_step_instruction": "",
                "forbidden_repeats": [],
                "blocker": "",
                "evidence_state": "orientation",
                "evidence_found": [],
                "confirmed_findings": [],
                "remaining_gaps": [],
                "stop_condition": "Retrieve concrete event",
                "stop_reason": "",
                "last_observation": "",
                "primary_pivot": {},
                "active_pivots": [],
                "next_pivot_strategy": "keep",
                "why_current_pivot_failed": "",
            },
            "last_observation": observation,
            "observation_retries": retries,
            "no_progress_cycles": 0,
        }

    def test_truncated_batch_routes_to_refine_query(self):
        obs = {
            "tools": ["search"],
            "signals": ["TRUNCATED"],
            "summary": "search=10000 hit(s); signals=TRUNCATED",
            "recommended_moves": ["narrow the query before trusting the sample"],
            "advanced_objective": False,
        }
        result = _run(interpret(
            self._state(obs),
            {"configurable": {"model": _StubModel({
                "what_showed": "search returned a truncated sample",
                "advanced_objective": False,
                "blocker": "query too broad",
                "progress_status": "needs refinement",
                "next_action": "refine_query",
                "hypothesis": "",
                "confirm_if": "retrieve a specific event",
            }), "tools": []}},
        ))
        self.assertEqual(result["status"], "needs_more_work")
        self.assertEqual(result["task_ledger"]["next_action"], "refine_query")
        # Continuation contract: interpret clears the message history so `think`
        # rebuilds the next prompt from the ledger (next_step_instruction +
        # forbidden_repeats) instead of replaying the original task checklist.
        self.assertEqual(result["messages"], [])

    def test_continuation_clears_messages_but_completion_keeps_summary(self):
        """needs_more_work -> empty messages (force ledger rebuild in `think`);
        ready_to_assess -> non-empty compacted summary for the report writer."""
        cont_obs = {
            "tools": ["get_case", "list_case_alerts", "list_baseline_entities"],
            "signals": ["ORIENTATION_ONLY"],
            "summary": "orientation only; evidence_queries=0",
            "recommended_moves": ["run the first evidence query"],
            "advanced_objective": False,
            "evidence_queries": 0,
        }
        cont = _run(interpret(
            self._state(cont_obs),
            {"configurable": {"model": _StubModel({
                "what_showed": "orientation metadata only",
                "advanced_objective": False,
                "blocker": "no evidence query run yet",
                "progress_status": "needs_more_work",
                "next_action": "retrieve_specific_event",
                "next_step_instruction": "Query the SIEM for the anchor host/source in the window.",
                "hypothesis": "",
                "confirm_if": "retrieve a nearby raw event",
            }), "tools": []}},
        ))
        self.assertEqual(cont["status"], "needs_more_work")
        self.assertEqual(cont["messages"], [])
        self.assertTrue(cont["task_ledger"].get("next_step_instruction"))

        done_obs = {
            "tools": ["get_event"],
            "signals": [],
            "summary": "retrieved event e1",
            "recommended_moves": [],
            "advanced_objective": True,
            "event_ids": ["e1"],
            "evidence_markers": ["event:e1"],
        }
        done = _run(interpret(
            self._state(done_obs),
            {"configurable": {"model": _StubModel({
                "what_showed": "event e1 confirms the callback",
                "advanced_objective": True,
                "blocker": "",
                "progress_status": "complete",
                "next_action": "stop_completed",
                "hypothesis": "callback confirmed",
                "confirm_if": "event e1 is sufficient",
            }), "tools": []}},
        ))
        self.assertEqual(done["status"], "ready_to_assess")
        self.assertTrue(done["messages"])

    def test_stop_negative_assesses_after_repeated_no_new_evidence(self):
        obs = {
            "tools": ["search"],
            "signals": ["EMPTY", "NO_NEW_EVIDENCE"],
            "summary": "search=0 hit(s); signals=EMPTY, NO_NEW_EVIDENCE",
            "recommended_moves": ["change the angle instead of repeating the same query shape"],
            "advanced_objective": False,
        }
        result = _run(interpret(
            self._state(obs, retries=1),
            {"configurable": {"model": _StubModel({
                "what_showed": "two scoped searches returned no events",
                "advanced_objective": False,
                "blocker": "no corroborating evidence remains",
                "progress_status": "exhausted",
                "next_action": "stop_negative",
                "hypothesis": "",
                "confirm_if": "no more evidence appears in this window",
            }), "tools": []}},
        ))
        self.assertEqual(result["status"], "ready_to_assess")

    def test_concrete_event_can_route_to_stop_completed(self):
        obs = {
            "tools": ["get_event"],
            "signals": [],
            "summary": "retrieved event e1",
            "recommended_moves": [],
            "advanced_objective": True,
            "event_ids": ["e1"],
            "evidence_markers": ["event:e1"],
        }
        result = _run(interpret(
            self._state(obs),
            {"configurable": {"model": _StubModel({
                "what_showed": "event e1 confirms the callback",
                "advanced_objective": True,
                "blocker": "",
                "progress_status": "complete",
                "next_action": "stop_completed",
                "hypothesis": "callback confirmed",
                "confirm_if": "event e1 is sufficient",
            }), "tools": []}},
        ))
        self.assertEqual(result["status"], "ready_to_assess")
        self.assertEqual(result["task_ledger"]["next_action"], "stop_completed")

    def test_signals_cannot_initiate_completion_over_model_continue(self):
        # Completion is the MODEL's claim (criteria mapped to evidence); a clean batch
        # with new evidence must not escalate the model's continue vote into
        # stop_completed (regression: a decode task completed after one retrieval).
        from agent.runtime.graph.interpretation import _action_from_review
        obs = {
            "signals": [],
            "advanced_objective": True,
            "event_ids": ["e1"],
            "evidence_markers": ["event:e1"],
        }
        # Text-template continue vote: signals may not produce a terminal action.
        action = _action_from_review({"stop_state": "continue"}, obs)
        self.assertNotIn(action, {"stop_completed", "stop_negative"})
        # JSON-shaped continue vote: the model's own continue action is honored.
        action = _action_from_review({"next_action": "retrieve_specific_event"}, obs)
        self.assertEqual(action, "retrieve_specific_event")

    def test_success_criteria_section_parses_into_stop_condition(self):
        from agent.runtime.graph.interpretation import _parse_interpretation_text
        parsed = _parse_interpretation_text(
            "What the last batch showed:\n48 web hits retrieved, none decoded.\n\n"
            "Did it advance the task:\nyes — narrowed the candidate set\n\n"
            "Success criteria:\n"
            "(a) payload decoded — unmet; (b) callback destination named — unmet; "
            "(c) pivot on destination run — unmet\n\n"
            "Stop state:\ncontinue\n"
        )
        self.assertIn("payload decoded", parsed["stop_condition"])
        self.assertIn("callback destination named", parsed["stop_condition"])
        self.assertEqual(parsed["stop_state"], "continue")

    def test_triage_completes_on_aggregate_evidence_when_the_model_votes_complete(self):
        # Triage MAY hand off on a scoped aggregate (not only raw events) — but that is now
        # the model's semantic call, honored via its stop vote, not a deterministic gate.
        obs = {
            "tools": ["profile_field"],
            "signals": ["TRUNCATED"],
            "summary": "profiled nearby rule family and found a capped aggregate signal",
            "recommended_moves": ["hand off exact raw-event retrieval to investigation"],
            "advanced_objective": True,
            "evidence_queries": 1,
        }
        state = self._state(obs)
        state["agent_name"] = "triage"
        state["current_task"] = {
            "title": "Triage case ~1",
            "description": "Write a bounded triage handoff.",
        }
        state["task_ledger"]["objective"] = "Triage case ~1"
        result = _run(interpret(
            state,
            {"configurable": {"model": _StubModel({
                "what_showed": "A scoped aggregate query grounded the alert; raw drilldown is investigation work.",
                "advanced_objective": True,
                "blocker": "",
                "stop_state": "complete",
                "next_step_instruction": "Write the handoff.",
            }), "tools": []}},
        ))
        self.assertEqual(result["status"], "ready_to_assess")
        self.assertEqual(result["task_ledger"]["next_action"], "stop_completed")
        self.assertEqual(result["task_ledger"]["evidence_state"], "sufficient_handoff")

    def test_interpret_sets_evidence_state_and_instruction_for_scoped_hits(self):
        obs = {
            "tools": ["search"],
            "signals": [],
            "summary": "search=3 hit(s)",
            "recommended_moves": [],
            "advanced_objective": True,
            "event_ids": ["e1", "e2", "e3"],
            "evidence_markers": ["event:e1", "event:e2", "event:e3"],
        }
        result = _run(interpret(
            self._state(obs),
            {"configurable": {"model": _StubModel({
                "what_showed": "three scoped hits match the target entity",
                "advanced_objective": True,
                "blocker": "raw event semantics have not been interpreted",
                "next_action": "retrieve_specific_event",
                "hypothesis": "the hit set likely contains direct evidence",
                "evidence_state": "scoped_hits",
                "next_step_instruction": "Retrieve raw events e1-e3 and interpret payload semantics.",
                "stop_condition": "Raw events directly prove or disprove the task objective.",
            }), "tools": []}},
        ))
        ledger = result["task_ledger"]
        self.assertEqual(ledger["evidence_state"], "scoped_hits")
        self.assertIn("Retrieve raw events", ledger["next_step_instruction"])
        self.assertIn("Raw events", ledger["stop_condition"])

    def test_prior_evidence_found_survives_an_empty_follow_up(self):
        # A follow-up query that returns nothing must NOT erase evidence already
        # assimilated on the ledger (the merge carries prior facts forward).
        obs = {
            "tools": ["search"],
            "signals": ["EMPTY", "NO_NEW_EVIDENCE"],
            "summary": "search=0 hit(s)",
            "recommended_moves": ["try a different representation"],
            "advanced_objective": False,
        }
        state = self._state(obs)
        state["task_ledger"]["evidence_found"] = ["Payload execution behavior observed in event e1"]
        result = _run(interpret(
            state,
            {"configurable": {"model": _StubModel({
                "what_showed": "follow-up query returned no hits in this representation",
                "advanced_objective": False,
                "blocker": "the field representation may be wrong",
                "next_action": "retrieve_specific_event",
                "hypothesis": "prior evidence still stands",
            }), "tools": []}},
        ))
        evidence_found = result["task_ledger"]["evidence_found"]
        self.assertIn("Payload execution behavior observed in event e1", evidence_found)

    def test_interpret_carries_evidence_found_and_gaps(self):
        obs = {
            "tools": ["search"],
            "signals": [],
            "summary": "search=1 hit(s)",
            "recommended_moves": [],
            "advanced_objective": True,
            "event_ids": ["e1"],
            "evidence_markers": ["event:e1"],
        }
        result = _run(interpret(
            self._state(obs),
            {"configurable": {"model": _StubModel({
                "what_showed": "event e1 contains a timestamp, rule id, URL, and PHP error body",
                "advanced_objective": True,
                "blocker": "success or payload execution is not proven",
                "next_action": "retrieve_specific_event",
                "hypothesis": "scan tail reached application probing but not confirmed execution",
                "evidence_found": ["PHP error event e1 for admin.php under rule 30301"],
                "remaining_gaps": ["No successful payload or callback is proven by this event."],
            }), "tools": []}},
        ))
        ledger = result["task_ledger"]
        self.assertIn("admin.php", ledger["evidence_found"][0])
        self.assertIn("payload", ledger["remaining_gaps"][0])
        self.assertTrue(ledger["confirmed_findings"])
        self.assertIn("admin.php", ledger["confirmed_findings"][0]["summary"])
        self.assertEqual(ledger["confirmed_findings"][0]["event_ids"], ["e1"])

    def test_confirmed_findings_survive_empty_follow_up(self):
        obs = {
            "tools": ["search"],
            "signals": ["EMPTY", "NO_NEW_EVIDENCE"],
            "summary": "search=0 hit(s)",
            "recommended_moves": ["try another window"],
            "advanced_objective": False,
        }
        state = self._state(obs)
        state["task_ledger"]["confirmed_findings"] = [{
            "summary": "event e1 confirmed privileged command execution",
            "event_ids": ["e1"],
            "time_range": {},
            "entities": [],
            "kind": "raw_event_evidence",
            "confidence": "high",
            "status": "confirmed",
        }]
        result = _run(interpret(
            state,
            {"configurable": {"model": _StubModel({
                "what_showed": "follow-up query returned nothing",
                "advanced_objective": False,
                "blocker": "persistence remains unproven",
                "next_action": "pivot_entity",
                "hypothesis": "confirmed command still stands",
                "remaining_gaps": ["No persistence event yet."],
            }), "tools": []}},
        ))
        confirmed = result["task_ledger"]["confirmed_findings"]
        self.assertEqual(len(confirmed), 1)
        self.assertIn("privileged command", confirmed[0]["summary"])

    def test_stuck_direction_forces_change_and_clears_adjacency(self):
        # After _STUCK_RETRIES consecutive no-new-evidence cycles on the same objective, the
        # direction is exhausted: interpret must change the instruction (not echo the stale
        # one), clear the persistent adjacency, and record the dead shape.
        obs = {
            "tools": ["search"],
            "signals": ["EMPTY", "NO_NEW_EVIDENCE"],
            "summary": "search=0 hit(s)",
            "recommended_moves": [],
            "advanced_objective": False,
        }
        state = self._state(obs, retries=2)
        state["task_ledger"]["next_adjacent_evidence_path"] = {
            "entity": "hwarren", "representation_hint": "rule.id=5715 auth"}
        state["task_ledger"]["next_step_instruction"] = (
            "Inspect the post-peak authentication window for data.srcuser=hwarren with rule.id=5715")
        state["task_ledger"]["primary_pivot"] = {
            "field": "data.srcuser", "value": "hwarren", "status": "active",
            "confidence": "medium", "failure_count": 2}
        result = _run(interpret(state, {"configurable": {"model": None, "tools": []}}))
        ledger = result["task_ledger"]
        self.assertEqual(ledger["next_adjacent_evidence_path"], {})
        self.assertNotIn("5715", ledger["next_step_instruction"])
        self.assertIn("change", ledger["next_step_instruction"].lower())
        self.assertTrue(any("hwarren" in str(f) for f in ledger["forbidden_repeats"]))

    def _wander_obs(self, advanced=False):
        # A non-crystallizing cycle: a query ran but produced no new confirmed finding.
        # `advanced` toggles the advancement flicker that used to reset the old STUCK counter.
        return {
            "tools": ["search"],
            "signals": [] if advanced else ["EMPTY", "NO_NEW_EVIDENCE"],
            "summary": "search=0 hit(s)",
            "recommended_moves": [],
            "advanced_objective": advanced,
        }

    def test_no_progress_brake_injects_converge_signal_and_instruction(self):
        # At/above the threshold, the general convergence brake fires: it injects NO_PROGRESS
        # and the deterministic instruction tells the agent to CONVERGE, not re-query.
        state = self._state(self._wander_obs(), retries=1)
        state["no_progress_cycles"] = _NO_PROGRESS_BRAKE_CYCLES
        result = _run(interpret(state, {"configurable": {"model": None, "tools": []}}))
        self.assertIn("NO_PROGRESS", result["last_observation"]["signals"])
        instr = result["task_ledger"]["next_step_instruction"]
        self.assertIn("converge", instr.lower())

    def test_no_progress_brake_dormant_below_threshold(self):
        # Below the threshold the brake stays silent — a normal short task is never nudged.
        state = self._state(self._wander_obs(), retries=1)
        state["no_progress_cycles"] = _NO_PROGRESS_BRAKE_CYCLES - 1
        result = _run(interpret(state, {"configurable": {"model": None, "tools": []}}))
        self.assertNotIn("NO_PROGRESS", result["last_observation"]["signals"])

    def test_no_progress_counter_increments_without_new_finding(self):
        state = self._state(self._wander_obs(), retries=1)
        state["no_progress_cycles"] = 3
        result = _run(interpret(state, {"configurable": {"model": None, "tools": []}}))
        self.assertEqual(result["no_progress_cycles"], 4)

    def test_no_progress_counter_ignores_advancement_flicker(self):
        # THE key property: mere advanced_objective (with no NEW confirmed finding) does NOT
        # reset the counter — this is the wander that defeated the old STUCK detector.
        state = self._state(self._wander_obs(advanced=True), retries=0)
        state["no_progress_cycles"] = 5
        result = _run(interpret(state, {"configurable": {"model": None, "tools": []}}))
        self.assertFalse(result["status"] == "ready_to_assess")
        self.assertEqual(result["no_progress_cycles"], 6)

    def test_no_progress_counter_resets_on_new_confirmed_finding(self):
        obs = {
            "tools": ["search"],
            "signals": [],
            "summary": "search=1 hit(s)",
            "recommended_moves": [],
            "advanced_objective": True,
            "event_ids": ["e1"],
            "evidence_markers": ["event:e1"],
        }
        state = self._state(obs, retries=2)
        state["no_progress_cycles"] = 6
        result = _run(interpret(state, {"configurable": {"model": None, "tools": []}}))
        self.assertEqual(result["no_progress_cycles"], 0)

    def test_discriminator_observation_targets_minority(self):
        # A flooded observation carrying a discriminator -> instruction targets the rare
        # minority (data.id=200) / must_not the dominant, NOT the alert's rule.id.
        obs = {
            "tools": ["search"],
            "signals": ["TRUNCATED", "FLOODED"],
            "summary": "search=10000 hit(s); signals=TRUNCATED, FLOODED",
            "recommended_moves": [],
            "advanced_objective": False,
            "discriminator": {"field": "data.id", "dominant": "404", "minority": "200",
                              "sample_event_ids": ["ws1"]},
        }
        result = _run(interpret(self._state(obs), {"configurable": {"model": None, "tools": []}}))
        instr = result["task_ledger"]["next_step_instruction"]
        # The instruction routes to the flood's minority axis (read the sample, then
        # query the minority / must_not the dominant) — not the alert's own rule.id.
        self.assertIn("data.id", instr)
        self.assertIn("200", instr)
        self.assertIn("must_not", instr.lower())
        self.assertNotIn("rule.id=31151", instr)

    def test_model_next_adjacent_evidence_path_is_coerced(self):
        obs = {
            "tools": ["search"],
            "signals": [],
            "summary": "search=3 hit(s)",
            "recommended_moves": [],
            "advanced_objective": True,
            "event_ids": ["e1"],
            "evidence_markers": ["event:e1"],
        }
        result = _run(interpret(
            self._state(obs),
            {"configurable": {"model": _StubModel({
                "what_showed": "scan on wazuh-client confirmed",
                "advanced_objective": True,
                "next_action": "retrieve_specific_event",
                "hypothesis": "recon confirmed; execution not yet proven",
                "evidence_state": "scoped_hits",
                "next_adjacent_evidence_path": {
                    "entity": "agent.name=wazuh-client AND data.srcip=172.17.130.196",
                    "time_direction": "forward",
                    "window_hint": "start just after the last confirmed scan event; expand until payload-bearing events appear",
                    "representation_hint": "raw web events with suspicious PHP paths, encoded params",
                    "junk_key": "dropped",
                },
            }), "tools": []}},
        ))
        adj = result["task_ledger"]["next_adjacent_evidence_path"]
        self.assertEqual(adj["time_direction"], "forward")
        self.assertIn("wazuh-client", adj["entity"])
        self.assertIn("PHP paths", adj["representation_hint"])
        self.assertNotIn("junk_key", adj)

    def test_next_adjacent_evidence_path_persists_when_model_omits_it(self):
        # The forward-stage target must survive a later cycle that does not restate it,
        # so a flooded/empty batch cannot erase the "what happened next" pressure.
        obs = {
            "tools": ["search"],
            "signals": ["EMPTY", "NO_NEW_EVIDENCE"],
            "summary": "search=0 hit(s)",
            "recommended_moves": [],
            "advanced_objective": False,
        }
        state = self._state(obs)
        state["task_ledger"]["next_adjacent_evidence_path"] = {
            "entity": "agent.name=wazuh-client",
            "time_direction": "forward",
            "window_hint": "post-scan tail",
            "representation_hint": "process/audit events",
        }
        result = _run(interpret(
            state,
            {"configurable": {"model": _StubModel({
                "what_showed": "no hits in this representation",
                "advanced_objective": False,
                "next_action": "pivot_entity",
                "hypothesis": "wrong representation",
            }), "tools": []}},
        ))
        adj = result["task_ledger"]["next_adjacent_evidence_path"]
        self.assertEqual(adj["window_hint"], "post-scan tail")
        self.assertEqual(adj["time_direction"], "forward")

    def test_interpret_emits_next_step_instruction(self):
        obs = {
            "tools": ["get_case", "list_case_alerts"],
            "signals": ["ORIENTATION_ONLY"],
            "summary": "no concrete evidence returned; signals=ORIENTATION_ONLY",
            "recommended_moves": ["run a concrete SIEM evidence query for this task objective"],
            "advanced_objective": False,
            "orientation_facts": [{
                "case_id": "~1",
                "alert_time": "2022-01-18T12:19:10Z",
                "host": "wazuh-client",
                "src_ip": "172.17.130.196",
                "rule_id": "31151",
            }],
        }
        result = _run(interpret(
            self._state(obs),
            {"configurable": {"model": _StubModel({
                "what_showed": "case and alert context were loaded",
                "advanced_objective": False,
                "blocker": "no SIEM evidence query has run",
                "progress_status": "needs evidence",
                "next_action": "retrieve_specific_event",
                "next_step_instruction": "Run one concrete SIEM search for host wazuh-client and source 172.17.130.196 after 2022-01-18T12:19:10Z; do not repeat get_case or list_case_alerts.",
                "forbidden_repeats": ["get_case", "list_case_alerts"],
                "hypothesis": "recon is established; progression remains unknown",
                "confirm_if": "retrieve nearby events on the same host/source",
            }), "tools": []}},
        ))
        ledger = result["task_ledger"]
        self.assertIn("concrete SIEM search", ledger["next_step_instruction"])
        self.assertIn("get_case", ledger["forbidden_repeats"])
        # The guidance now travels on the ledger (consumed by `think`'s rebuild),
        # not the message history — a continuation clears messages so `think` does
        # not replay the original orientation checklist.
        self.assertEqual(result["messages"], [])

    def test_multi_regime_interpret_prefers_anchor_relative_selection(self):
        obs = {
            "tools": ["get_event_volume"],
            "signals": ["MULTI_REGIME"],
            "summary": "get_event_volume=1000 event(s), regimes=2; signals=MULTI_REGIME",
            "recommended_moves": ["compare candidate regimes against the alert anchor before narrowing"],
            "advanced_objective": False,
            "orientation_facts": [{
                "case_id": "~1",
                "alert_time": "2022-01-18T12:19:10Z",
                "host": "wazuh-client",
                "src_ip": "172.17.130.196",
            }],
            "volume_regimes": [
                {"start": "2022-01-18T12:17:30Z", "end": "2022-01-18T12:40:00Z", "peak_count": 300, "total": 600},
                {"start": "2022-01-19T09:00:00Z", "end": "2022-01-19T10:00:00Z", "peak_count": 900, "total": 1200},
            ],
        }
        result = _run(interpret(
            self._state(obs),
            {"configurable": {"model": _StubModel({
                "what_showed": "the profile surfaced two distinct regimes",
                "advanced_objective": False,
                "next_action": "profile_window",
                "next_step_instruction": "Drill the 2022-01-18T12:17:30Z to 2022-01-18T12:40:00Z regime because it is adjacent to the alert anchor on the same host/source; do not follow the larger Jan 19 burst.",
                "next_adjacent_evidence_path": {
                    "entity": "wazuh-client / 172.17.130.196",
                    "time_direction": "forward",
                    "window_hint": "2022-01-18T12:17:30Z to 2022-01-18T12:40:00Z",
                    "representation_hint": "raw web access events with full URI and parameters",
                },
                "forbidden_repeats": ["shrink around peak_time", "largest burst by default"],
                "hypothesis": "the Jan 18 regime is the relevant attack chain",
                "blocker": "the wrong burst would derail the investigation",
                "evidence_state": "aggregate_signal",
                "evidence_found": ["Two separate activity regimes exist in the window."],
                "remaining_gaps": ["Need raw events from the Jan 18 regime to confirm payload semantics."],
                "stop_condition": "retrieve the right regime's raw events",
            }), "tools": []}},
        ))
        ledger = result["task_ledger"]
        self.assertIn("2022-01-18T12:17:30Z", ledger["next_step_instruction"])
        self.assertIn("Jan 19", ledger["next_step_instruction"])
        self.assertIn("largest burst by default", ledger["forbidden_repeats"])

    def test_interpret_ready_path_keeps_recent_evidence_drops_seed_checklist(self):
        # On the ready-to-assess handoff, interpret must PRESERVE the recent tool evidence
        # (so `assess` can confirm a SIEM query ran and synthesize the report from it) while
        # dropping the seed task checklist HumanMessage. Stripping the tool messages here was
        # the bug that made triage persist a bare ledger summary with no ## Investigation Plan.
        obs = {
            "tools": ["search"],
            "signals": [],
            "summary": "search=1 hit(s)",
            "recommended_moves": [],
            "advanced_objective": True,
            "event_ids": ["e1"],
            "evidence_markers": ["event:e1"],
        }
        state = self._state(obs)
        state["messages"] = [
            SystemMessage(content="system"),
            HumanMessage(content="1. Load the case record. 2. ... original seed checklist"),
            AIMessage(content="", tool_calls=[{
                "name": "search",
                "args": {},
                "id": "call-1",
            }]),
            ToolMessage(content="raw search result for e1", tool_call_id="call-1", name="search"),
        ]
        result = _run(interpret(
            state,
            {"configurable": {"model": _StubModel({
                "what_showed": "event e1 answers the task",
                "advanced_objective": True,
                "blocker": "",
                "progress_status": "complete",
                "next_action": "stop_completed",
                "hypothesis": "task answered",
                "confirm_if": "event e1 is sufficient",
                "task_progress": "answered",
                "evidence_found": ["event e1 answers the task"],
                "stop_reason": "event e1 is sufficient",
            }), "tools": []}},
        ))
        msgs = result["messages"]
        # Recent tool evidence is preserved for assess/report synthesis.
        self.assertTrue(any(isinstance(m, ToolMessage) and "raw search result" in m.content for m in msgs))
        # The tail is a ToolMessage so assess routes into report synthesis, not "summary as report".
        self.assertIsInstance(msgs[-1], ToolMessage)
        self.assertTrue(any(isinstance(m, SystemMessage) for m in msgs))
        # The interpreted summary is carried as context.
        self.assertTrue(any("event e1 answers the task" in (m.content or "") for m in msgs))
        # The seed checklist HumanMessage is dropped.
        self.assertFalse(any("original seed checklist" in (m.content or "") for m in msgs))

    def test_fallback_emits_stop_completed_for_concrete_satisfying_evidence(self):
        obs = {
            "tools": ["get_event"],
            "signals": [],
            "summary": "retrieved event e1",
            "recommended_moves": [],
            "advanced_objective": True,
            "event_ids": ["e1"],
            "evidence_markers": ["event:e1"],
        }
        result = _run(interpret(
            self._state(obs),
            {"configurable": {"model": None, "tools": []}},
        ))
        self.assertEqual(result["status"], "ready_to_assess")
        self.assertEqual(result["task_ledger"]["next_action"], "stop_completed")

    def test_triage_can_stop_completed_via_model(self):
        obs = {
            "tools": ["search_keyword"],
            "evidence_queries": 1,
            "signals": [],
            "summary": "search_keyword=3 hit(s)",
            "recommended_moves": [],
            "advanced_objective": True,
            "event_ids": ["e1"],
            "small_scoped_evidence": True,
        }
        state = self._state(obs)
        state["agent_name"] = "triage"
        result = _run(interpret(
            state,
            {"configurable": {"model": _StubModel({
                "what_showed": "nearby events were checked and the task is complete",
                "advanced_objective": True,
                "blocker": "",
                "progress_status": "complete",
                "next_action": "stop_completed",
                "hypothesis": "triage complete",
                "confirm_if": "report can be written from gathered evidence",
            }), "tools": []}},
        ))
        self.assertEqual(result["status"], "ready_to_assess")
        self.assertEqual(result["task_ledger"]["next_action"], "stop_completed")

    def test_stop_completed_clears_stale_blocker_text(self):
        obs = {
            "tools": ["search_keyword", "get_event_volume", "profile_field"],
            "evidence_queries": 3,
            "signals": [],
            "summary": "search_keyword=66 hit(s), get_event_volume=438069 event(s)",
            "recommended_moves": [],
            "advanced_objective": True,
            "event_ids": ["e1", "e2"],
            "evidence_markers": ["event:e1", "event:e2"],
            "small_scoped_evidence": True,
        }
        state = self._state(obs)
        state["agent_name"] = "triage"
        result = _run(interpret(
            state,
            {"configurable": {"model": _StubModel({
                "what_showed": "scoped evidence is sufficient to summarize and hand off",
                "advanced_objective": True,
                "blocker": "No case-linked alert summary has been loaded into the ledger yet",
                "progress_status": "evidence_collected",
                "next_action": "stop_completed",
                "hypothesis": "enough evidence exists for triage handoff",
                "confirm_if": "report can be written from gathered evidence",
            }), "tools": []}},
        ))
        self.assertEqual(result["status"], "ready_to_assess")
        self.assertEqual(result["task_ledger"]["next_action"], "stop_completed")
        self.assertEqual(result["task_ledger"]["blocker"], "")

    def test_stop_completed_does_not_survive_needs_more_work_status(self):
        obs = {
            "tools": ["search"],
            "signals": ["TRUNCATED"],
            "summary": "search=10000 hit(s); signals=TRUNCATED",
            "recommended_moves": ["narrow the query before trusting the sample"],
            "advanced_objective": True,
            "event_ids": ["e1"],
            "evidence_markers": ["event:e1"],
        }
        result = _run(interpret(
            self._state(obs),
            {"configurable": {"model": _StubModel({
                "what_showed": "an event was found but the batch is still truncated",
                "advanced_objective": True,
                "blocker": "query still too broad",
                "progress_status": "working",
                "next_action": "stop_completed",
                "hypothesis": "a key event exists",
                "confirm_if": "retrieve a usable sample first",
            }), "tools": []}},
        ))
        self.assertEqual(result["status"], "needs_more_work")
        self.assertEqual(result["task_ledger"]["next_action"], "refine_query")

    def test_triage_still_continues_on_truncated_result(self):
        obs = {
            "tools": ["search_keyword"],
            "evidence_queries": 1,
            "signals": ["TRUNCATED"],
            "summary": "search_keyword=10000 hit(s); signals=TRUNCATED",
            "recommended_moves": ["narrow the query before trusting the sample"],
            "advanced_objective": False,
        }
        state = self._state(obs)
        state["agent_name"] = "triage"
        result = _run(interpret(
            state,
            {"configurable": {"model": _StubModel({
                "what_showed": "the result is truncated and cannot support completion",
                "advanced_objective": False,
                "blocker": "query too broad",
                "progress_status": "needs refinement",
                "next_action": "refine_query",
                "hypothesis": "",
                "confirm_if": "retrieve a usable sample",
            }), "tools": []}},
        ))
        self.assertEqual(result["status"], "needs_more_work")
        self.assertEqual(result["task_ledger"]["next_action"], "refine_query")

    def test_triage_respects_model_continue_vote_no_deterministic_force_upgrade(self):
        # There is NO deterministic triage lower-bar that force-upgrades a continue vote into
        # completion. Even with scoped evidence present, if the model votes to keep going
        # (here: pivot_entity), triage keeps going — completion is the model's judgment.
        obs = {
            "tools": ["search"],
            "evidence_queries": 1,
            "signals": [],
            "summary": "search=3 hit(s)",
            "recommended_moves": [],
            "advanced_objective": True,
            "event_ids": ["e1", "e2", "e3"],
            "evidence_markers": ["event:e1", "event:e2", "event:e3"],
        }
        state = self._state(obs)
        state["agent_name"] = "triage"
        result = _run(interpret(
            state,
            {"configurable": {"model": _StubModel({
                "what_showed": "small scoped set retrieved; want to correlate the entity next",
                "advanced_objective": True,
                "blocker": "",
                "progress_status": "working",
                "next_action": "pivot_entity",
                "hypothesis": "not yet grounded — correlate before concluding",
                "confirm_if": "surrounding activity read",
            }), "tools": []}},
        ))
        self.assertEqual(result["status"], "needs_more_work")
        self.assertEqual(result["task_ledger"]["next_action"], "pivot_entity")

    def _flood_with_evidence_obs(self):
        # The dd2d9d8d shape: a flood on the latest batch, but concrete evidence already
        # accumulated (8 event ids, 12 markers).
        return {
            "tools": ["search"],
            "evidence_queries": 4,
            "signals": ["TRUNCATED", "FLOODED"],
            "summary": "search=10000 hit(s); signals=TRUNCATED,FLOODED",
            "recommended_moves": ["scope by rule.groups"],
            "advanced_objective": False,
            "event_ids": [f"e{i}" for i in range(8)],
            "evidence_markers": [f"event:e{i}" for i in range(12)],
        }

    def test_triage_may_complete_on_flood_when_the_model_votes_complete(self):
        # For triage a flood is a needs-investigation cue, not a keep-drilling one: once the
        # model judges the alert grounded and votes complete, `_should_assess` grants the
        # handoff even on a FLOODED/TRUNCATED batch (its triage-only tolerance is preserved).
        state = self._state(self._flood_with_evidence_obs())
        state["agent_name"] = "triage"
        result = _run(interpret(
            state,
            {"configurable": {"model": _StubModel({
                "what_showed": "flooded, but the alert is grounded in the events already read",
                "advanced_objective": False,
                "blocker": "",
                "stop_state": "complete",
                "hypothesis": "scanning + lateral movement",
                "confirm_if": "enough scoped evidence to route",
            }), "tools": []}},
        ))
        self.assertEqual(result["status"], "ready_to_assess")
        self.assertEqual(result["task_ledger"]["next_action"], "stop_completed")

    def test_investigation_does_not_complete_on_flood_even_with_evidence(self):
        # The triage handoff shortcut is triage-only: investigation must NOT conclude a
        # finding on a flooded batch — it keeps refining.
        state = self._state(self._flood_with_evidence_obs())  # agent_name stays investigation
        result = _run(interpret(
            state,
            {"configurable": {"model": _StubModel({
                "what_showed": "flooded", "advanced_objective": False,
                "blocker": "too broad", "progress_status": "needs refinement",
                "next_action": "refine_query", "hypothesis": "", "confirm_if": "narrow it",
            }), "tools": []}},
        ))
        self.assertEqual(result["status"], "needs_more_work")
        self.assertNotEqual(result["task_ledger"]["next_action"], "stop_completed")

    def test_repeated_failed_exemplar_pivot_broadens_to_behavior_family(self):
        obs = {
            "tools": ["search_keyword"],
            "evidence_queries": 1,
            "signals": ["FLOODED", "NO_NEW_EVIDENCE"],
            "summary": "search_keyword flooded without new evidence",
            "recommended_moves": ["change the angle instead of repeating the same query shape"],
            "advanced_objective": False,
            "pivot_candidates": [{
                "field": "url",
                "value": "/wp-content/create_account",
                "source_level": "case",
                "role": "exemplar",
                "confidence": "low",
                "status": "active",
                "failure_count": 1,
                "last_failure_reason": "flooded",
                "broader_alternative": "/wp-content/*",
            }],
        }
        state = self._state(obs)
        state["task_ledger"]["primary_pivot"] = {
            "field": "url",
            "value": "/wp-content/create_account",
            "source_level": "case",
            "role": "exemplar",
            "confidence": "low",
            "status": "active",
            "failure_count": 1,
            "last_failure_reason": "flooded",
            "broader_alternative": "/wp-content/*",
        }
        state["task_ledger"]["active_pivots"] = [dict(state["task_ledger"]["primary_pivot"])]
        result = _run(interpret(
            state,
            {"configurable": {"model": _StubModel({
                "what_showed": "the exact path kept flooding and did not add new evidence",
                "advanced_objective": False,
                "blocker": "exact path is too specific",
                "next_action": "refine_query",
                "hypothesis": "web probing is broader than one path",
            }), "tools": []}},
        ))
        ledger = result["task_ledger"]
        self.assertEqual(ledger["next_pivot_strategy"], "broaden")
        self.assertEqual(ledger["primary_pivot"]["value"], "/wp-content/*")
        self.assertIn("provisional example", ledger["next_step_instruction"])


class QueryTrialsTest(unittest.TestCase):
    """The outcome-annotated trial history the interpreter reasons over (matching-logic +
    time-window autocorrection). See project memory trial-memory."""

    def _obs_with_trial(self, discriminator, window, outcome, hits=None):
        return {
            "tools": ["search"],
            "signals": ["EMPTY"] if outcome == "empty" else [],
            "summary": f"search={hits or 0} hit(s)",
            "recommended_moves": [],
            "advanced_objective": outcome == "scoped_hits",
            "trials": [{"discriminator": discriminator, "window": window,
                        "outcome": outcome, **({"hits": hits} if hits is not None else {})}],
        }

    def test_observation_records_trial_from_search_args(self):
        obs = build_observation([{
            "name": "search",
            "args": {"query": {"bool": {"must": [{"term": {"url": "/wp-content/create_account"}}]}},
                     "time_range": {"from": "2022-01-18T12:19:10Z", "to": "2022-01-18T12:24:30Z"}},
            "raw": json.dumps({"total": 0, "events": []}),
            "artifacts": [],
        }], objective="trace tail")
        self.assertEqual(len(obs["trials"]), 1)
        t = obs["trials"][0]
        self.assertIn("url=/wp-content/create_account", t["discriminator"])
        self.assertEqual(t["outcome"], "empty")
        self.assertIn("12:19:10Z..", t["window"])

    def test_trial_preserves_retrieved_event_semantics(self):
        # A trial that returned events keeps a compact digest of WHAT it retrieved, so the
        # interpreter can analyze past queries' content after the events scroll out.
        obs = build_observation([{
            "name": "search",
            "args": {"query": {"bool": {"must": [{"term": {"rule.groups": "web"}}]}},
                     "time_range": {"from": "2022-01-18T12:38:00Z", "to": "2022-01-18T12:40:00Z"}},
            "raw": json.dumps({"total": 2, "events": [{
                "_id": "ws1", "rule.id": "31108", "rule.description": "Ignored URLs",
                "rule.groups": "web", "data.url": "/wp-content/uploads/2022/01/x.php",
                "data.id": "200"}]}),
            "artifacts": [],
        }], objective="find webshell")
        t = obs["trials"][0]
        self.assertEqual(t["outcome"], "scoped_hits")
        self.assertTrue(t.get("evidence"))
        self.assertIn("/wp-content/uploads/2022/01/x.php", t["evidence"][0])
        # ...and it renders under the trial line for the interpreter to read.
        from agent.runtime.graph.interpretation import _render_query_trials
        rendered = _render_query_trials(obs["trials"])
        self.assertIn("31108", rendered)
        self.assertIn("/wp-content/uploads/2022/01/x.php", rendered)

    def test_trials_accumulate_and_repeat_increments_count(self):
        state = InterpretContractTest()._state(
            self._obs_with_trial("dsl:url=/wp-content/create_account",
                                 "2022-01-18T12:19:10Z..2022-01-18T12:24:30Z", "empty", hits=0),
            retries=1,
        )
        cfg = {"configurable": {"model": None, "tools": []}}
        r1 = _run(interpret(state, cfg))
        trials = r1["task_ledger"]["query_trials"]
        self.assertEqual(len(trials), 1)
        self.assertEqual(trials[0]["count"], 1)
        # Feed the same trial again with the accumulated ledger → count increments, not dup.
        state2 = InterpretContractTest()._state(
            self._obs_with_trial("dsl:url=/wp-content/create_account",
                                 "2022-01-18T12:19:10Z..2022-01-18T12:24:30Z", "empty", hits=0),
            retries=2,
        )
        state2["task_ledger"]["query_trials"] = trials
        r2 = _run(interpret(state2, cfg))
        trials2 = r2["task_ledger"]["query_trials"]
        self.assertEqual(len(trials2), 1)
        self.assertEqual(trials2[0]["count"], 2)

    def test_compromise_block_surfaces_boarded_decoded_indicators(self):
        # A decoded compromise indicator on the board is surfaced prominently to interpret
        # with a must-disposition instruction — even if the raw event was past the 24KB cap
        # (diagnosed: a decoded webshell cracking command was boarded but never addressed).
        from agent.runtime.graph.interpretation import _prompt, _compromise_block
        facts = ["command: [decoded] ./wphashcrack-0.1/wphashcrack.sh -w $PWD/rockyou.txt -u phopkins [EavD3M2o]"]
        block = _compromise_block(facts)
        self.assertIn("CONFIRMED COMPROMISE INDICATORS", block)
        self.assertIn("wphashcrack", block)
        self.assertIn("disposition", block.lower())
        text = _prompt({"title": "t"}, {"objective": "x"}, {"trials": []}, "", "", facts)
        self.assertIn("wphashcrack", text)
        # Empty when there are none.
        self.assertEqual(_compromise_block([]), "")

    def test_full_tool_outputs_passed_to_interpret_untruncated(self):
        from agent.runtime.graph.interpretation import _batch_tool_outputs, _prompt
        raw = ('{"total":1,"events":[{"_id":"ws1","data":{"url":'
               '"/wp-content/uploads/2022/01/x.php?wp_meta=W10=","id":"200"}}]}')
        msgs = [
            SystemMessage(content="s"), HumanMessage(content="h"),
            AIMessage(content="", tool_calls=[{"id": "1", "name": "search", "args": {}}]),
            ToolMessage(content=raw, tool_call_id="1", name="search"),
        ]
        outputs = _batch_tool_outputs(msgs)
        # The complete result — including the encoded payload — is present, not a digest.
        self.assertIn("wp_meta=W10=", outputs)
        text = _prompt({"title": "t"}, {"objective": "x"}, {"trials": []}, "", outputs)
        self.assertIn("Full tool outputs this batch", text)
        self.assertIn("wp_meta=W10=", text)

    def test_prompt_dedups_rendered_fields_from_json_dumps(self):
        # query_trials is rendered once (the trials block), not again in the ledger JSON
        # dump; observation trials/evidence_digest/evidence_snapshots are not re-dumped.
        from agent.runtime.graph.interpretation import _prompt
        ledger = {"objective": "x", "query_trials": [
            {"discriminator": "dsl:url=UNIQUEDISCRIM", "window": "w", "outcome": "empty", "count": 1}]}
        obs = {"signals": ["EMPTY"], "trials": [], "evidence_digest": ["DIGESTONLYMARKER"],
               "evidence_snapshots": [{"url": "SNAPSHOTMARKER"}]}
        text = _prompt({"title": "t"}, ledger, obs, "")
        # The trial's discriminator appears exactly once (the block), not twice (block + dump).
        self.assertEqual(text.count("UNIQUEDISCRIM"), 1)
        # The observation's snapshot-only field is not dumped (it's in the full outputs).
        self.assertNotIn("SNAPSHOTMARKER", text)
        # Signals (single-rendered state) still present in the observation dump.
        self.assertIn("EMPTY", text)

    def test_prompt_renders_trials_block_with_autocorrect_guidance(self):
        from agent.runtime.graph.interpretation import _prompt
        ledger = {
            "objective": "trace tail",
            "query_trials": [
                {"discriminator": "dsl:url=/wp-content/create_account",
                 "window": "2022-01-18T12:19:10Z..2022-01-18T12:24:30Z",
                 "outcome": "empty", "count": 14, "hits": 0},
            ],
        }
        text = _prompt({"title": "t"}, ledger, {"trials": []}, "")
        self.assertIn("query trials so far", text.lower())
        self.assertIn("url=/wp-content/create_account", text)
        self.assertIn("x14", text)  # the repetition is made glaring
        self.assertIn("MATCHING-LOGIC", text)  # the empty→profile/subtract guidance


if __name__ == "__main__":
    unittest.main(verbosity=2)
