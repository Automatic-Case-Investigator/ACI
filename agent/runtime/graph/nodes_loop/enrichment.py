from __future__ import annotations

"""Post-tool enrichment: memoize, correlate, kill-chain, TI."""

from ..toolio import _call
from ...infra.logbus import emit


# ── Post-tool enrichment (use_tools helpers): memoize, correlate, kill-chain, TI ──
def _memoize_query_and_schema(
    tool_name: str, args: dict, raw: str, state: dict, src: str
) -> None:
    """Record a once-per-run board memo for over-broad query shapes and discovered
    schema fields (Phase 1 #13/#18), so later tasks don't re-pay the same broad-query
    tax or re-derive field names. Dedup keys make each shape/schema recorded once."""
    from ...analysis.query_memo import broad_query_memo, extract_schema_fields
    from ..board import _record_board_entry

    memo = broad_query_memo(tool_name, args, raw)
    if memo:
        dedup_key, content = memo
        _record_board_entry(
            state,
            kind="query_memo",
            content=content,
            source="auto-memo",
            confidence="high",
            status="observed",
            dedup_key=dedup_key,
        )
        emit(src, "note", f"query memo: recorded broad query shape ({dedup_key})")

    fields = extract_schema_fields(tool_name, raw)
    if fields:
        idx = args.get("index_pattern") or "default"
        content = f"index `{idx}` fields ({len(fields)}): " + ", ".join(fields)
        _record_board_entry(
            state,
            kind="schema_fields",
            content=content[:1400],
            source="auto-memo",
            confidence="high",
            status="observed",
            dedup_key=f"schema:{idx}",
        )
        emit(src, "note", f"schema memo: recorded {len(fields)} field(s) for {idx}")


async def _auto_correlate_entities(
    artifacts: list, raw: str, state: dict, tmap: dict, src: str
) -> None:
    """Correlate confirmed entities and assemble the connected incident graph on
    the findings board — the graph does this instead of relying on the model to call
    the tool (Fix 1; mirrors TI enrichment).

    Multi-hop (Fix #2): seed entities come from the tool result; when correlating one
    surfaces NEW high-value entities among its neighbors, those are correlated too —
    a bounded breadth-first walk (depth-limited, deduped per run, capped) that builds
    the linked attack graph rather than isolated 1-hop cards. The board injects the
    result into the next think prompt, so the model reasons over the graph.

    Emits a `metric` event per correlation for adoption/coverage telemetry (Fix 3).
    """
    corr_fn = tmap.get("correlate_entity")
    if corr_fn is None:
        return
    try:
        from collections import deque

        from ...analysis.correlation_leads import (
            MAX_CORRELATIONS,
            MAX_HOP_DEPTH,
            corr_dedup_key,
            derive_window,
            entities_from_neighbors,
            field_for,
            match_fields_for,
            select_targets,
            summarize_correlation,
        )
        from aci_board import store as board_store

        case_id, run_id, agent_name = (
            state["case_id"],
            state["run_id"],
            state["agent_name"],
        )
        board_store.init_db()
        existing = [
            e
            for e in board_store.list_entries(case_id, run_id, agent_name)
            if e.get("kind") == "correlation"
        ]
        covered = {(e.get("dedup_key") or "").lower() for e in existing}
        seeds = select_targets(
            artifacts,
            covered=covered,
            remaining_budget=MAX_CORRELATIONS - len(existing),
        )
        if not seeds:
            return

        vicinity = int(state.get("default_vicinity_window_hours") or 24)
        start, end = derive_window(raw, vicinity)

        # Breadth-first correlation walk. `visited` spans the run (board) + this walk
        # so an entity is correlated at most once; `remaining` enforces the run cap.
        visited = set(covered)
        remaining = MAX_CORRELATIONS - len(existing)
        queue: deque = deque((k, v, f, 0, None) for k, v, f in seeds)
        while queue and remaining > 0:
            kind, value, field, depth, via = queue.popleft()
            key = corr_dedup_key(kind, value)
            if key in visited:
                continue
            visited.add(key)

            args = {
                "field": field,
                "value": value,
                "match_fields": match_fields_for(kind),
            }
            if start and end:
                args["start_time"], args["end_time"] = start, end
            result_raw = await _call(corr_fn, args, _dbg=src)
            content, neighbor_count, has_cross = summarize_correlation(
                kind, value, result_raw, via=via
            )
            board_store.add_entry(
                case_id=case_id,
                run_id=run_id,
                agent_name=agent_name,
                kind="correlation",
                content=content,
                source="auto-correlation",
                confidence="high",
                status="observed",
                dedup_key=key,
            )
            remaining -= 1
            emit(
                src,
                "note",
                f"auto-correlation[h{depth}]: {field}={value} → {neighbor_count} neighbor field(s)"
                + (f" (via {via})" if via else "")
                + (" +cross_role" if has_cross else ""),
            )
            emit(
                src,
                "metric",
                f"correlation entity={kind}:{value} depth={depth} neighbors={neighbor_count} cross_role={int(has_cross)}",
            )

            # Expand: enqueue newly-discovered neighbor entities for the next hop.
            if depth + 1 < MAX_HOP_DEPTH:
                for nk, nv in entities_from_neighbors(result_raw):
                    nkey = corr_dedup_key(nk, nv)
                    if nkey not in visited:
                        queue.append(
                            (nk, nv, field_for(nk), depth + 1, f"{kind}:{value}")
                        )
    except Exception as exc:
        emit(src, "warning", "auto-correlation failed", detail=str(exc))


async def _build_kill_chain(
    artifacts: list, raw: str, state: dict, tmap: dict, src: str
) -> None:
    """Build the MITRE ATT&CK kill-chain view for the case host and write it to the
    board (Fix #3). Runs once per run: triggered when a host artifact appears (real
    SIEM data is present) and no kill-chain entry exists yet. The board entry orders
    observed techniques along the kill chain and names the core phases with no
    evidence as gaps to investigate — the adversary-behavior view, graph-provided.
    """
    tech_fn = tmap.get("correlate_techniques")
    if tech_fn is None:
        return
    hosts = [
        a.value for a in artifacts if getattr(a, "kind", None) == "host" and a.value
    ]
    if not hosts:
        return  # only attempt once we have a host to scope the kill chain to
    try:
        from ...analysis.correlation_leads import derive_window
        from ...analysis.kill_chain import (
            drop_covered_specs,
            gap_lead_specs,
            summarize_kill_chain,
        )
        from aci_board import store as board_store

        case_id, run_id, agent_name = (
            state["case_id"],
            state["run_id"],
            state["agent_name"],
        )
        board_store.init_db()
        if any(
            e.get("kind") == "kill_chain"
            for e in board_store.list_entries(case_id, run_id, agent_name)
        ):
            return  # already built this run

        vicinity = int(state.get("default_vicinity_window_hours") or 24)
        start, end = derive_window(raw, vicinity)
        args: dict = {"query": {"term": {"agent.name": hosts[0]}}}
        if start and end:
            args["start_time"], args["end_time"] = start, end
        result_raw = await _call(tech_fn, args, _dbg=src)
        content, observed, gaps = summarize_kill_chain(result_raw)
        # Only persist once techniques exist, so an early (pre-evidence) call doesn't
        # lock in an empty kill chain; a later host-bearing batch will populate it.
        if observed:
            board_store.add_entry(
                case_id=case_id,
                run_id=run_id,
                agent_name=agent_name,
                kind="kill_chain",
                content=content,
                source="auto-killchain",
                confidence="high",
                status="observed",
                dedup_key="killchain",
            )
            emit(
                src,
                "note",
                f"kill-chain: {len(observed)} tactic(s) observed; "
                f"{len(gaps)} core gap(s)",
            )
            emit(
                src,
                "metric",
                f"kill_chain tactics={len(observed)} gaps={len(gaps)} host={hosts[0]}",
            )

            # Fix #1: turn the gaps into concrete, prioritized, auto-queued leads
            # instead of relying on the model to convert the board GAP into a lead.
            if gaps:
                from aci_taskqueue import store as tq_store

                tq_store.init_db()
                specs = gap_lead_specs(
                    gaps,
                    hosts[0],
                    window_hint=f"Window: ±{vicinity}h around the case/alert anchor timestamp.",
                    observed=observed,
                )
                # These go straight onto the queue, so they miss the lead validator
                # that dedups every other lead source. Without this, a forward-trace
                # lead duplicates a triage plan item AND outranks it (88 > 85/80/75),
                # so the duplicate runs first and the plan item finds nothing left.
                before = len(specs)
                specs = drop_covered_specs(
                    specs,
                    tq_store.list_tasks(case_id, run_id, agent_name) or [],
                )
                if before != len(specs):
                    emit(
                        src,
                        "note",
                        f"kill-chain gap leads: {before - len(specs)} already covered by "
                        "a queued task — skipped",
                    )
                for s in specs:
                    tq_store.create_task(
                        case_id=case_id,
                        run_id=run_id,
                        agent_name=agent_name,
                        title=s["title"],
                        description=s["description"],
                        priority=s["priority"],
                        origin="killchain_gap",
                    )
                if specs:
                    emit(
                        src,
                        "note",
                        f"kill-chain gap leads: {len(specs)} task(s) queued",
                    )
                    emit(src, "metric", f"killchain_gap_leads={len(specs)}")
    except Exception as exc:
        emit(src, "warning", "kill-chain build failed", detail=str(exc))


async def _enrich_artifacts_async(artifacts: list, state: dict, src: str) -> None:
    """Enrich extracted artifacts against configured TI providers.

    Silently no-ops when no TI provider is configured (VT_API_KEY not set).
    Errors are caught and emitted as warnings so enrichment failures never
    interrupt the investigation graph.
    """
    try:
        from agent.ti.enricher import create_ti_leads, get_enricher, write_ti_results
    except Exception:
        return

    # get_enricher() reads ProviderConfig via the Django ORM, which raises
    # SynchronousOnlyOperation on the event loop (and is silently swallowed,
    # disabling TI). Build it on a worker thread so the ORM runs in sync context;
    # once cached, later calls are cheap and ORM-free.
    import asyncio

    enricher = await asyncio.to_thread(get_enricher)
    if enricher is None:
        return

    try:
        results = await enricher.enrich_artifacts_async(
            artifacts,
            case_id=state["case_id"],
            run_id=state["run_id"],
            agent_name=state["agent_name"],
        )
    except Exception as exc:
        emit(src, "warning", "TI enrichment failed", detail=str(exc))
        return

    if not results:
        return

    try:
        flagged = write_ti_results(
            results,
            case_id=state["case_id"],
            run_id=state["run_id"],
            agent_name=state["agent_name"],
        )
    except Exception as exc:
        emit(src, "warning", "TI board write failed", detail=str(exc))
        return

    verdicts = ", ".join(
        f"{r.artifact_kind} {r.artifact_value}={r.verdict}" for r in results
    )
    emit(src, "note", f"TI enrichment: {len(results)} result(s) — {verdicts}")

    if flagged:
        try:
            n = create_ti_leads(
                flagged,
                case_id=state["case_id"],
                run_id=state["run_id"],
                agent_name=state["agent_name"],
            )
            if n:
                emit(src, "note", f"TI enrichment: {n} investigation lead(s) created")
        except Exception as exc:
            emit(src, "warning", "TI lead creation failed", detail=str(exc))
