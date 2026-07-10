#!/usr/bin/env python3
"""End-to-end benchmark orchestrator.

    1. prepare the alert dataset (download + preprocess)
    2. for each scenario, run the test cycle:
         a. clean up any prior Wazuh + TheHive data
         b. populate the preprocessed events into Wazuh + TheHive
         c. run the scenario tests and record metrics
         d. tear down the Wazuh + TheHive data (always, even if the tests fail)

Run from the project root (with the venv active):

    python3 run_benchmark.py                          # scenario: fox
    python3 run_benchmark.py --scenarios fox harrison --trials 3
    python3 run_benchmark.py --skip-prepare           # reuse an existing dataset

Prerequisites (see benchmark/README.md): the project set up with the model provider and
Wazuh/TheHive connections configured in the dashboard, `elasticdump` on PATH, and the live
services running. This drives the same stages as `python -m benchmark <stage>` in-process,
so connection/config resolution is shared — there is no duplicated logic here.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from pathlib import Path

# Run as a standalone script (`python3 run_benchmark.py`): make the project root importable
# so `benchmark`, `agent`, and `aci` resolve regardless of the current working directory.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from benchmark import cli  # noqa: E402

_DATA = cli._DATA


def _bench(*argv: str) -> None:
    print(f"\n\033[1m==> benchmark {' '.join(argv)}\033[0m")
    cli.main(list(argv))


# ── 1. prepare ────────────────────────────────────────────────────────────────
def prepare(scenarios: list[str], skip: bool = False) -> None:
    if skip:
        print("== 1. prepare dataset — skipped (--skip-prepare) ==")
        return
    _bench("acquire")
    for s in scenarios:
        _bench("preprocess", "--scenario", s)


# ── 2. per-scenario test cycle ────────────────────────────────────────────────
def run_scenario(scenario: str, trials: int | None = None) -> Exception | None:
    # 2a. clean up prior data (best-effort — nothing to clean on a fresh env)
    try:
        _bench("teardown", "--scenario", scenario)
    except Exception as exc:  # noqa: BLE001
        print(f"  (pre-clean teardown skipped: {exc})")

    failure: Exception | None = None
    try:
        # 2b. populate
        _bench("load-wazuh", "--scenario", scenario)
        _bench("load-thehive", "--scenario", scenario)
        # 2c. run + record metrics
        run_argv = ["run", "--scenario", scenario]
        if trials:
            run_argv += ["--trials", str(trials)]
        _bench(*run_argv)
        _bench("report", "--scenario", scenario)
    except Exception as exc:  # noqa: BLE001
        failure = exc
        traceback.print_exc()
    finally:
        # 2d. teardown — always runs
        try:
            _bench("teardown", "--scenario", scenario)
        except Exception as exc:  # noqa: BLE001
            print(f"  (final teardown error: {exc})")
    return failure


# ── token/cost summary ────────────────────────────────────────────────────────
def _token_cost(scenarios: list[str]) -> None:
    pricing = (cli._run_cfg().get("pricing") or {})
    in_price = float(pricing.get("input_per_mtok", 0.0))
    out_price = float(pricing.get("output_per_mtok", 0.0))
    print("\n== tokens / cost ==")
    grand_in = grand_out = 0
    for s in scenarios:
        s_in = s_out = trials = 0
        for meta_path in sorted((_DATA / "runs" / s).rglob("meta.json")):
            tok = (json.loads(meta_path.read_text(encoding="utf-8")).get("tokens") or {})
            s_in += int(tok.get("input") or 0)
            s_out += int(tok.get("output") or 0)
            trials += 1
        if not trials:
            print(f"  {s}: (no runs)")
            continue
        cost = s_in / 1e6 * in_price + s_out / 1e6 * out_price
        print(f"  {s}: {trials} trials | input={s_in:,} output={s_out:,} tok"
              f" | ${cost:,.2f} (${cost / trials:,.2f}/run @ ${in_price}/${out_price} per Mtok)")
        grand_in += s_in
        grand_out += s_out
    if len(scenarios) > 1 and (grand_in or grand_out):
        total = grand_in / 1e6 * in_price + grand_out / 1e6 * out_price
        print(f"  TOTAL: input={grand_in:,} output={grand_out:,} tok | ${total:,.2f}")


# ── metrics summary ───────────────────────────────────────────────────────────
def _summary(scenarios: list[str]) -> None:
    print("\n== metrics ==")
    for s in scenarios:
        path = _DATA / "results" / f"{s}.json"
        if not path.exists():
            print(f"  {s}: (no results — {path} missing)")
            continue
        print(f"  {s}: {path} (+ .md, .csv)")
        data = json.loads(path.read_text(encoding="utf-8"))
        for entry_point, block in data.items():
            per_key = block.get("metrics", {}).get("phase_recall", {}).get("per_key")
            if per_key:
                reached = sum(1 for rate in per_key.values() if rate > 0)
                print(f"    {entry_point}: phase_recall {reached}/{len(per_key)} phases "
                      f"reached in >=1 of {block.get('trials')} trials")
    _token_cost(scenarios)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="run_benchmark.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenarios", nargs="+", default=["fox"])
    ap.add_argument("--trials", type=int, default=None)
    ap.add_argument("--skip-prepare", action="store_true")
    args = ap.parse_args(argv)

    prepare(args.scenarios, skip=args.skip_prepare)

    failed: list[str] = []
    for s in args.scenarios:
        if run_scenario(s, args.trials) is not None:
            failed.append(s)

    _summary(args.scenarios)

    if failed:
        print(f"\n\033[31mFAILED scenarios: {', '.join(failed)}\033[0m")
        return 1
    print("\n\033[32mall scenarios completed\033[0m")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
