# ACI Agent Benchmark

End-to-end evaluation of the triage/investigation agents against a labelled attack
dataset (AIT-LDS). It acquires and preprocesses the dataset, loads it into Wazuh +
TheHive, runs the agents against defined entry points, and scores the runs against
ground truth.

This lives outside the offline `tests/` tree on purpose: it needs live services
(Wazuh, TheHive, LLM, AVFS), runs for a long time, and emits **metrics**, not
pass/fail assertions. The pure scoring logic *is* unit-tested offline, under
`tests/unit/benchmark/`.

## Structure

```
benchmark/
  cli.py / __main__.py         # `python -m benchmark <stage>` — stages map 1:1 to pipeline/
  config/
    datasets.yaml              # dataset source (Zenodo record, scenarios, checksums)
    run.yaml                   # trial params: N trials, caps, metric selection, poll timeout
    scenarios/<name>.yaml      # per-scenario ground truth: phases, host map, entry points, expected verdict
  pipeline/                    # the stages (each importable + idempotent + teardown-by-tag)
    acquire · preprocess · load_wazuh · load_thehive · runner · score · report
  scoring/                     # the metric plugin system
    base.py                    #   Metric + MetricResult contracts
    context.py                 #   ScoringContext (parsed run + ground truth, built once)
    registry.py                #   @register + selected/run_all (scorer never hardcodes a list)
    aggregate.py               #   metric-agnostic roll-up across N trials, keyed off MetricResult.kind
    judges/llm_judge.py        #   shared model-call wrapper for judge-based metrics
    metrics/<metric>.py        #   ONE FILE PER METRIC — auto-discovered; adding one touches nothing else
  fixtures/labels.csv          # canonical AIT ground-truth phase windows (committed)
  data/                        # gitignored generated artifacts (raw/ preprocessed/ runs/ results/ manifests/)
```

Committed = code, config, scenario specs, labels. Generated = everything under `data/`.

## Running the benchmark

### Prerequisites

- The project set up and running (`docs/guides/getting-started.md`), with the **model
  provider and the Wazuh/TheHive connections configured in the dashboard** — the load and
  run stages resolve those from `ProviderConfig`.
- **`elasticdump`** on PATH for the Wazuh load: `npm install -g elasticdump`.
- Network access for `acquire` (downloads from Zenodo).
- Run everything from the project root with the venv active and `PYTHONPATH=.`.

### Stages

Each stage is a subcommand of `python -m benchmark`; `all` chains preprocess → report.

```bash
# 1. one-time data preparation (per scenario)
python -m benchmark acquire                       # download the dataset -> data/raw/
python -m benchmark preprocess     --scenario fox # -> data/preprocessed/
python -m benchmark load-wazuh      --scenario fox # elasticdump into Wazuh
python -m benchmark load-thehive    --scenario fox # create TheHive alerts (tagged, teardownable)

# 2. run the agents and measure (repeatable)
python -m benchmark run    --scenario fox         # N trials per entry point -> data/runs/
python -m benchmark report --scenario fox         # score + aggregate -> data/results/fox.{json,md}
```

Common flags: `--scenario <name>`, `--entry-point <id>` (default: all of the scenario's
entry points), `--trials <N>` (default from `config/run.yaml`). Trial count, agent, metric
selection, and caps live in `config/run.yaml`.

### Quick smoke (one trial, one entry point)

```bash
python -m benchmark run    --scenario fox --entry-point recon --trials 1
python -m benchmark report --scenario fox
```

### Re-scoring without re-running

`score`/`report` read the stored runs under `data/runs/`, so after adding or changing a
metric you can re-grade existing runs without spending agent time:

```bash
python -m benchmark report --scenario fox
```

### Teardown

Imports are tagged for clean removal. TheHive alerts: `load_thehive.teardown(tag)` (the tag
is in each `data/manifests/thehive_manifest.<run_id>.json`). Wazuh data:
`load_wazuh.teardown(base_url)` drops the dated benchmark indices (`wazuh-alerts-4.x-2022-*`).

### Output

`data/results/<scenario>.md` is the human-readable roll-up (per-phase hit-rate over trials
per entry point); `<scenario>.json` is the machine-readable aggregate; `<scenario>.csv`
is a pandas-friendly flat metric table across all trials. Per-trial artifacts
(`report.md`, `verdict.json`, `scorecard.json`) live under `data/runs/<scenario>/<entry>/<trial>/`.
Each `scorecard.json` keeps the nested `results` metric contract and also includes `rows`,
a flat representation with columns such as `scenario`, `entry_point`, `trial`, `metric`,
`kind`, `key`, `value`, and `detail_*`.

## Adding a metric

1. Drop `scoring/metrics/<name>.py` with a `@register` `Metric` subclass (see
   `phase_recall.py` as the reference).
2. Optionally add it to `config/run.yaml: metrics` (default `all`).
3. Add `tests/unit/benchmark/test_<name>.py`.

`score.py`, `aggregate.py`, `report.py`, and every other metric are untouched. A
judge-based metric sets `needs_judge = True` and reads `ctx.judge`.

## Adding a scenario

Drop `config/scenarios/<name>.yaml` (phases copied from `fixtures/labels.csv`, entry
points tagged `organic` vs `synthetic`). No code changes — `ScoringContext` loads it
uniformly. The 8 AIT scenarios are `fox, harrison, russellmitchell, santos, shaw,
wardbeck, wilson, wheeler`.

## Metrics (current + planned)

- **phase_recall** *(implemented)* — of the labelled phases, how many the report
  reaches (cited marker event or a timestamp inside the phase window). The primary
  outcome metric.
- verdict_correctness, citation_validity, confident_false_negative, cost_to_verdict,
  rubric *(planned)* — see the metric discussion; each is one file in `metrics/`.

## Status

All pipeline stages are implemented. `preprocess` and `load_thehive` wrap the vendored,
proven AIT scripts (`pipeline/_vendor/`); `load_thehive` applies the corrected admission
rule (`rule.level ≥ N OR non-training anomaly`), which is what surfaces the low-severity
attack phases (webshell / privesc / service_stop) the original level-only filter dropped.
`runner` uses `run_agent_sync` (the same dispatch the REST API uses). The scoring half
(`score`/`report`/`phase_recall`) is offline unit-tested; the data/load/run stages need
the live services and can't be exercised offline.

Two notes carried over: elasticdump preserves the file's `_id` (which the agent cites) and
preprocess randomizes it, so deterministic ground-truth event markers are a *preprocess*
concern — `phase_recall` otherwise matches on timestamp windows. And `acquire`'s Zenodo
record id in `config/datasets.yaml` should be verified against the release you use.
