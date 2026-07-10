"""Benchmark CLI: `python -m benchmark <stage> [--scenario fox] [...]`.

Stages map to benchmark/pipeline modules; `all` chains preprocess -> load -> run ->
score -> report. Connections for the load stages resolve from the dashboard
`ProviderConfig` unless overridden. Each stage is also importable and callable directly.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parent
_CONFIG = _ROOT / "config"
_DATA = _ROOT / "data"


def _progress_enabled(args):
    return False if args.no_progress else True


def _load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _run_cfg() -> dict:
    return _load_yaml(_CONFIG / "run.yaml")


def _wazuh_output_url() -> str:
    import os

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
    import django

    django.setup()
    from agent.models.config import ProviderConfig

    s = ProviderConfig.objects.get(key="aci-wazuh").settings
    scheme, _, host = s["url"].partition("://")
    return f"{scheme}://{s['user']}:{s['password']}@{host}"


def _cmd_acquire(args):
    from .pipeline import acquire

    print(acquire.run(_load_yaml(_CONFIG / "datasets.yaml"), _DATA / "raw"))


def _cmd_preprocess(args):
    from .pipeline import preprocess

    print(preprocess.run(args.scenario, _DATA / "raw", _DATA / "preprocessed"))


def _cmd_load_wazuh(args):
    from .pipeline import load_wazuh

    url = args.output_url or _wazuh_output_url()
    print(load_wazuh.run(args.scenario, _DATA / "preprocessed", url, progress=_progress_enabled(args)))


def _cmd_load_thehive(args):
    from .pipeline import load_thehive

    print(
        load_thehive.run(
            args.scenario,
            _DATA / "preprocessed",
            min_level=args.min_level,
            manifest_dir=_DATA / "manifests",
            progress=_progress_enabled(args),
            workers=args.concurrency or 32,
        )
    )


def _cmd_run(args):
    from .pipeline import runner
    from .scoring import ScenarioSpec
    from .pipeline.score import scenario_spec_path

    cfg = _run_cfg()
    spec = ScenarioSpec.from_yaml(scenario_spec_path(args.scenario))
    entry_ids = [args.entry_point] if args.entry_point else [e.id for e in spec.entry_points]
    trials = args.trials or cfg["trials"]
    agent_name = cfg.get("agent", "investigation")
    concurrency = max(1, args.concurrency or cfg.get("run_concurrency") or 1)
    logger = None if args.quiet else runner.stderr_logger
    if logger:
        logger(
            f"run scenario={args.scenario} entry_points={entry_ids} trials={trials} "
            f"agent={agent_name} concurrency={concurrency}"
        )
    results = runner.run_many(
        args.scenario,
        entry_ids,
        trials,
        _DATA / "runs",
        agent_name=agent_name,
        log=logger,
        timeout_secs=cfg.get("poll_timeout_secs"),
        concurrency=concurrency,
    )
    for ep in entry_ids:
        print(f"{ep}: {len(results.get(ep, []))} runs")


def _cmd_score(args):
    from .pipeline import score

    cards = score.run(_DATA / "runs", args.scenario, _run_cfg().get("metrics", "all"))
    print(f"scored {len(cards)} trials")


def _cmd_report(args):
    from .pipeline import score, report

    cards = score.run(_DATA / "runs", args.scenario, _run_cfg().get("metrics", "all"))
    report.run(cards, _DATA / "results")
    print(f"wrote {_DATA / 'results' / (args.scenario + '.md')}")


def _cmd_all(args):
    _cmd_preprocess(args)
    _cmd_load_wazuh(args)
    _cmd_load_thehive(args)
    _cmd_run(args)
    _cmd_report(args)


def _thehive_tags_for_scenario(scenario: str) -> list[tuple[str, Path]]:
    """Every (run tag, manifest path) recorded in data/manifests/ for this scenario
    (there may be several, if load-thehive was run more than once while iterating).
    Returning the manifest path lets teardown use its stored alert ids and skip the
    slow paged tag-discovery query."""
    import json

    manifest_dir = _DATA / "manifests"
    out: list[tuple[str, Path]] = []
    for path in sorted(manifest_dir.glob("thehive_manifest.*.json")):
        m = json.loads(path.read_text(encoding="utf-8"))
        if m.get("scenario") == scenario and m.get("tag"):
            out.append((m["tag"], path))
    return out


def _thehive_manifest_for_run(run_id: str) -> Path:
    manifest_dir = _DATA / "manifests"
    normalized = run_id.removeprefix("ait-import-run:")
    return manifest_dir / f"thehive_manifest.{normalized}.json"


def _cmd_teardown(args):
    target = args.target or "all"

    if target in ("wazuh", "all"):
        from .pipeline import load_wazuh

        url = args.output_url or _wazuh_output_url()
        result = load_wazuh.teardown(url, args.scenario, progress=_progress_enabled(args))
        print("wazuh:", result)

    if target in ("thehive", "all"):
        from .pipeline import load_thehive

        # (tag, manifest_path) pairs — from --run-id, or every manifest for the scenario.
        if args.run_id:
            targets = [(args.run_id, _thehive_manifest_for_run(args.run_id))]
        else:
            targets = _thehive_tags_for_scenario(args.scenario)
        if not targets:
            print(f"thehive: no manifests found for scenario {args.scenario!r} "
                  f"under {_DATA / 'manifests'}; pass --run-id to tear down a specific tag")
        for tag, manifest in targets:
            deleted = load_thehive.teardown(
                tag,
                manifest_path=manifest,
                progress=_progress_enabled(args),
                workers=args.concurrency or 32,
            )
            print(f"thehive: deleted {deleted} alerts for tag {tag!r}")


_COMMANDS = {
    "acquire": _cmd_acquire,
    "preprocess": _cmd_preprocess,
    "load-wazuh": _cmd_load_wazuh,
    "load-thehive": _cmd_load_thehive,
    "run": _cmd_run,
    "score": _cmd_score,
    "report": _cmd_report,
    "all": _cmd_all,
    "teardown": _cmd_teardown,
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="benchmark", description=__doc__)
    sub = p.add_subparsers(dest="stage", required=True)
    for stage in _COMMANDS:
        s = sub.add_parser(stage)
        s.add_argument("--scenario", default="fox")
        s.add_argument("--entry-point", default=None)
        s.add_argument("--trials", type=int, default=None)
        s.add_argument("--min-level", type=int, default=7)
        s.add_argument("--output-url", default=None)
        s.add_argument("--target", choices=["wazuh", "thehive", "all"], default=None,
                        help="teardown only: which system to tear down (default: all)")
        s.add_argument("--run-id", default=None,
                        help="teardown only: a specific TheHive run tag/id "
                             "(default: every manifest recorded for --scenario)")
        s.add_argument("--no-progress", action="store_true",
                        help="disable interactive benchmark progress bars")
        s.add_argument("--concurrency", type=int, default=None,
                        help="worker count for concurrent runs or TheHive import/teardown")
        s.add_argument("--quiet", action="store_true",
                        help="suppress benchmark status logging")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _COMMANDS[args.stage](args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
