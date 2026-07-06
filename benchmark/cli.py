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
    print(load_wazuh.run(args.scenario, _DATA / "preprocessed", url))


def _cmd_load_thehive(args):
    from .pipeline import load_thehive

    print(
        load_thehive.run(
            args.scenario,
            _DATA / "preprocessed",
            min_level=args.min_level,
            manifest_dir=_DATA / "manifests",
        )
    )


def _cmd_run(args):
    from .pipeline import runner
    from .scoring import ScenarioSpec
    from .pipeline.score import scenario_spec_path

    cfg = _run_cfg()
    spec = ScenarioSpec.from_yaml(scenario_spec_path(args.scenario))
    entry_ids = [args.entry_point] if args.entry_point else [e.id for e in spec.entry_points]
    for ep in entry_ids:
        ids = runner.run(args.scenario, ep, args.trials or cfg["trials"], _DATA / "runs", agent_name=cfg.get("agent", "investigation"))
        print(f"{ep}: {len(ids)} runs")


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


_COMMANDS = {
    "acquire": _cmd_acquire,
    "preprocess": _cmd_preprocess,
    "load-wazuh": _cmd_load_wazuh,
    "load-thehive": _cmd_load_thehive,
    "run": _cmd_run,
    "score": _cmd_score,
    "report": _cmd_report,
    "all": _cmd_all,
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
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _COMMANDS[args.stage](args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
