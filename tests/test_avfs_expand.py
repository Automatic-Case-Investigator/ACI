"""Quick unit test for _expand_tilde_args — no server needed."""
import sys, os
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci_backend.settings")
backend_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, backend_root)
import django; django.setup()

from agent.runtime.graph import _expand_tilde_args
from agent.runtime.avfs import home_dir

def main():
    home = home_dir()
    print(f"home_dir() = {home!r}")

    cases = [
        ({"path": "~/cases/~123/evidence/foo.json"}, f"{home}/cases/~123/evidence/foo.json"),
        ({"path_prefix": "~/memory", "query": "crontab"}, f"{home}/memory"),
        ({"path": "/already/absolute"}, "/already/absolute"),
        ({"path": "~"}, home),
        ({"content": "some text", "path": "~/findings/f.md"}, f"{home}/findings/f.md"),
    ]

    all_pass = True
    for args, expected_path_or_prefix in cases:
        result = _expand_tilde_args(args)
        key = "path" if "path" in args else "path_prefix" if "path_prefix" in args else None
        got = result.get(key) if key else None
        ok = got == expected_path_or_prefix if key else True
        status = "PASS" if ok else "FAIL"
        if not ok:
            all_pass = False
        print(f"  {status}  {args}  →  {result}")

    print(f"\n{'ALL PASS' if all_pass else 'FAILURES DETECTED'}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
