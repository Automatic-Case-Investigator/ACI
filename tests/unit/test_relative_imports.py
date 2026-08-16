"""Every relative import under `agent/` must resolve to a real module.

Deferred (in-body) imports are the reason this exists. A module-level import with a
wrong dot count explodes the moment anything imports the file, so the suite catches
it. An in-body one does not run until its function is called — and when the call site
wraps it in `try/except` and emits a warning, as the query-memo hook does, a broken
import degrades the agent silently and forever.

That is not hypothetical: splitting `nodes_loop.py` into `nodes_loop/` bumped the
module-level imports by one dot and left four in-body ones behind, so
`agent.runtime.graph.analysis.query_memo` was looked up on every tool call and every
broad-query and schema memo was lost. The suite stayed green throughout.
"""

from __future__ import annotations

import ast
import io
import os
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PACKAGE = "agent"


def _unresolvable() -> list[str]:
    problems: list[str] = []
    root_dir = os.path.join(PROJECT_ROOT, PACKAGE)
    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for name in files:
            if not name.endswith(".py") or name.startswith("._"):
                continue
            path = os.path.join(root, name)
            rel = os.path.relpath(root, PROJECT_ROOT).replace(os.sep, "/")
            try:
                tree = ast.parse(io.open(path, encoding="utf-8").read())
            except SyntaxError:  # not our concern here
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.ImportFrom) or not node.level:
                    continue
                base = rel.split("/")
                up = node.level - 1
                if up > len(base):
                    problems.append(f"{path}:{node.lineno} escapes the tree")
                    continue
                if up:
                    base = base[:-up]
                target = base + ((node.module or "").split(".") if node.module else [])
                candidate = os.path.join(PROJECT_ROOT, *target)
                if os.path.isdir(candidate) or os.path.isfile(candidate + ".py"):
                    continue
                dotted = "." * node.level + (node.module or "")
                problems.append(f"{path}:{node.lineno} -> {dotted}")
    return problems


class RelativeImportResolutionTest(unittest.TestCase):
    def test_every_relative_import_resolves(self):
        problems = _unresolvable()
        self.assertEqual(
            problems,
            [],
            "Unresolvable relative import(s) — check the dot count, and remember that "
            "in-body imports need the same adjustment as module-level ones when a "
            "module moves:\n  " + "\n  ".join(problems),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
