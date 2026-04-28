"""Add semantic_requirement=None to simple_spec calls that lack it."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path("depos/analysis/detectors/builtin")
# Last line of simple_spec in single-block files is `severity="...",`
PAT = re.compile(
    r"(\n\s*severity=\"[^\"]+\",)\n(\)\n)",
    re.MULTILINE,
)

def main() -> None:
    for path in sorted(ROOT.rglob("*.py")):
        if path.name in {"common.py", "group_b_cfg_detectors.py", "group_c_taint_dfg_detectors.py"}:
            continue
        t = path.read_text(encoding="utf-8")
        if "simple_spec" not in t or "semantic_requirement" in t:
            continue
        if "group_a" in str(path) or "group_b" in str(path) or "group_c" in str(path):
            continue
        t2, n = PAT.subn(r"\1\n    semantic_requirement=None,\2", t, count=1)
        if n:
            path.write_text(t2, encoding="utf-8")
            print("patched", path)
        else:
            print("SKIP", path)


if __name__ == "__main__":
    main()
