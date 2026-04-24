"""Every registered detector must declare semantic_requirement explicitly (Block 9)."""
from __future__ import annotations

from depos.analysis.detectors import REGISTRY, load_builtin


def test_all_detectors_have_explicit_semantic_requirement() -> None:
    load_builtin()
    for name, (spec, _) in REGISTRY.items():
        r = spec.semantic_requirement
        assert r is None or r in ("cfg", "dfg", "taint"), f"{name}: {r!r}"
