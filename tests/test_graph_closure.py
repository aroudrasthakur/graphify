from __future__ import annotations

import ast
import pathlib


CLOSED_AFTER_STAGE_6 = [
    "depos/analysis/verifier.py",
    "depos/analysis/gray_zone_evaluator.py",
]


def test_no_graph_access_after_bundle() -> None:
    for rel_path in CLOSED_AFTER_STAGE_6:
        source = pathlib.Path(rel_path).read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                assert node.attr not in {
                    "nodes",
                    "edges",
                    "successors",
                    "predecessors",
                    "in_degree",
                    "out_degree",
                    "neighbors",
                }, f"{rel_path}:{node.lineno} — graph access after Stage 6 closure"
