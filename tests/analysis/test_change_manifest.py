"""Change manifest: unified diff hunks and hunk-aware node attachment."""
from __future__ import annotations

import networkx as nx

from depos.analysis.candidate_identifier import (
    _attach_graph_nodes,
    _parse_unified_diff_to_manifest,
    resolve_change_manifest,
)
from depos.analysis.schemas import ChangeManifest, ChangeManifestEntry, DiffHunkSpan


def test_parse_unified_diff_collects_touched_lines() -> None:
    diff = """diff --git a/foo.py b/foo.py
--- a/foo.py
+++ b/foo.py
@@ -1,3 +1,4 @@
 line1
+new
 line2
"""
    m = _parse_unified_diff_to_manifest(diff)
    assert m is not None
    assert m.resolved_via == "git_unified"
    assert len(m.entries) == 1
    assert m.entries[0].path == "foo.py"
    hs = {(h.start_line, h.end_line) for h in m.entries[0].hunks}
    assert (2, 2) in hs


def test_attach_graph_nodes_filters_by_hunks() -> None:
    g = nx.DiGraph()
    g.add_node(
        "a",
        source_file="/work/foo.py",
        start_line=1,
        end_line=5,
    )
    g.add_node(
        "b",
        source_file="/work/foo.py",
        start_line=40,
        end_line=50,
    )
    manifest = ChangeManifest(
        entries=[
            ChangeManifestEntry(
                path="foo.py",
                node_ids=[],
                file_change=True,
                hunks=[DiffHunkSpan(start_line=1, end_line=6)],
            )
        ],
        resolved_via="git_unified",
    )
    out = _attach_graph_nodes(g, manifest)
    assert "a" in out.entries[0].node_ids
    assert "b" not in out.entries[0].node_ids


def test_resolve_change_manifest_manual_preserves_hunks() -> None:
    g = nx.DiGraph()
    manual = {
        "entries": [
            {
                "path": "x.py",
                "node_ids": [],
                "file_change": True,
                "hunks": [{"start_line": 10, "end_line": 12}],
            }
        ]
    }
    m = resolve_change_manifest(g, manual_manifest=manual)
    assert m.entries[0].hunks[0].start_line == 10
