from __future__ import annotations

import networkx as nx

from depos.analysis.fragments import merge_fragments
from depos.enrichment.deps_resolver import emit_dependency_edges


def test_emit_dependency_edges_creates_phantom_package_dep() -> None:
    g = nx.DiGraph()
    g.add_node(
        "code:main",
        node_kind="python_module",
        source_file="app/main.py",
        label="import requests",
        import_name="requests",
    )
    frag = emit_dependency_edges(g, repo_root=None)
    merge_fragments(g, [frag])

    phantom_id = "pkg::phantom:requests"
    assert phantom_id in g
    assert g.nodes[phantom_id].get("declared") is False
    assert g.nodes[phantom_id].get("node_kind") == "package_dep"
    assert g.has_edge("code:main", phantom_id)
    assert g.edges["code:main", phantom_id].get("relation") == "IMPORTS_PACKAGE"


def test_emit_dependency_edges_links_to_declared_dep() -> None:
    g = nx.DiGraph()
    g.add_node(
        "pkg::dep:requirements.txt::requests",
        node_kind="package_dep",
        package_name="requests",
        declared=True,
        lockfile_drift=False,
    )
    g.add_node(
        "code:main",
        node_kind="python_module",
        source_file="app/main.py",
        import_name="requests",
    )
    frag = emit_dependency_edges(g, repo_root=None)
    merge_fragments(g, [frag])

    assert "pkg::phantom:requests" not in g
    assert g.has_edge("code:main", "pkg::dep:requirements.txt::requests")
