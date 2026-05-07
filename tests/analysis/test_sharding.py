from __future__ import annotations

import networkx as nx

from depos.analysis.sharding import detection_nodes_package_manifest_workspaces, subgraph_for_shard_strategy


def test_package_manifest_sharding_includes_workspace_sources() -> None:
    g = nx.DiGraph()
    g.add_node(
        "pkg::manifest:svc/package.json",
        node_kind="package_manifest",
        manifest_id="pkg::manifest:svc/package.json",
        source_file="svc/package.json",
    )
    g.add_node("code:api", node_kind="python_module", source_file="svc/src/api.py")
    g.add_node("other:app", node_kind="python_module", source_file="other/main.py")

    members = detection_nodes_package_manifest_workspaces(g)
    assert members is not None
    assert "pkg::manifest:svc/package.json" in members
    assert "code:api" in members
    assert "other:app" not in members

    sub = subgraph_for_shard_strategy(g, "package_manifest")
    assert sub.number_of_nodes() == 2


def test_subgraph_none_strategy_returns_same_graph() -> None:
    g = nx.DiGraph()
    g.add_node("a")
    assert subgraph_for_shard_strategy(g, None) is g
    assert subgraph_for_shard_strategy(g, "none") is g
