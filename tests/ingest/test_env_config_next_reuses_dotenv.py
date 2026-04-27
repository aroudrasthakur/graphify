"""env_config should not create defined=False env_var duplicates for next.config."""

from __future__ import annotations

import networkx as nx

from depos.analysis.config import IntelligenceConfig
from depos.ingest.env_config import ingest


def test_next_config_reuses_env_var_defined_in_dotenv_example(tmp_path) -> None:
    (tmp_path / ".env.example").write_text(
        "NEXT_PUBLIC_FROM_EXAMPLE=1\n",
        encoding="utf-8",
    )
    web = tmp_path / "apps" / "web"
    web.mkdir(parents=True)
    (web / "next.config.js").write_text(
        "module.exports = { env: { "
        "X: process.env.NEXT_PUBLIC_FROM_EXAMPLE || '' } };\n",
        encoding="utf-8",
    )
    graph = nx.DiGraph()
    ingest(graph, repo_root=tmp_path, config=IntelligenceConfig())

    undefined = [
        n
        for n, a in graph.nodes(data=True)
        if a.get("node_kind") == "env_var"
        and a.get("name") == "NEXT_PUBLIC_FROM_EXAMPLE"
        and not a.get("defined")
    ]
    assert not undefined

    defined_nodes = [
        n
        for n, a in graph.nodes(data=True)
        if a.get("node_kind") == "env_var"
        and a.get("name") == "NEXT_PUBLIC_FROM_EXAMPLE"
        and a.get("defined")
    ]
    assert len(defined_nodes) == 1
