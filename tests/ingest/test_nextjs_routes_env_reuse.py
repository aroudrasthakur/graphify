"""Next.js route ingest should link READS_ENV_VAR to .env-defined nodes, not duplicate stubs."""

from __future__ import annotations

import networkx as nx

from depos.analysis.config import IntelligenceConfig
from depos.ingest import ingest_all


def test_nextjs_route_reuses_env_var_from_dotenv_example(tmp_path) -> None:
    (tmp_path / ".env.example").write_text(
        "NEXT_PUBLIC_FROM_DOTENV=1\n",
        encoding="utf-8",
    )
    app = tmp_path / "apps" / "web" / "app" / "demo"
    app.mkdir(parents=True)
    (app / "page.tsx").write_text(
        'export default function Page() {\n'
        '  return <div>{process.env.NEXT_PUBLIC_FROM_DOTENV}</div>;\n'
        "}\n",
        encoding="utf-8",
    )
    graph = nx.DiGraph()
    ingest_all(graph, repo_root=tmp_path, config=IntelligenceConfig())

    undefined = [
        n
        for n, a in graph.nodes(data=True)
        if a.get("node_kind") == "env_var"
        and a.get("name") == "NEXT_PUBLIC_FROM_DOTENV"
        and not a.get("defined")
    ]
    assert not undefined

    defined_ids = [
        n
        for n, a in graph.nodes(data=True)
        if a.get("node_kind") == "env_var"
        and a.get("name") == "NEXT_PUBLIC_FROM_DOTENV"
        and a.get("defined")
    ]
    assert len(defined_ids) == 1
