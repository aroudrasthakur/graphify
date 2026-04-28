"""Phase 7–10: graph indexes, perf config, parallel taint equivalence, cheap metrics."""
from __future__ import annotations

from pathlib import Path

import networkx as nx

from depos.analysis.config import PerfConfig
from depos.analysis.graph_indexes import build_graph_indexes
from depos.analysis.graph_metrics import compute_cheap_graph_metrics, compute_graph_metrics
from depos.analysis.run_context import build_run_context
from depos.diagnostics import map_diagnostics_to_nodes
from depos.models import DiagnosticCategory, DiagnosticRef


def _python_handler_graph(tmp_path) -> nx.DiGraph:
    (tmp_path / "handler.py").write_text(
        "\n".join(
            [
                "def handler():",
                "    import sqlite3",
                '    conn = sqlite3.connect(":memory:")',
                "    cur = conn.cursor()",
                '    cur.execute("select 1")',
                "",
            ]
        ),
        encoding="utf-8",
    )
    g = nx.DiGraph()
    g.add_node(
        "pyfn",
        language="python",
        source_file="handler.py",
        span={"start": {"line": 1}, "end": {"line": 20}},
        qualname="handler",
        entity_kind="function_definition",
        name="handler()",
    )
    return g


def test_build_run_context_populates_indexes(tmp_path) -> None:
    g = _python_handler_graph(tmp_path)
    ctx = build_run_context(g, manifest=None, repo_root=tmp_path)
    assert ctx.indexes is not None
    assert "pyfn" in ctx.indexes.node_by_id
    assert ctx.indexes.node_by_id["pyfn"]["qualname"] == "handler"


def test_graph_indexes_nodes_by_file_matches_scan(tmp_path) -> None:
    (tmp_path / "a.py").write_text("x=1\n", encoding="utf-8")
    g = nx.DiGraph()
    g.add_node("n1", source_file="a.py", label="n1")
    g.add_node("n2", source_file="subdir/a.py", label="n2")
    idx = build_graph_indexes(g)
    by_file: dict[str, list[str]] = {}
    for nid, data in g.nodes(data=True):
        sf = data.get("source_file") or ""
        if not sf:
            continue
        key = str(sf).replace("\\", "/").lstrip("./")
        k2 = str(Path(key).as_posix()).lstrip("./")
        by_file.setdefault(k2, []).append(str(nid))
    for k, v in by_file.items():
        by_file[k] = sorted(v)
    assert idx.nodes_by_file == by_file


def test_map_diagnostics_with_indexes_matches_scan(tmp_path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "x.py").write_text("def f():\n    pass\n", encoding="utf-8")
    g = nx.Graph()
    g.add_node(
        "node-a",
        source_file="src/x.py",
        source_location="L2",
        label="f",
    )
    idx = build_graph_indexes(g)
    uri = str((tmp_path / "src" / "x.py").resolve())
    d = DiagnosticRef(
        uri=uri,
        start_line=2,
        category=DiagnosticCategory.unknown,
        message="m",
    )
    m_full = map_diagnostics_to_nodes(g, [d], repo_root=tmp_path)
    m_idx = map_diagnostics_to_nodes(g, [d], repo_root=tmp_path, indexes=idx)
    assert m_full == m_idx


def test_taint_parallel_matches_serial(tmp_path) -> None:
    g1 = _python_handler_graph(tmp_path)
    build_run_context(g1, manifest=None, repo_root=tmp_path, perf=PerfConfig(taint_n_jobs=1))
    g2 = _python_handler_graph(tmp_path)
    build_run_context(g2, manifest=None, repo_root=tmp_path, perf=PerfConfig(taint_n_jobs=4))
    rows1 = [te.model_dump(mode="json") for te in g1.graph.get("taint_edges", [])]
    rows2 = [te.model_dump(mode="json") for te in g2.graph.get("taint_edges", [])]
    assert rows1 == rows2


def test_graph_indexes_callers_matches_edge_scan() -> None:
    g = nx.DiGraph()
    for nid in ("a", "b", "c"):
        g.add_node(nid, source_file="x.py")
    g.add_edge("a", "b", relation="CALLS")
    g.add_edge("b", "c", relation="imports")
    idx = build_graph_indexes(g)
    naive_callees: dict[str, list[str]] = {}
    for u, v, data in g.edges(data=True):
        rel = str(data.get("relation") or data.get("type") or "")
        if rel.casefold() != "calls":
            continue
        naive_callees.setdefault(str(u), []).append(str(v))
    for k, v in naive_callees.items():
        naive_callees[k] = sorted(set(v))
    assert idx.callees_by_caller == naive_callees
    naive_callers: dict[str, list[str]] = {}
    for u, v, data in g.edges(data=True):
        rel = str(data.get("relation") or data.get("type") or "")
        if rel.casefold() != "calls":
            continue
        naive_callers.setdefault(str(v), []).append(str(u))
    for k, v in naive_callers.items():
        naive_callers[k] = sorted(set(v))
    assert idx.callers_by_callee == naive_callers


def test_python_cfg_dfg_parallel_matches_serial(tmp_path) -> None:
    (tmp_path / "mod.py").write_text(
        "\n".join(
            [
                "def a():",
                "    x = 1",
                "    print(x)",
                "",
                "def b():",
                "    y = 2",
                "    print(y)",
                "",
            ]
        ),
        encoding="utf-8",
    )

    def make_graph() -> nx.DiGraph:
        g = nx.DiGraph()
        g.add_node(
            "fa",
            language="python",
            source_file="mod.py",
            span={"start": {"line": 1}, "end": {"line": 15}},
            qualname="a",
            entity_kind="function_definition",
            name="a()",
        )
        g.add_node(
            "fb",
            language="python",
            source_file="mod.py",
            span={"start": {"line": 5}, "end": {"line": 15}},
            qualname="b",
            entity_kind="function_definition",
            name="b()",
        )
        return g

    g1 = make_graph()
    build_run_context(
        g1,
        None,
        repo_root=tmp_path,
        perf=PerfConfig(cfg_dfg_n_jobs=1, taint_n_jobs=1),
    )
    g2 = make_graph()
    build_run_context(
        g2,
        None,
        repo_root=tmp_path,
        perf=PerfConfig(cfg_dfg_n_jobs=4, taint_n_jobs=1),
    )
    assert set(g1.nodes()) == set(g2.nodes())
    assert g1.number_of_edges() == g2.number_of_edges()
    for u, v, d in g1.edges(data=True):
        assert g2.has_edge(u, v)
        assert dict(g2.edges[u, v]) == dict(d)


def test_compute_graph_metrics_cheap_omits_betweenness() -> None:
    g = nx.DiGraph()
    g.add_node("a")
    g.add_node("b")
    g.add_edge("a", "b", relation="calls")
    cheap = compute_graph_metrics(g, expensive=False)
    cheap_alias = compute_cheap_graph_metrics(g)
    full = compute_graph_metrics(g, expensive=True)
    assert cheap.betweenness == {}
    assert cheap_alias.node_pagerank == cheap.node_pagerank
    assert full.betweenness
    assert cheap.cross_lang_cycles == []
    assert cheap.articulation_points == []
