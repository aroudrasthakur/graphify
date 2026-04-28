from __future__ import annotations

from pathlib import Path

import pytest

from depos.ingest.parallel_extract import extract_parallel, extract_paths_parallel
from depos.snapshot import build_graph_for_root
from graphify.extract import extract


def _graph_signature(graph) -> tuple:
    nodes = tuple(
        sorted(
            (str(node_id), tuple(sorted(attrs.items())))
            for node_id, attrs in graph.nodes(data=True)
        )
    )
    edges = tuple(
        sorted(
            (str(source), str(target), tuple(sorted(attrs.items())))
            for source, target, attrs in graph.edges(data=True)
        )
    )
    return nodes, edges


def test_parallel_extract_n_jobs_1_matches_snapshot_graph(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "from b import helper\n\n"
        "class Runner:\n"
        "    def run(self):\n"
        "        return helper()\n",
        encoding="utf-8",
    )
    (tmp_path / "b.py").write_text(
        "def helper():\n"
        "    return 1\n",
        encoding="utf-8",
    )

    _, expected = build_graph_for_root(tmp_path, directed=True)
    actual = extract_parallel(tmp_path, n_jobs=1, cache=True, directed=True)

    assert _graph_signature(actual) == _graph_signature(expected)


def test_extract_paths_parallel_n_jobs_1_matches_graphify_extract(tmp_path: Path) -> None:
    paths = [tmp_path / "a.py", tmp_path / "b.py"]
    paths[0].write_text("from b import helper\n\ndef run():\n    return helper()\n", encoding="utf-8")
    paths[1].write_text("def helper():\n    return 1\n", encoding="utf-8")

    expected = extract(paths, cache_root=tmp_path)
    actual = extract_paths_parallel(paths, n_jobs=1, cache=True, cache_root=tmp_path)

    assert actual == expected


def test_extract_paths_parallel_n_jobs_2_matches_serial_when_joblib_available(tmp_path: Path) -> None:
    pytest.importorskip("joblib")
    paths = [tmp_path / "a.py", tmp_path / "b.py"]
    paths[0].write_text("from b import helper\n\ndef run():\n    return helper()\n", encoding="utf-8")
    paths[1].write_text("def helper():\n    return 1\n", encoding="utf-8")

    expected = extract_paths_parallel(paths, n_jobs=1, cache=False, cache_root=tmp_path)
    actual = extract_paths_parallel(paths, n_jobs=2, cache=False, cache_root=tmp_path)

    assert actual == expected
