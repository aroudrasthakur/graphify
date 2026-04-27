from __future__ import annotations

from pathlib import Path

import pytest

from depos.analysis.fragments import HardCollision, MergeReport
from depos.analysis.schemas import TaintEdge
from depos.cache import (
    EXTRACTOR_CONFIG_HASH_FIELDS,
    FragmentCache,
    build_enrichment_fragment_cache_key,
    build_extraction_cache_key,
    build_semantic_function_cache_key,
    cache_allowed,
    extractor_config_hash,
    file_content_hash,
    sort_taint_edges,
)


def test_file_content_hash_changes_with_file_bytes(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("print('one')\n", encoding="utf-8")
    before = file_content_hash(source)
    source.write_text("print('two')\n", encoding="utf-8")
    assert file_content_hash(source) != before


def test_extractor_config_hash_uses_named_fields_only() -> None:
    assert "tree_sitter_parser_version" in EXTRACTOR_CONFIG_HASH_FIELDS
    base = {
        "ignore": ["node_modules"],
        "language_allowlist": ["python"],
        "tree_sitter_parser_version": "0.23",
        "unrelated_runtime_toggle": "a",
    }
    same_shape = {**base, "unrelated_runtime_toggle": "b"}
    changed_shape = {**base, "language_allowlist": ["python", "typescript"]}

    assert extractor_config_hash(base) == extractor_config_hash(same_shape)
    assert extractor_config_hash(base) != extractor_config_hash(changed_shape)


def test_enrichment_cache_key_changes_on_logic_version_bump() -> None:
    v1 = build_enrichment_fragment_cache_key(
        stage="emit_http_calls_route",
        source_file="app.py",
        file_hash="abc",
        language="python",
        enricher_logic_version="v1",
    )
    v2 = build_enrichment_fragment_cache_key(
        stage="emit_http_calls_route",
        source_file="app.py",
        file_hash="abc",
        language="python",
        enricher_logic_version="v2",
    )
    assert str(v1) != str(v2)


def test_extraction_cache_key_changes_on_parser_version_bump() -> None:
    cfg_hash = extractor_config_hash({"language_allowlist": ["python"]})
    old = build_extraction_cache_key(
        stage="extract",
        source_file="app.py",
        file_hash="abc",
        language="python",
        parser_version="tree-sitter-python-0.23",
        extractor_config_hash_value=cfg_hash,
    )
    new = build_extraction_cache_key(
        stage="extract",
        source_file="app.py",
        file_hash="abc",
        language="python",
        parser_version="tree-sitter-python-0.24",
        extractor_config_hash_value=cfg_hash,
    )
    assert str(old) != str(new)


def test_semantic_function_cache_key_includes_function_source_hash() -> None:
    first = build_semantic_function_cache_key(
        function_id="fn",
        source_file="app.py",
        function_source_hash="h1",
        language="python",
        version_tuple=("cfg-v1", "dfg-v1", "taint-v1"),
    )
    second = build_semantic_function_cache_key(
        function_id="fn",
        source_file="app.py",
        function_source_hash="h2",
        language="python",
        version_tuple=("cfg-v1", "dfg-v1", "taint-v1"),
    )
    assert str(first) != str(second)


def test_zero_error_gate_rejects_failed_merge_report() -> None:
    report = MergeReport()
    report.hard_collisions.append(
        HardCollision(
            entity_id="node:a",
            key="type",
            old_value="function",
            new_value="class",
            stage="enrich",
            source_file="app.py",
        )
    )
    assert not cache_allowed(merge_report=report)
    assert not cache_allowed(errors=[{"probe": "emit_env_edges", "message": "boom"}])
    assert not cache_allowed(errors=[{}])
    assert cache_allowed(merge_report=MergeReport(), errors=[])


def test_sort_taint_edges_is_deterministic() -> None:
    rows = [
        {"scope": "b", "source_node": "src2", "sink_node": "sink1", "line": 3},
        {"scope": "a", "source_node": "src1", "sink_node": "sink2", "line": 2},
        {"scope": "a", "source_node": "src1", "sink_node": "sink1", "line": 1},
    ]
    assert sort_taint_edges(reversed(rows)) == [
        {"scope": "a", "source_node": "src1", "sink_node": "sink1", "line": 1},
        {"scope": "a", "source_node": "src1", "sink_node": "sink2", "line": 2},
        {"scope": "b", "source_node": "src2", "sink_node": "sink1", "line": 3},
    ]


def test_fragment_cache_disabled_is_noop(tmp_path: Path) -> None:
    key = build_enrichment_fragment_cache_key(
        stage="emit_env_edges",
        source_file="app.py",
        file_hash="abc",
        language="python",
        enricher_logic_version="v1",
    )
    cache = FragmentCache(tmp_path / "cache", enabled=False)
    assert cache.get(key) is None
    assert cache.put(key, {"nodes": [], "edges": []}) is False
    assert cache.get(key) is None
    cache.clear()


def test_fragment_cache_roundtrip_when_diskcache_available(tmp_path: Path) -> None:
    pytest.importorskip("diskcache")
    key = build_enrichment_fragment_cache_key(
        stage="emit_env_edges",
        source_file="app.py",
        file_hash="abc",
        language="python",
        enricher_logic_version="v1",
    )
    payload = {"nodes": [{"id": "n"}], "edges": []}
    cache = FragmentCache(tmp_path / "cache", enabled=True)
    try:
        assert cache.put(key, payload) is True
        assert cache.get(key) == payload
    finally:
        cache.close()


def test_fragment_cache_skips_failed_merge_report_when_diskcache_available(tmp_path: Path) -> None:
    pytest.importorskip("diskcache")
    key = build_enrichment_fragment_cache_key(
        stage="emit_env_edges",
        source_file="app.py",
        file_hash="abc",
        language="python",
        enricher_logic_version="v1",
    )
    report = MergeReport()
    report.hard_collisions.append(
        HardCollision(
            entity_id="node:a",
            key="label",
            old_value="old",
            new_value="new",
            stage="enrich",
            source_file="app.py",
        )
    )
    cache = FragmentCache(tmp_path / "cache", enabled=True)
    try:
        assert cache.put(key, {"bad": True}, merge_report=report) is False
        assert cache.get(key) is None
    finally:
        cache.close()


def test_fragment_cache_put_taint_edges_serializes_models_when_diskcache_available(tmp_path: Path) -> None:
    pytest.importorskip("diskcache")
    key = build_semantic_function_cache_key(
        function_id="fn",
        source_file="app.py",
        function_source_hash="abc",
        language="python",
        version_tuple=("taint-v1",),
    )
    rows = [
        TaintEdge(
            source_node="src:b",
            sink_node="sink:b",
            intermediate_path=["src:b", "sink:b"],
            scope="b",
            line=2,
        ),
        TaintEdge(
            source_node="src:a",
            sink_node="sink:a",
            intermediate_path=["src:a", "sink:a"],
            scope="a",
            line=1,
        ),
    ]
    cache = FragmentCache(tmp_path / "cache", enabled=True)
    try:
        assert cache.put_taint_edges(key, rows) is True
        assert cache.get(key) == [
            {
                "source_node": "src:a",
                "sink_node": "sink:a",
                "intermediate_path": ["src:a", "sink:a"],
                "crosses_seam": False,
                "seam_edges_crossed": [],
                "source_chain": "",
                "sink_pattern": "",
                "source_hints": [],
                "scope": "a",
                "line": 1,
            },
            {
                "source_node": "src:b",
                "sink_node": "sink:b",
                "intermediate_path": ["src:b", "sink:b"],
                "crosses_seam": False,
                "seam_edges_crossed": [],
                "source_chain": "",
                "sink_pattern": "",
                "source_hints": [],
                "scope": "b",
                "line": 2,
            },
        ]
    finally:
        cache.close()
