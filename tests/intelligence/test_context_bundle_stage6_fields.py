from __future__ import annotations

import networkx as nx

from depos.analysis.candidate_identifier import resolve_change_manifest
from depos.analysis.config import IntelligenceConfig
from depos.analysis.context_bundle import build_bundle
from depos.analysis.run_context import build_run_context
from depos.analysis.schemas import AnalysisMode, Candidate, PackManifest, SeedType, ContextBundle


def test_context_bundle_schema_exposes_stage6_fields() -> None:
    bundle = ContextBundle(
        bundle_id="b1",
        candidate_id="c1",
        scope_id="node:scope",
        pack_manifest=PackManifest(manifest_id="m1"),
    )
    assert hasattr(bundle, "scope_text")
    assert hasattr(bundle, "scope_language")
    assert hasattr(bundle, "callers")
    assert hasattr(bundle, "callees")
    assert hasattr(bundle, "caller_texts")
    assert hasattr(bundle, "callee_texts")
    assert hasattr(bundle, "seam_edges")
    assert hasattr(bundle, "seam_neighbor_texts")
    assert hasattr(bundle, "pagerank_percentile")
    assert hasattr(bundle, "scc_size")
    assert hasattr(bundle, "graph_distance_to_diff")
    assert hasattr(bundle, "cfg_summary")
    assert hasattr(bundle, "null_paths")


def test_build_bundle_populates_stage6_fields(tmp_path) -> None:
    (tmp_path / "scope.py").write_text(
        "\n".join(
            [
                "def scope(user):",
                "    if user is None:",
                "        return None",
                "    return user.profile.name",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "caller.py").write_text(
        "\n".join(
            [
                "def caller(user):",
                "    return scope(user)",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "callee.py").write_text(
        "\n".join(
            [
                "def callee(value):",
                "    return value",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "neighbor.ts").write_text(
        "\n".join(
            [
                "export function neighbor() {",
                "  return scopeClient!.value",
                "}",
                "",
            ]
        ),
        encoding="utf-8",
    )

    graph = nx.DiGraph()
    graph.add_node(
        "scope",
        language="python",
        source_file="scope.py",
        span={"start": {"line": 1}, "end": {"line": 4}},
        qualname="scope",
        entity_kind="function_definition",
        label="scope()",
        embedded_text="def scope(user):\n    if user is None:\n        return None\n    return user.profile.name",
    )
    graph.add_node(
        "caller",
        language="python",
        source_file="caller.py",
        span={"start": {"line": 1}, "end": {"line": 2}},
        qualname="caller",
        entity_kind="function_definition",
        label="caller()",
        embedded_text="def caller(user):\n    return scope(user)",
    )
    graph.add_node(
        "neighbor",
        language="javascript",
        source_file="neighbor.ts",
        span={"start": {"line": 1}, "end": {"line": 3}},
        entity_kind="function_declaration",
        label="neighbor()",
        embedded_text="export function neighbor() {\n  return scopeClient!.value\n}",
    )
    graph.add_node(
        "callee",
        language="python",
        source_file="callee.py",
        span={"start": {"line": 1}, "end": {"line": 2}},
        qualname="callee",
        entity_kind="function_definition",
        label="callee()",
        embedded_text="def callee(value):\n    return value",
    )

    graph.add_edge("caller", "scope", relation="CALLS")
    graph.add_edge("scope", "callee", relation="CALLS")
    graph.add_edge(
        "scope",
        "neighbor",
        relation="HTTP_CALL",
        source_system="python",
        target_system="javascript",
    )
    graph.add_edge(
        "neighbor",
        "scope",
        relation="HTTP_CALLBACK",
        source_system="javascript",
        target_system="python",
    )

    config = IntelligenceConfig()
    manifest = resolve_change_manifest(graph, diff_path=None, manual_manifest=None, repo_root=tmp_path)
    run_context = build_run_context(graph, manifest, repo_root=tmp_path, config=config)
    candidate = Candidate(
        candidate_id="cand1",
        scope_id="node:scope",
        seed_type=SeedType.diff_anchor,
        diff_anchors=["caller"],
        analysis_mode=AnalysisMode.full_repo_scan,
    )

    bundle = build_bundle(
        graph,
        candidate,
        config=config,
        source_roots=[tmp_path],
        run_context=run_context,
    )

    assert "return user.profile.name" in bundle.scope_text
    assert bundle.scope_language == "python"
    assert bundle.callers == ["caller"]
    assert "return scope(user)" in bundle.caller_texts["caller"]
    assert bundle.callees == ["callee"]
    assert "return value" in bundle.callee_texts["callee"]
    assert bundle.seam_edges
    assert "scopeClient!.value" in bundle.seam_neighbor_texts["neighbor"]
    assert bundle.is_articulation_point is True
    assert bundle.pagerank_percentile > 0.0
    assert bundle.scc_size >= 1
    assert bundle.on_cross_lang_cycle is True
    assert bundle.graph_distance_to_diff == 1
    assert bundle.cfg_available is True
    assert bundle.cfg_summary is not None
    assert isinstance(bundle.null_paths, list)
