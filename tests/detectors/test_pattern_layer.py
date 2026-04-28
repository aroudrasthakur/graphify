from __future__ import annotations

import networkx as nx

from depos.analysis.config import IntelligenceConfig
from depos.analysis.detectors import run_all
from depos.analysis.detectors.pattern_formula import evaluate_formula
from depos.analysis.detectors.pattern_matcher import (
    PatternSourceCache,
    collect_pattern_scopes,
    evaluate_primitive,
    pattern_match_to_candidate,
    run_pattern_rule,
)
from depos.analysis.detectors.pattern_types import PatternRule
from depos.analysis.run_context import GraphMetrics, RunContext
from depos.analysis.schemas import AnalysisMode, Candidate, ChangeManifest


def _ctx(repo_root=None, *, cfg_available: dict[str, bool] | None = None) -> RunContext:
    metrics = GraphMetrics()
    metrics._computed = True
    return RunContext(
        manifest=ChangeManifest(),
        repo_root=repo_root,
        graph_metrics=metrics,
        cfg_available=dict(cfg_available or {}),
    )


def _rule(formula: dict, *, scope: str = "node", detector: str = "pattern-test") -> PatternRule:
    return PatternRule(
        id="pattern-test-rule",
        detector_name=detector,
        risk_category="TEST",
        severity="medium",
        scope=scope,
        message="test pattern",
        formula=formula,
    )


def test_source_regex_primitive_matches_file_scope(tmp_path) -> None:
    (tmp_path / "app.py").write_text("def f():\n    while True:\n        pass\n", encoding="utf-8")
    graph = nx.DiGraph()
    graph.add_node("fn", entity_kind="function_definition", source_file="app.py")
    rule = _rule({"source_regex": r"while\s+True"}, scope="function")
    scopes = collect_pattern_scopes(graph, rule)

    matches = run_pattern_rule(graph, PatternSourceCache(repo_root=tmp_path), rule, scopes)

    assert len(matches) == 1
    assert matches[0].matched_text == "while True"
    assert matches[0].evidence[0].kind == "source_regex"


def test_node_kind_primitive_matches_scope() -> None:
    graph = nx.DiGraph()
    graph.add_node("env", node_kind="env_var", name="DATABASE_URL")
    rule = _rule({"node_kind": "env_var"}, scope="env_var")
    scopes = collect_pattern_scopes(graph, rule)

    matches = evaluate_primitive(graph, PatternSourceCache(), rule, {"node_kind": "env_var"}, scopes)

    assert set(matches) == {"env"}


def test_edge_exists_primitive_records_edge_evidence() -> None:
    graph = nx.DiGraph()
    graph.add_node("reader")
    graph.add_node("env", node_kind="env_var")
    graph.add_edge("reader", "env", relation="READS_ENV_VAR")
    rule = _rule({"edge_exists": {"relation": "READS_ENV_VAR", "direction": "incoming"}}, scope="env_var")
    scopes = collect_pattern_scopes(graph, rule)

    matches = run_pattern_rule(graph, PatternSourceCache(), rule, scopes)

    assert len(matches) == 1
    assert matches[0].edge_ids == ["reader->env"]
    assert {"reader", "env"} <= set(matches[0].node_ids)


def test_formula_all_of_any_of_and_not() -> None:
    graph = nx.DiGraph()
    graph.add_node("a", node_kind="env_var", defined=False)
    graph.add_node("b", node_kind="env_var", defined=True)
    graph.add_node("c", node_kind="config_key", defined=False)
    scopes = collect_pattern_scopes(graph, _rule({"node_kind": "env_var"}, scope="node"))
    cache = PatternSourceCache()

    def ev(primitive, local_scopes):
        return evaluate_primitive(graph, cache, _rule({}), primitive, local_scopes)

    all_matches = evaluate_formula(
        {"all_of": [{"node_kind": "env_var"}, {"node_attr": {"key": "defined", "value": False}}]},
        scopes,
        rule_id="r",
        detector_name="d",
        eval_primitive=ev,
    )
    any_matches = evaluate_formula(
        {"any_of": [{"node_attr": {"key": "defined", "value": True}}, {"node_kind": "config_key"}]},
        scopes,
        rule_id="r",
        detector_name="d",
        eval_primitive=ev,
    )
    not_matches = evaluate_formula(
        {"all_of": [{"node_kind": "env_var"}, {"not": {"node_attr": {"key": "defined", "value": True}}}]},
        scopes,
        rule_id="r",
        detector_name="d",
        eval_primitive=ev,
    )

    assert set(all_matches) == {"a"}
    assert set(any_matches) == {"b", "c"}
    assert set(not_matches) == {"a"}


def test_pattern_match_to_candidate_emits_normal_candidate(tmp_path) -> None:
    (tmp_path / "app.py").write_text("def f():\n    while True: pass\n", encoding="utf-8")
    graph = nx.DiGraph()
    graph.add_node("fn", entity_kind="function_definition", source_file="app.py")
    rule = _rule({"source_regex": r"while\s+True"}, scope="function", detector="infinite-loop")
    match = run_pattern_rule(
        graph,
        PatternSourceCache(repo_root=tmp_path),
        rule,
        collect_pattern_scopes(graph, rule),
    )[0]

    candidate = pattern_match_to_candidate(
        match,
        rule,
        mode=AnalysisMode.full_repo_scan,
        config=IntelligenceConfig(),
        graph=graph,
        run_context=_ctx(tmp_path),
    )

    assert isinstance(candidate, Candidate)
    assert candidate.detector_payload.raw["rule_id"] == "pattern-test-rule"
    assert candidate.detector_payload.raw["matched_scope"]["node_id"] == "fn"


def test_converted_group_b_pattern_detectors_emit_candidates(tmp_path) -> None:
    (tmp_path / "api.ts").write_text(
        "function handler() {\n  while (true) {}\n  const value = user!.name;\n}\n",
        encoding="utf-8",
    )
    graph = nx.DiGraph()
    graph.add_node(
        "handler",
        entity_kind="function_declaration",
        language="typescript",
        source_file="api.ts",
    )
    cfg = IntelligenceConfig()
    ctx = _ctx(tmp_path, cfg_available={"handler": True})

    infinite, _ = run_all(
        graph,
        ChangeManifest(),
        AnalysisMode.full_repo_scan,
        cfg,
        {"enabled": ["infinite-loop"]},
        run_context=ctx,
    )
    nulls, _ = run_all(
        graph,
        ChangeManifest(),
        AnalysisMode.full_repo_scan,
        cfg,
        {"enabled": ["null-dereference-approx"]},
        run_context=ctx,
    )

    assert any(c.detector_payload.detector_name == "infinite-loop" for c in infinite)
    assert any(c.detector_payload.detector_name == "null-dereference-approx" for c in nulls)


def test_pattern_backed_env_var_detector_emits_with_evidence() -> None:
    graph = nx.DiGraph()
    graph.add_node("reader", label="process.env.MISSING_SECRET")
    graph.add_node(
        "env",
        node_kind="env_var",
        universe="env",
        name="MISSING_SECRET",
        label="MISSING_SECRET",
        defined=False,
    )
    graph.add_edge("reader", "env", relation="READS_ENV_VAR", source_system="code", target_system="env")
    cfg = IntelligenceConfig()

    candidates, _ = run_all(
        graph,
        ChangeManifest(),
        AnalysisMode.full_repo_scan,
        cfg,
        {"enabled": ["env-var-referenced-but-undefined"]},
        run_context=_ctx(),
    )

    candidate = candidates[0]
    assert candidate.detector_payload.detector_name == "env-var-referenced-but-undefined"
    assert candidate.detector_payload.raw["rule_id"] == "env-var-referenced-but-undefined"
    assert candidate.detector_payload.raw["env_var"] == "MISSING_SECRET"
    assert candidate.detector_payload.raw["evidence"]
