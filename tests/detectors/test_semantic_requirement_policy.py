"""Policy gate: Group A = ``semantic_requirement is None``; B/C = cfg / dfg / taint layers."""
from __future__ import annotations

from depos.analysis.detectors import REGISTRY, load_builtin
from depos.analysis.detectors.policy import DetectorPolicy
from depos.analysis.run_context import GraphMetrics, RunContext


def _ctx_python_full() -> RunContext:
    m = GraphMetrics()
    m._computed = True
    return RunContext(
        manifest=None,
        graph_metrics=m,
        cfg_available={"py_scope": True},
        dfg_available={"py_scope": True},
        taint_edges_available={"py_scope": True},
    )


def _ctx_jsts_no_layers() -> RunContext:
    m = GraphMetrics()
    m._computed = True
    return RunContext(
        manifest=None,
        graph_metrics=m,
        cfg_available={"js_scope": False},
        dfg_available={"js_scope": False},
        taint_edges_available={"js_scope": False},
    )


def _ctx_go_no_layers() -> RunContext:
    m = GraphMetrics()
    m._computed = True
    return RunContext(
        manifest=None,
        graph_metrics=m,
    )


def _ctx_jsts_all_layers() -> RunContext:
    m = GraphMetrics()
    m._computed = True
    return RunContext(
        manifest=None,
        graph_metrics=m,
        cfg_available={"js_scope": True},
        dfg_available={"js_scope": True},
        taint_edges_available={"js_scope": True},
    )


def test_python_full_sees_abc_by_policy() -> None:
    load_builtin()
    pol = DetectorPolicy()
    rctx = _ctx_python_full()
    scope = "py_scope"
    for name, (spec, _) in REGISTRY.items():
        if spec.semantic_requirement is None:
            assert pol.semantic_layer_satisfied(spec, rctx, scope), f"A {name}"
        elif spec.semantic_requirement == "cfg":
            assert pol.semantic_layer_satisfied(spec, rctx, scope), f"B {name}"
        elif spec.semantic_requirement in ("dfg", "taint"):
            assert pol.semantic_layer_satisfied(spec, rctx, scope), f"C {name}"


def test_jsts_unanalyzed_sees_group_a_only() -> None:
    load_builtin()
    pol = DetectorPolicy()
    rctx = _ctx_jsts_no_layers()
    scope = "js_scope"
    for name, (spec, _) in REGISTRY.items():
        if spec.semantic_requirement is None:
            assert pol.semantic_layer_satisfied(spec, rctx, scope), f"A {name} should run"
        else:
            assert not pol.semantic_layer_satisfied(spec, rctx, scope), f"{name} B/C should not run for empty layers"


def test_non_code_scope_sees_group_a_only() -> None:
    load_builtin()
    pol = DetectorPolicy()
    rctx = _ctx_go_no_layers()
    scope = "go_scope"
    for name, (spec, _) in REGISTRY.items():
        if spec.semantic_requirement is None:
            assert pol.semantic_layer_satisfied(spec, rctx, scope), f"A {name}"
        else:
            assert not pol.semantic_layer_satisfied(spec, rctx, scope), f"{name} B/C without layers"


def test_jsts_with_full_layers_allows_b_and_c() -> None:
    load_builtin()
    pol = DetectorPolicy()
    rctx = _ctx_jsts_all_layers()
    scope = "js_scope"
    for name, (spec, _) in REGISTRY.items():
        if spec.semantic_requirement is None:
            assert pol.semantic_layer_satisfied(spec, rctx, scope), name
        elif spec.semantic_requirement in ("cfg", "dfg", "taint"):
            assert pol.semantic_layer_satisfied(spec, rctx, scope), name


def test_every_detector_declares_valid_semantic_requirement() -> None:
    load_builtin()
    for name, (spec, _) in REGISTRY.items():
        r = spec.semantic_requirement
        assert r is None or r in ("cfg", "dfg", "taint"), f"{name}: {r!r}"
