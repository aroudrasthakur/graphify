"""Group B: CFG-gated heuristics (Python + JS/TS) — master plan inventory."""
from __future__ import annotations

import re
from typing import Any

import networkx as nx

from depos.analysis.detectors import register
from depos.analysis.detectors.pattern_matcher import (
    PatternSourceCache,
    collect_pattern_scopes,
    pattern_match_to_candidate,
    run_pattern_rule,
)
from depos.analysis.detectors.pattern_registry import INFINITE_LOOP, TS_NON_NULL_ASSERTION
from depos.analysis.detectors.policy import iter_eligible_scopes
from depos.analysis.detectors.builtin.common import make_candidate, simple_spec, read_source_text_safely
from depos.analysis.schemas import SeedType, Universe

RE_UNREACH = re.compile(r"if\s*\(\s*false\s*\)|if\s*\(\s*0\s*\)|\bif\s+False\s*:", re.I)
RE_OFFBY = re.compile(r"<=\s*\w+\s*\.\s*length|len\s*\(\s*\w+\s*\)\s*[-+]\s*1|for\s*\([^)]*<=[^;]*length", re.I)
RE_EMPTY_CATCH = re.compile(
    r"catch\s*\(\s*[^)]*\s*\)\s*\{\s*(?:/\*[^*]*\*+(?:[^/*][^*]*\*+)*/\s*)?\}",
    re.M,
)
RE_DBL_NEG = re.compile(r"if\s*\(\s*!\s*!\s*", re.M)


def _iter_cfg_scopes(
    graph: nx.DiGraph, ctx: dict[str, Any], spec: Any
) -> list[tuple[str, dict[str, Any], bool]]:
    rctx = ctx.get("run_context")
    if rctx is None:
        return []
    out: list[tuple[str, dict, bool]] = []
    for sid in iter_eligible_scopes(graph, rctx, spec):
        a = graph.nodes.get(sid) or {}
        if not isinstance(a, dict):
            a = {}
        rel = str(a.get("source_file") or "")
        if not rel:
            continue
        out.append((sid, a, bool(rctx.cfg_available.get(sid))))
    return out


def _make(
    det_name: str, scope: str, mode, config, extra: dict[str, Any], ps: float
):
    e = {**extra, "group": "B", "detector": det_name}
    return make_candidate(
        scope_id=f"cfg:{det_name}:{scope}",
        seed_type=SeedType.graph_anomaly,
        detector_confidence=ps,
        analysis_mode=mode,
        config=config,
        diff_anchors=[str(scope)],
        extra=e,
        requires_cfg=True,
    )


SPEC = [
    simple_spec(
        name="infinite-loop",
        universe=Universe.code,
        verifier_checks=["source_snippet", "cfg_path_exists"],
        requires_reasoner=False,
        severity="high",
        semantic_requirement="cfg",
    ),
    simple_spec(
        name="unreachable-branch",
        universe=Universe.code,
        verifier_checks=["source_snippet", "cfg_path_exists"],
        requires_reasoner=False,
        severity="medium",
        semantic_requirement="cfg",
    ),
    simple_spec(
        name="off-by-one-approx",
        universe=Universe.code,
        verifier_checks=["source_snippet", "cfg_path_exists"],
        requires_reasoner=True,
        severity="medium",
        semantic_requirement="cfg",
    ),
    simple_spec(
        name="null-dereference-approx",
        universe=Universe.code,
        verifier_checks=["source_snippet", "cfg_path_exists"],
        requires_reasoner=True,
        severity="high",
        semantic_requirement="cfg",
    ),
    simple_spec(
        name="unhandled-exception-path",
        universe=Universe.code,
        verifier_checks=["source_snippet", "cfg_path_exists"],
        requires_reasoner=True,
        severity="medium",
        semantic_requirement="cfg",
    ),
    simple_spec(
        name="logic-inversion-approx",
        universe=Universe.code,
        verifier_checks=["source_snippet", "cfg_path_exists"],
        requires_reasoner=True,
        severity="low",
        semantic_requirement="cfg",
    ),
]


def _run_infinite_loop(graph, manifest, mode, config, ctx) -> list:
    spec = ctx["detector"]
    rctx = ctx.get("run_context")
    root = rctx.repo_root if rctx is not None else None
    eligible = [sid for sid, _, has_cfg in _iter_cfg_scopes(graph, ctx, spec) if has_cfg]
    source_cache = PatternSourceCache(repo_root=root)
    scopes = collect_pattern_scopes(graph, INFINITE_LOOP, scope_ids=eligible)
    return [
        pattern_match_to_candidate(
            match,
            INFINITE_LOOP,
            mode=mode,
            config=config,
            graph=graph,
            run_context=rctx,
            extra={"group": "B", "detector": "infinite-loop", "pattern": "while_true"},
        )
        for match in run_pattern_rule(graph, source_cache, INFINITE_LOOP, scopes, ctx)
    ]


def _run_unreachable(graph, manifest, mode, config, ctx) -> list:
    out = []
    spec = ctx["detector"]
    rctx = ctx.get("run_context")
    root = rctx.repo_root if rctx is not None else None
    for sid, a, has_cfg in _iter_cfg_scopes(graph, ctx, spec):
        if not has_cfg:
            continue
        src = read_source_text_safely(root, str(a.get("source_file") or ""))
        if not src or not RE_UNREACH.search(src):
            continue
        out.append(_make("unreachable-branch", sid, mode, config, {"pattern": "if_false"}, 0.72))
    return out


def _run_offby(graph, manifest, mode, config, ctx) -> list:
    out = []
    spec = ctx["detector"]
    rctx = ctx.get("run_context")
    root = rctx.repo_root if rctx is not None else None
    for sid, a, has_cfg in _iter_cfg_scopes(graph, ctx, spec):
        if not has_cfg:
            continue
        src = read_source_text_safely(root, str(a.get("source_file") or ""))
        if not src or not RE_OFFBY.search(src):
            continue
        out.append(_make("off-by-one-approx", sid, mode, config, {"pattern": "index_vs_length"}, 0.65))
    return out


def _run_null_deref(graph, manifest, mode, config, ctx) -> list:
    spec = ctx["detector"]
    rctx = ctx.get("run_context")
    root = rctx.repo_root if rctx is not None else None
    eligible = []
    for sid, a, has_cfg in _iter_cfg_scopes(graph, ctx, spec):
        rel = str(a.get("source_file") or "")
        if has_cfg and rel.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")):
            eligible.append(sid)
    source_cache = PatternSourceCache(repo_root=root)
    scopes = collect_pattern_scopes(graph, TS_NON_NULL_ASSERTION, scope_ids=eligible)
    return [
        pattern_match_to_candidate(
            match,
            TS_NON_NULL_ASSERTION,
            mode=mode,
            config=config,
            graph=graph,
            run_context=rctx,
            extra={
                "group": "B",
                "detector": "null-dereference-approx",
                "pattern": "ts_non_null_assertion",
            },
        )
        for match in run_pattern_rule(graph, source_cache, TS_NON_NULL_ASSERTION, scopes, ctx)
    ]


def _run_unhandled(graph, manifest, mode, config, ctx) -> list:
    out = []
    spec = ctx["detector"]
    rctx = ctx.get("run_context")
    root = rctx.repo_root if rctx is not None else None
    for sid, a, has_cfg in _iter_cfg_scopes(graph, ctx, spec):
        if not has_cfg:
            continue
        src = read_source_text_safely(root, str(a.get("source_file") or ""))
        if not src or "try" not in src:
            continue
        if RE_EMPTY_CATCH.search(src):
            out.append(
                _make("unhandled-exception-path", sid, mode, config, {"pattern": "empty_catch"}, 0.74)
            )
    return out


def _run_logic_inversion(graph, manifest, mode, config, ctx) -> list:
    out = []
    spec = ctx["detector"]
    rctx = ctx.get("run_context")
    root = rctx.repo_root if rctx is not None else None
    for sid, a, has_cfg in _iter_cfg_scopes(graph, ctx, spec):
        if not has_cfg:
            continue
        src = read_source_text_safely(root, str(a.get("source_file") or ""))
        if not src or not RE_DBL_NEG.search(src):
            continue
        out.append(
            _make("logic-inversion-approx", sid, mode, config, {"pattern": "double_negation_in_condition"}, 0.52)
        )
    return out




def run1(*a):
    return _run_infinite_loop(*a)


def run2(*a):
    return _run_unreachable(*a)


def run3(*a):
    return _run_offby(*a)


def run4(*a):
    return _run_null_deref(*a)


def run5(*a):
    return _run_unhandled(*a)


def run6(*a):
    return _run_logic_inversion(*a)


for sp, fn in zip(SPEC, (run1, run2, run3, run4, run5, run6), strict=True):
    register(sp, fn)
