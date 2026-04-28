"""Group A (graph-only) detectors: seams, cross-lang cycles, topology (master plan)."""
from __future__ import annotations

import networkx as nx

from depos.analysis.detectors import register
from depos.analysis.detectors.builtin.common import iter_nodes_by_kind, make_candidate, simple_spec
from depos.analysis.schemas import ChangeManifest, SeedType, Universe, SeamEdge

# Canonical entry kinds for reachability (verified from graph fixtures: node_kind).
ENTRY_NODE_KINDS_PROD: frozenset[str] = frozenset({"next_route", "openapi_operation"})
# Test-only entry sources (paths) — routes reachable only through these are "orphan" vs prod.
_TEST_PATH_MARKERS: tuple[str, ...] = ("__tests__", ".test.", ".spec.", "/e2e/", "/playwright/")


def _is_test_path(source_file: str) -> bool:
    s = source_file.replace("\\", "/").lower()
    return any(m in s for m in _TEST_PATH_MARKERS)


def _production_entry_nodes(graph: nx.DiGraph) -> list[str]:
    """Seeds: top-level production surfaces (no incoming graph edges) or explicit API routes."""
    out: list[str] = []
    for n, a in graph.nodes(data=True):
        nk = str(a.get("node_kind") or a.get("kind") or "")
        if nk not in ENTRY_NODE_KINDS_PROD and not a.get("is_fastapi_route"):
            continue
        sf = str(a.get("source_file") or "")
        if _is_test_path(sf):
            continue
        if graph.in_degree(n) > 0 and not a.get("is_fastapi_route"):
            continue
        out.append(str(n))
    return out


def _test_entry_nodes(graph: nx.DiGraph) -> list[str]:
    out: list[str] = []
    for n, a in graph.nodes(data=True):
        nk = str(a.get("node_kind") or a.get("kind") or "")
        if nk != "next_route":
            continue
        sf = str(a.get("source_file") or "")
        if _is_test_path(sf):
            out.append(str(n))
    return out


def _reachable_from(graph: nx.DiGraph, seeds: list[str]) -> set[str]:
    r: set[str] = set()
    for e in seeds:
        if graph.has_node(e):
            r.add(e)
            r |= nx.descendants(graph, e)
    return r


def _call_subgraph(graph: nx.DiGraph) -> nx.DiGraph:
    """Directed subgraph of call/import style edges for deadness."""
    h = nx.DiGraph()
    h.add_nodes_from(graph.nodes(data=True))
    for u, v, d in graph.edges(data=True):
        rel = str(d.get("relation") or "")
        if rel in {
            "CALLS",
            "IMPORTS",
            "HTTP_CALLS_ROUTE",
            "TASK_ENQUEUES",
            "TASK_CONSUMES",
        } or rel.startswith("CALL"):
            h.add_edge(u, v, **d)
    return h


# -- specs ----------------------------------------------------------------

SPEC_CROSS_LANG = simple_spec(
    name="cross-lang-cycle",
    universe=Universe.code,
    verifier_checks=["graph_path_exists", "cross_language_cycle_witness"],
    requires_reasoner=False,
    severity="high",
    semantic_requirement=None,
)

SPEC_SEAM_DRIFT = simple_spec(
    name="seam-contract-drift",
    universe=Universe.code,
    verifier_checks=["seam_index_consistency", "graph_path_exists"],
    requires_reasoner=False,
    severity="medium",
    semantic_requirement=None,
)

SPEC_ARTIC = simple_spec(
    name="articulation-point-high-fanin",
    universe=Universe.code,
    verifier_checks=["graph_path_exists", "centrality_witness"],
    requires_reasoner=False,
    severity="medium",
    semantic_requirement=None,
)

SPEC_ORPHAN = simple_spec(
    name="orphan-surface",
    universe=Universe.nextjs,
    verifier_checks=["graph_path_exists", "in_degree_witness"],
    requires_reasoner=False,
    severity="low",
    semantic_requirement=None,
)

SPEC_DEAD = simple_spec(
    name="dead-code",
    universe=Universe.code,
    verifier_checks=["graph_path_exists", "staleness_witness"],
    requires_reasoner=False,
    severity="low",
    semantic_requirement=None,
)

SPEC_ISO = simple_spec(
    name="high-centrality-isolated",
    universe=Universe.code,
    verifier_checks=["graph_path_exists", "manifest_overlap"],
    requires_reasoner=True,
    severity="medium",
    semantic_requirement=None,
)

SPEC_ENV_EXPOSED = simple_spec(
    name="env-var-exposed",
    universe=Universe.env,
    verifier_checks=["graph_path_exists", "negation_witness"],
    requires_reasoner=False,
    severity="medium",
    semantic_requirement=None,
)


def _manifest_node_ids(manifest: object) -> set[str]:
    if not isinstance(manifest, ChangeManifest):
        return set()
    out: set[str] = set()
    for e in manifest.entries:
        for n in e.node_ids:
            out.add(str(n))
    return out


def _run_cross_lang(graph: nx.DiGraph, mode, config, ctx) -> list:
    rctx = ctx.get("run_context")
    if rctx is None or rctx.graph_metrics is None:
        return []
    cycs = rctx.graph_metrics.cross_lang_cycles or []
    if not cycs:
        return []
    out = []
    for i, cyc in enumerate(cycs[:8]):
        out.append(
            make_candidate(
                scope_id=f"code:cross-lang-cycle:{i}",
                seed_type=SeedType.graph_anomaly,
                detector_confidence=0.88,
                analysis_mode=mode,
                config=config,
                diff_anchors=list(cyc)[:5],
                extra={"cycle": cyc, "group": "A"},
            )
        )
    return out


def _run_seam_drift(graph: nx.DiGraph, mode, config, ctx) -> list:
    rctx = ctx.get("run_context")
    if rctx is None:
        return []
    index = rctx.seam_edge_index or {}
    if len(index) < 2:
        return []
    from collections import Counter

    patterns: list[str] = []
    for rec in index.values():
        if isinstance(rec, SeamEdge):
            patterns.append(str(rec.pattern))
        elif isinstance(rec, dict):
            patterns.append(str(rec.get("pattern") or "generic"))
        else:
            patterns.append("generic")
    c = Counter(patterns)
    if not c:
        return []
    top_pat, n = c.most_common(1)[0]
    if n < 2:
        return []
    eids = [
        eid
        for eid, v in index.items()
        if (
            (getattr(v, "pattern", None) if isinstance(v, SeamEdge) else (v or {}).get("pattern"))
            == top_pat
        )
    ][:6]
    return [
        make_candidate(
            scope_id=f"deps:seam-contract-drift:{top_pat}",
            seed_type=SeedType.graph_anomaly,
            detector_confidence=0.62,
            analysis_mode=mode,
            config=config,
            diff_anchors=[str(x) for x in eids if x],
            extra={"pattern": top_pat, "count": n, "group": "A"},
        )
    ]


def _run_articulation_fanin(graph: nx.DiGraph, mode, config, ctx) -> list:
    rctx = ctx.get("run_context")
    if rctx is None or rctx.graph_metrics is None:
        return []
    gmi = rctx.graph_metrics
    fin = gmi.fan_in or {}
    betw = gmi.betweenness or {}
    if not fin:
        return []
    by_fin = sorted(((int(v), n) for n, v in fin.items() if graph.has_node(n)), reverse=True)[:5]
    out = []
    for deg, node in by_fin:
        b = float(betw.get(node, 0.0) or 0.0)
        if deg >= 6 and b >= 0.05:
            out.append(
                make_candidate(
                    scope_id=f"code:fanin:{node}",
                    seed_type=SeedType.graph_anomaly,
                    detector_confidence=0.71,
                    analysis_mode=mode,
                    config=config,
                    diff_anchors=[str(node)],
                    extra={"fan_in": deg, "betweenness": b, "group": "A"},
                )
            )
    return out


def _run_orphan_surface(graph: nx.DiGraph, mode, config, ctx) -> list:
    """Surface nodes not reachable from production entry points (BFS on full graph)."""
    prod = _production_entry_nodes(graph)
    reach_prod = _reachable_from(graph, prod)
    out = []
    seen: set[str] = set()
    for n, a in graph.nodes(data=True):
        if str(a.get("node_kind") or a.get("kind") or "") != "next_route":
            continue
        sf = str(a.get("source_file") or "")
        if _is_test_path(sf):
            continue
        if n not in reach_prod:
            if str(n) in seen:
                continue
            seen.add(str(n))
            out.append(
                make_candidate(
                    scope_id=f"nextjs:orphan-surface:{n}",
                    seed_type=SeedType.graph_anomaly,
                    detector_confidence=0.55,
                    analysis_mode=mode,
                    config=config,
                    diff_anchors=[str(n)],
                    extra={"group": "A", "reachability": "not_from_prod_entries"},
                )
            )
    # Routes only reachable from test sandboxes (not from prod entries) — stricter orphan.
    test_e = _test_entry_nodes(graph)
    reach_test = _reachable_from(graph, test_e)
    for n, a in graph.nodes(data=True):
        if str(a.get("node_kind") or a.get("kind") or "") != "next_route":
            continue
        sf = str(a.get("source_file") or "")
        if _is_test_path(sf):
            continue
        if n in reach_test and n not in reach_prod:
            if str(n) in seen:
                continue
            seen.add(str(n))
            out.append(
                make_candidate(
                    scope_id=f"nextjs:orphan-test-only:{n}",
                    seed_type=SeedType.graph_anomaly,
                    detector_confidence=0.58,
                    analysis_mode=mode,
                    config=config,
                    diff_anchors=[str(n)],
                    extra={"group": "A", "reachability": "test_sandbox_only"},
                )
            )
    return out


def _run_dead_code(graph: nx.DiGraph, mode, config, ctx) -> list:
    """Dead = not reachable from production entries on call subgraph (transitive)."""
    cg = _call_subgraph(graph)
    prod = _production_entry_nodes(graph)
    seeds = [e for e in prod if cg.has_node(e)]
    reach = _reachable_from(cg, seeds)
    out = []
    for n, a in cg.nodes(data=True):
        nk = str(a.get("node_kind") or a.get("kind") or "")
        if nk not in {"function", "function_declaration", "method", "class_declaration"} and not a.get("synthetic_entity"):
            if not a.get("is_fastapi_route") and not a.get("label"):
                continue
        if n in reach:
            continue
        if cg.in_degree(n) == 0 and not a.get("is_fastapi_route"):
            continue
        out.append(
            make_candidate(
                scope_id=f"code:dead-reachability:{n}",
                seed_type=SeedType.graph_anomaly,
                detector_confidence=0.52,
                analysis_mode=mode,
                config=config,
                diff_anchors=[str(n)],
                extra={"group": "A", "dead_reason": "not_reachable_from_prod_entries"},
            )
        )
    return out[:40]


def _run_env_var_exposed(graph: nx.DiGraph, mode, config, ctx) -> list:
    safe = {str(x) for x in config.detectors.env_var_safe_names}
    out = []
    for node_id, attrs in iter_nodes_by_kind(graph, "env_var"):
        name = attrs.get("env_var_name", attrs.get("name"))
        dynamic = bool(attrs.get("dynamic"))
        if name and str(name) in safe:
            continue
        if not name or dynamic:
            out.append(
                make_candidate(
                    scope_id=f"env:exposed:{node_id}",
                    seed_type=SeedType.graph_anomaly,
                    detector_confidence=0.61,
                    analysis_mode=mode,
                    config=config,
                    diff_anchors=[str(node_id)],
                    extra={
                        "group": "A",
                        "env_var": name,
                        "dynamic": dynamic,
                        "note": "missing_name" if not name else "dynamic_access",
                    },
                )
            )
    return out


def _run_centrality_isolated(graph: nx.DiGraph, manifest, mode, config, ctx) -> list:
    rctx = ctx.get("run_context")
    if rctx is None or rctx.graph_metrics is None:
        return []
    m_nodes = _manifest_node_ids(manifest)
    if not m_nodes:
        return []
    pr = rctx.graph_metrics.node_pagerank or {}
    if not pr:
        return []
    ranked = sorted(((float(s), n) for n, s in pr.items()), reverse=True)[:20]
    out = []
    for score, n in ranked:
        if m_nodes and str(n) not in m_nodes and score > 0.02:
            out.append(
                make_candidate(
                    scope_id=f"code:hi-centrality-isolated:{n}",
                    seed_type=SeedType.graph_anomaly,
                    detector_confidence=0.68,
                    analysis_mode=mode,
                    config=config,
                    diff_anchors=[str(n)],
                    extra={"pagerank": score, "group": "A", "isolated_from_manifest": True},
                )
            )
    return out[:10]


def run_cross_lang(graph, manifest, mode, config, ctx):
    return _run_cross_lang(graph, mode, config, ctx)


def run_seam_drift(graph, manifest, mode, config, ctx):
    return _run_seam_drift(graph, mode, config, ctx)


def run_artic(graph, manifest, mode, config, ctx):
    return _run_articulation_fanin(graph, mode, config, ctx)


def run_orphan(graph, manifest, mode, config, ctx):
    return _run_orphan_surface(graph, mode, config, ctx)


def run_dead(graph, manifest, mode, config, ctx):
    return _run_dead_code(graph, mode, config, ctx)


def run_iso(graph, manifest, mode, config, ctx):
    return _run_centrality_isolated(graph, manifest, mode, config, ctx)


def run_env_exposed(graph, manifest, mode, config, ctx):
    return _run_env_var_exposed(graph, mode, config, ctx)


register(SPEC_CROSS_LANG, run_cross_lang)
register(SPEC_SEAM_DRIFT, run_seam_drift)
register(SPEC_ARTIC, run_artic)
register(SPEC_ORPHAN, run_orphan)
register(SPEC_DEAD, run_dead)
register(SPEC_ISO, run_iso)
register(SPEC_ENV_EXPOSED, run_env_exposed)
