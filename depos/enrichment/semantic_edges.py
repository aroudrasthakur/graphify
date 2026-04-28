"""Module 1 orchestrator: run all probes, emit semantic edges, compute the
:class:`StitcherCoverageReport`.

All enrichers now produce :class:`~depos.analysis.fragments.GraphFragment`
objects. :func:`enrich_graph` merges them into the graph at each wave
boundary using :func:`~depos.analysis.fragments.merge_fragments`, keeping the
main thread as the sole graph writer (Phase 6a).
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Optional

import networkx as nx

from depos.analysis.config import IntelligenceConfig
from depos.analysis.fragments import GraphFragment, merge_fragments
from depos.graph_relations import CONSUMES_OPENAPI_OP
from depos.graph_relations import CONSUMES_PAYLOAD
from depos.graph_relations import DECLARES_DEP
from depos.graph_relations import DEFINED_BY_CONFIG
from depos.graph_relations import HTTP_CALLS_ROUTE
from depos.graph_relations import IMPLEMENTS_OPENAPI_OP
from depos.graph_relations import IMPORTS_PACKAGE
from depos.graph_relations import MIGRATION_PRECEDES
from depos.graph_relations import NEXT_ROUTE_GUARDED_BY_MIDDLEWARE
from depos.graph_relations import NEXT_ROUTE_USES_LAYOUT
from depos.graph_relations import PEER_OF
from depos.graph_relations import PRODUCES_PAYLOAD
from depos.graph_relations import PROMPT_DECLARES_VAR
from depos.graph_relations import PROMPT_USES_VAR
from depos.graph_relations import READS_ENV_VAR
from depos.graph_relations import RENDERED_BY_PROMPT

logger = logging.getLogger(__name__)
from depos.graph_relations import RESOLVES_TO
from depos.graph_relations import ROUTE_CALLS_RPC
from depos.graph_relations import ROUTE_GUARDED_BY_RLS
from depos.graph_relations import ROUTE_READS_TABLE
from depos.graph_relations import ROUTE_WRITES_TABLE
from depos.graph_relations import SCHEMA_DEFINED_BY_MIGRATION
from depos.graph_relations import SCHEMA_OF
from depos.graph_relations import SERVICE_DEPENDS_ON
from depos.graph_relations import STAGE_COPIES_PATH
from depos.graph_relations import TASK_CONSUMES
from depos.graph_relations import TASK_ENQUEUES
from depos.graph_relations import WORKFLOW_USES_SECRET
from depos.graph_relations import WRITES_ENV_VAR
from depos.analysis.schemas import IngestReport
from depos.analysis.schemas import (
    ContractKind,
    RLSCoverage,
    SemanticEdgeMetadata,
    StitcherCoverageReport,
)
from depos.enrichment.http_probes import (
    annotate_fastapi_routes,
    annotate_ts_http_calls,
    iter_fastapi_route_nodes,
)
from depos.enrichment.url_normalize import normalize_route, score_match
from depos.analysis.fragments import FragmentEdge, make_fragment


ENRICHER_SCHEMA_VERSION = "v1"


def _edge_key(metadata: SemanticEdgeMetadata, *, source_node_id: str = "") -> str:
    """Stable edge key attribute.  Incorporates source_node_id for HTTP_CALLS_ROUTE
    edges so two call-site nodes mapping to the same route produce distinct keys."""
    route = metadata.route_pattern or metadata.table_name or metadata.task_name or ""
    return f"{metadata.contract_kind}:{metadata.api_method or ''}:{route}:{source_node_id}"


def _safe_run(name: str, fn: Callable[[], Any], errors_out: list[dict[str, Any]]) -> Any:
    try:
        return fn()
    except ImportError as exc:
        errors_out.append({"probe": name, "kind": "import_error", "message": str(exc)})
    except Exception as exc:  # noqa: BLE001 - defensive by design
        errors_out.append({"probe": name, "kind": "probe_error", "message": str(exc)})
    return None


def emit_http_calls_route(graph: nx.DiGraph) -> GraphFragment:
    """Match annotated TS fetch/axios call sites to annotated FastAPI route
    nodes and return a :class:`~depos.analysis.fragments.GraphFragment`
    containing :data:`HTTP_CALLS_ROUTE` edges.

    Deduplicates by ``(caller, handler)`` pair, keeping the highest-confidence
    match, so each pair produces exactly one FragmentEdge regardless of how
    many call sites in the same file match the same route.
    """
    routes: list[tuple[str, object]] = []
    for nid, attrs in iter_fastapi_route_nodes(graph):
        method = (attrs.get("http_method") or "").upper()
        path = attrs.get("route_pattern") or ""
        routes.append((nid, normalize_route(path, method=method)))

    if not routes:
        return make_fragment("enrich_http_route")

    # best_by_pair: (caller_node_id, handler_id) → (metadata, result, server_nr)
    best_by_pair: dict[tuple[str, str], tuple[SemanticEdgeMetadata, Any]] = {}

    for node_id, node_attrs in graph.nodes(data=True):
        sites = node_attrs.get("http_call_sites")
        if not sites:
            continue
        for site in sites:
            client = normalize_route(
                site["url_literal"],
                method=site.get("http_method"),
                strip_api=True,
            )
            best = None
            best_score = 0.0

            logger.debug(
                "Matching client route: %s (method=%s, is_dynamic=%s, method_inferred=%s)",
                client.normalized,
                client.method,
                site.get("is_dynamic_url"),
                site.get("method_inferred"),
            )

            for (handler_id, server_nr) in routes:
                result = score_match(
                    client,
                    server_nr,
                    client_is_dynamic_url=bool(site.get("is_dynamic_url")),
                    client_method_inferred=bool(site.get("method_inferred")),
                )

                logger.debug(
                    "  vs server route: %s (method=%s) -> score=%.2f, emit=%s, kind=%s",
                    server_nr.normalized,
                    server_nr.method,
                    result.score,
                    result.emit,
                    result.match_kind,
                )

                if result.emit and result.score > best_score:
                    best = (handler_id, server_nr, result)
                    best_score = result.score

            if best is None:
                logger.debug("  No match found (all scores below emit threshold)")
                continue

            handler_id, server_nr, result = best
            caller_node_id = site.get("node_id", node_id)

            metadata = SemanticEdgeMetadata(
                confidence=result.score,
                inferred=result.inferred,
                source_system="typescript",
                target_system="python",
                contract_kind=ContractKind.http,
                api_method=server_nr.method,
                route_pattern=server_nr.normalized,
            )

            pair = (caller_node_id, handler_id)
            prev = best_by_pair.get(pair)
            if prev is None or result.score > prev[1].confidence:
                best_by_pair[pair] = (metadata, result)

    edges: list[FragmentEdge] = []
    for (caller_node_id, handler_id), (metadata, result) in best_by_pair.items():
        logger.debug(
            "  EMITTING edge: caller=%s -> handler=%s (score=%.2f)",
            caller_node_id,
            handler_id,
            metadata.confidence,
        )
        edges.append(FragmentEdge(
            u=caller_node_id,
            v=handler_id,
            key=_edge_key(metadata, source_node_id=caller_node_id),
            attrs={
                "relation": HTTP_CALLS_ROUTE,
                **metadata.model_dump(mode="json"),
            },
        ))

    return make_fragment("enrich_http_route", edges=edges)


def _discover_rls_policy_nodes(graph: nx.DiGraph) -> int:
    """Count nodes that look like RLS policies so the coverage report can
    distinguish "no SQL extracted" (0) from "SQL extracted but no policies"."""
    count = 0
    for _, attrs in graph.nodes(data=True):
        label = (attrs.get("label") or "").lower()
        relation = attrs.get("relation") or ""
        if "rls" in label or "policy" in label and label.startswith(("create policy", "rls_")):
            count += 1
            continue
        if relation in {"rls_policy", "policy"}:
            count += 1
    return count


def _discover_migration_files(graph: nx.DiGraph, glob: str, repo_root: Optional[Path] = None) -> int:
    """Count migration files present in the graph (via source_file) AND on
    disk at the configured glob. We report the on-disk number so the
    coverage report reflects what Module 1 can actually sequence over.
    """
    base = repo_root or Path()
    on_disk = sorted(base.glob(glob))
    return len(on_disk)


def compute_coverage(
    graph: nx.DiGraph,
    *,
    config: IntelligenceConfig,
    repo_root: Optional[Path] = None,
) -> StitcherCoverageReport:
    routes = list(iter_fastapi_route_nodes(graph))
    total = len(routes)
    linked = 0
    unlinked: list[str] = []
    for nid, attrs in routes:
        has_incoming = any(
            data.get("relation") == HTTP_CALLS_ROUTE for _, _, data in graph.in_edges(nid, data=True)
        )
        if has_incoming:
            linked += 1
        else:
            pattern = attrs.get("route_pattern") or nid
            method = (attrs.get("http_method") or "").upper()
            unlinked.append(f"{method} {pattern}".strip())

    ratio = (linked / total) if total else 1.0
    report = StitcherCoverageReport(
        total_fastapi_routes=total,
        linked_routes=linked,
        unlinked_routes=unlinked,
        coverage_ratio=round(ratio, 4),
        low_coverage=total > 0 and ratio < config.low_stitcher_coverage_threshold,
        rls_nodes_found=_discover_rls_policy_nodes(graph),
        migration_files_found=_discover_migration_files(graph, config.migration_glob, repo_root),
    )
    return report


def enrich_graph(
    graph: nx.DiGraph,
    *,
    config: IntelligenceConfig,
    repo_root: Optional[Path] = None,
    n_jobs: int = 1,
) -> tuple[nx.DiGraph, StitcherCoverageReport]:
    """Run all Module 1 passes in order, merge fragments wave-by-wave, and
    return the enriched graph plus the :class:`StitcherCoverageReport`.

    Wave ordering:
    1. ``ingest_all`` — direct graph mutation (not yet fragment-based).
    2. Wave A: ``annotate_fastapi_routes`` + ``annotate_ts_http_calls`` →
       fragments merged immediately so downstream enrichers see annotations.
    3. ``emit_http_calls_route`` — reads annotated graph, produces fragment.
    4. Wave B: independent emitters → fragments.
    5. ``merge_fragments`` for step 3 + 4 together.

    Graceful degradation: each probe catches its own errors so a bug in one
    does not prevent the others from running.
    """
    graph.graph["migration_glob"] = config.migration_glob
    errors: list[dict[str, Any]] = []
    ingest_reports: list[IngestReport] = []

    # ── Layer 0: ingest (direct graph mutation; not yet fragment-based) ────
    if repo_root is not None:
        result = _safe_run(
            "ingest_all",
            lambda: __import__("depos.ingest", fromlist=["ingest_all"]).ingest_all(  # noqa: WPS421
                graph,
                repo_root=repo_root,
                config=config,
            ),
            errors,
        )
        if isinstance(result, list):
            ingest_reports = result
            for report in ingest_reports:
                if hasattr(report, "errors"):
                    errors.extend(list(report.errors))

    # ── Wave A: annotators → merge immediately so emit_http_calls_route reads them ──
    frag_fastapi = _safe_run(
        "annotate_fastapi_routes",
        lambda: annotate_fastapi_routes(graph, repo_root=repo_root),
        errors,
    )
    frag_ts = _safe_run(
        "annotate_ts_http_calls",
        lambda: annotate_ts_http_calls(graph, repo_root=repo_root),
        errors,
    )
    wave_a_frags = [f for f in [frag_fastapi, frag_ts] if isinstance(f, GraphFragment)]
    if wave_a_frags:
        merge_fragments(graph, wave_a_frags)

    # ── Wave A cont: emit HTTP call→route edges (reads annotated graph) ────
    frag_http = _safe_run("emit_http_calls_route", lambda: emit_http_calls_route(graph), errors)

    # ── Wave B: independent emitters ────────────────────────────────────────
    # Build a (name, callable) list. When n_jobs > 1 we wrap graph in
    # ReadOnlyGraphView so accidental mutations surface immediately.
    _wave_b_read_target: Any = graph
    if n_jobs > 1:
        from depos.enrichment.readonly_graph import ReadOnlyGraphView
        _wave_b_read_target = ReadOnlyGraphView(graph)

    _wave_b_jobs: list[tuple[str, Any]] = [
        (
            "emit_rls_edges",
            lambda g=_wave_b_read_target: __import__(  # noqa: WPS421
                "depos.enrichment.rls_resolver", fromlist=["emit_rls_edges"]
            ).emit_rls_edges(g, repo_root=repo_root),
        ),
        (
            "emit_migration_edges",
            lambda g=_wave_b_read_target: __import__(  # noqa: WPS421
                "depos.enrichment.migrations", fromlist=["emit_migration_edges"]
            ).emit_migration_edges(g, config=config, repo_root=repo_root),
        ),
        (
            "emit_celery_payload_edges",
            lambda g=_wave_b_read_target: __import__(  # noqa: WPS421
                "depos.enrichment.celery_payload", fromlist=["emit_celery_payload_edges"]
            ).emit_celery_payload_edges(g, repo_root=repo_root),
        ),
        (
            "emit_dependency_edges",
            lambda g=_wave_b_read_target: __import__(  # noqa: WPS421
                "depos.enrichment.deps_resolver", fromlist=["emit_dependency_edges"]
            ).emit_dependency_edges(g, repo_root=repo_root),
        ),
        (
            "emit_env_edges",
            lambda g=_wave_b_read_target: __import__(  # noqa: WPS421
                "depos.enrichment.env_resolver", fromlist=["emit_env_edges"]
            ).emit_env_edges(g, repo_root=repo_root),
        ),
        (
            "emit_prompt_edges",
            lambda g=_wave_b_read_target: __import__(  # noqa: WPS421
                "depos.enrichment.prompt_resolver", fromlist=["emit_prompt_edges"]
            ).emit_prompt_edges(g, repo_root=repo_root),
        ),
        (
            "emit_openapi_edges",
            lambda g=_wave_b_read_target: __import__(  # noqa: WPS421
                "depos.enrichment.openapi_resolver", fromlist=["emit_openapi_edges"]
            ).emit_openapi_edges(g, repo_root=repo_root),
        ),
        (
            "emit_nextjs_edges",
            lambda g=_wave_b_read_target: __import__(  # noqa: WPS421
                "depos.enrichment.nextjs_resolver", fromlist=["emit_nextjs_edges"]
            ).emit_nextjs_edges(g, repo_root=repo_root),
        ),
    ]

    wave_b_frags: list[GraphFragment] = []

    def _run_wave_b_worker(name: str, fn: Any) -> tuple[Any, list[dict[str, Any]]]:
        local_errors: list[dict[str, Any]] = []
        result = _safe_run(name, fn, local_errors)
        return result, local_errors

    if n_jobs > 1:
        tasks = list(_wave_b_jobs)
        max_workers = max(1, min(int(n_jobs), len(tasks)))
        paired: list[tuple[Any, list[dict[str, Any]]]]
        try:
            from joblib import Parallel, delayed  # type: ignore[import-untyped]

            paired = Parallel(n_jobs=max_workers, backend="threading")(
                delayed(_run_wave_b_worker)(name, fn) for name, fn in tasks
            )
        except ImportError:
            logger.warning(
                "joblib not installed; using stdlib ThreadPoolExecutor for Wave B "
                "(pip install 'graphifyy[perf]' for joblib)"
            )
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                paired = list(pool.map(lambda item: _run_wave_b_worker(item[0], item[1]), tasks))
        for result, local_errors in paired:
            errors.extend(local_errors)
            if isinstance(result, GraphFragment):
                wave_b_frags.append(result)
    else:
        for name, fn in _wave_b_jobs:
            result = _safe_run(name, fn, errors)
            if isinstance(result, GraphFragment):
                wave_b_frags.append(result)

    frag_rls = next(
        (f for f in wave_b_frags if f.stage == "enrich_rls"),
        None,
    )

    # ── Merge Wave A (http_route) + all Wave B fragments ───────────────────
    all_frags = [f for f in [frag_http] + wave_b_frags if isinstance(f, GraphFragment)]
    if all_frags:
        merge_fragments(graph, all_frags)

    coverage = compute_coverage(graph, config=config, repo_root=repo_root)
    coverage.errors.extend(errors)
    # Expose run-level metadata so downstream modules / CLI can read flags.
    graph.graph.setdefault("run_metadata", {})
    # Propagate run-level flags from fragment diagnostics (main thread only).
    if frag_rls is not None:
        for diag in frag_rls.diagnostics:
            if diag.get("flag") == "needs_manual_rls_config":
                graph.graph["run_metadata"]["needs_manual_rls_config"] = diag["value"]
    graph.graph["run_metadata"]["low_stitcher_coverage"] = coverage.low_coverage
    graph.graph["run_metadata"]["coverage"] = coverage.model_dump(mode="json")
    graph.graph["run_metadata"]["ingest_reports"] = [report.model_dump(mode="json") for report in ingest_reports]
    graph.graph["run_metadata"]["ingest_errors"] = list(errors)
    return graph, coverage


__all__ = [
    "enrich_graph",
    "compute_coverage",
    "ENRICHER_SCHEMA_VERSION",
    "emit_http_calls_route",
    "HTTP_CALLS_ROUTE",
    "ROUTE_READS_TABLE",
    "ROUTE_WRITES_TABLE",
    "ROUTE_CALLS_RPC",
    "ROUTE_GUARDED_BY_RLS",
    "TASK_ENQUEUES",
    "TASK_CONSUMES",
    "PRODUCES_PAYLOAD",
    "CONSUMES_PAYLOAD",
    "SCHEMA_DEFINED_BY_MIGRATION",
    "MIGRATION_PRECEDES",
    "DECLARES_DEP",
    "RESOLVES_TO",
    "PEER_OF",
    "IMPORTS_PACKAGE",
    "READS_ENV_VAR",
    "WRITES_ENV_VAR",
    "DEFINED_BY_CONFIG",
    "RENDERED_BY_PROMPT",
    "PROMPT_DECLARES_VAR",
    "PROMPT_USES_VAR",
    "IMPLEMENTS_OPENAPI_OP",
    "CONSUMES_OPENAPI_OP",
    "SCHEMA_OF",
    "NEXT_ROUTE_GUARDED_BY_MIDDLEWARE",
    "NEXT_ROUTE_USES_LAYOUT",
    "WORKFLOW_USES_SECRET",
    "SERVICE_DEPENDS_ON",
    "STAGE_COPIES_PATH",
]
