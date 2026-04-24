"""Detector registry and execution."""
from __future__ import annotations

import importlib
import time
from pathlib import Path
from typing import Any, Callable, Optional

import networkx as nx

from depos.analysis.detectors.policy import DetectorPolicy, iter_eligible_scopes, load_policy
from depos.analysis.run_context import RunContext
from depos.analysis.schemas import (
    Candidate,
    Detector,
    DetectorPayload,
    DetectorRunStats,
    TaintEdge,
)
from depos.analysis.scoring import apply_composite


DetectorRunner = Callable[[nx.DiGraph, Any, Any, Any, dict[str, Any]], list[Candidate]]
REGISTRY: dict[str, tuple[Detector, DetectorRunner]] = {}
_BUILTINS_LOADED = False
PIPELINE_VERSION = "2.0.0"

_BUILTIN_MODULES = [
    "depos.analysis.detectors.builtin.diff_anchor",
    "depos.analysis.detectors.builtin.interface_surface",
    "depos.analysis.detectors.builtin.graph_anomaly",
    "depos.analysis.detectors.builtin.lexical_keyword_seed",
    "depos.analysis.detectors.builtin.dep_version_mismatch_across_workspaces",
    "depos.analysis.detectors.builtin.lockfile_drift",
    "depos.analysis.detectors.builtin.peer_dep_unsatisfied",
    "depos.analysis.detectors.builtin.phantom_dep",
    "depos.analysis.detectors.builtin.unused_dep",
    "depos.analysis.detectors.builtin.vulnerable_dep",
    "depos.analysis.detectors.builtin.transitive_pin_conflict",
    "depos.analysis.detectors.builtin.env_var_referenced_but_undefined",
    "depos.analysis.detectors.builtin.env_var_defined_but_unused",
    "depos.analysis.detectors.builtin.env_var_typed_drift",
    "depos.analysis.detectors.builtin.next_route_protected_in_middleware_but_not_layout",
    "depos.analysis.detectors.builtin.cors_origin_omits_known_client_origin",
    "depos.analysis.detectors.builtin.redirect_target_not_safelisted",
    "depos.analysis.detectors.builtin.prompt_missing_required_field",
    "depos.analysis.detectors.builtin.prompt_field_type_mismatch",
    "depos.analysis.detectors.builtin.prompt_references_undefined_variable",
    "depos.analysis.detectors.builtin.prompt_drift_between_provider_versions",
    "depos.analysis.detectors.builtin.request_body_missing_required_field",
    "depos.analysis.detectors.builtin.response_field_consumed_but_not_produced",
    "depos.analysis.detectors.builtin.enum_value_used_but_not_in_schema",
    "depos.analysis.detectors.builtin.migration_adds_not_null_without_default",
    "depos.analysis.detectors.builtin.route_without_session_check",
    "depos.analysis.detectors.builtin.rpc_invoked_without_rls_or_service_role",
    "depos.analysis.detectors.builtin.password_reset_link_handler_redirects_to_external_origin",
    "depos.analysis.detectors.builtin.cookie_set_without_httponly_or_secure_in_prod",
    "depos.analysis.detectors.builtin.error_swallowed_in_async_handler",
    "depos.analysis.detectors.builtin.awaitable_returned_unawaited",
    "depos.analysis.detectors.builtin.transaction_started_but_not_committed_on_all_branches",
    "depos.analysis.detectors.builtin.dockerfile_copies_path_not_in_build_context",
    "depos.analysis.detectors.builtin.gha_workflow_uses_secret_not_declared",
    "depos.analysis.detectors.builtin.gha_matrix_node_version_diverges_from_engines",
    "depos.analysis.detectors.builtin.compose_service_depends_on_service_with_different_network",
    "depos.analysis.detectors.builtin.group_a_graph_detectors",
    "depos.analysis.detectors.builtin.group_b_cfg_detectors",
    "depos.analysis.detectors.builtin.group_c_taint_dfg_detectors",
]


def register(spec: Detector, runner: DetectorRunner) -> None:
    REGISTRY[spec.name] = (spec, runner)


def load_builtin() -> None:
    global _BUILTINS_LOADED
    if _BUILTINS_LOADED:
        return
    for module_name in _BUILTIN_MODULES:
        importlib.import_module(module_name)
    _BUILTINS_LOADED = True


def list_detectors() -> list[Detector]:
    load_builtin()
    return [spec for spec, _ in REGISTRY.values()]


def get_detector(name: str) -> Detector:
    load_builtin()
    spec, _ = REGISTRY[name]
    return spec


def _enrich_candidate_score_from_context(
    graph: nx.DiGraph,
    run_context: RunContext,
    candidate: Candidate,
    *,
    mode: Any,
    config: Any,
) -> None:
    gm = run_context.graph_metrics
    if gm is None or not getattr(gm, "_computed", False):
        return
    sid = candidate.scope_id
    candidate.score.structural_centrality = float(gm.node_pagerank.get(sid, 0.0))
    candidate.score.blast_radius_norm = min(1.0, float(gm.fan_in.get(sid, 0)) / 50.0)
    present = False
    for raw in list(graph.graph.get("taint_edges", []) or []):
        te = raw if isinstance(raw, TaintEdge) else TaintEdge.model_validate(raw)
        if te.source_node == sid or te.sink_node == sid:
            present = True
            break
    candidate.score.taint_chain_present = present
    apply_composite(candidate.score, mode=mode, config=config)


def _wrap_candidate(
    spec: Detector,
    candidate: Candidate,
    *,
    policy: DetectorPolicy,
    mode: Any,
    config: Any,
) -> Candidate:
    from depos.analysis.schemas import RankingMetadata, SeedType
    
    raw = dict(candidate.detector_payload.raw)
    extra_oh = raw.pop("oracle_hints", None)
    hints = dict(candidate.detector_payload.oracle_hints)
    if isinstance(extra_oh, dict):
        hints.update({str(k): v for k, v in extra_oh.items()})
    severity = str(policy.severity_for(spec))
    
    # Fix 2: Preserve detector_name for graph-anomaly candidates from Group C detectors
    # Group C detectors (taint-based) mark candidates with "group": "C" in raw dict
    # Store attack pattern labels in ranking_metadata.matched_pattern instead
    is_group_c = raw.get("group") == "C"
    if candidate.seed_type == SeedType.graph_anomaly and is_group_c:
        # Preserve original detector identity as "graph-anomaly"
        detector_name = "graph-anomaly"
        # Store the attack pattern (spec.name) in ranking_metadata
        candidate.ranking_metadata = RankingMetadata(matched_pattern=spec.name)
    else:
        # Non-Group-C detectors: use spec.name as detector_name (existing behavior)
        detector_name = spec.name
    
    candidate.detector_payload = DetectorPayload(
        category=spec.name,
        detector_name=detector_name,
        detector_version=spec.version,
        pipeline_version=PIPELINE_VERSION,
        severity=severity,
        oracle_hints=hints,
        requires_cfg=candidate.detector_payload.requires_cfg,
        requires_dfg=candidate.detector_payload.requires_dfg,
        raw=raw,
    )
    apply_composite(candidate.score, mode=mode, config=config, severity=severity)
    return candidate


def _dedup(candidates: list[Candidate]) -> list[Candidate]:
    seen: dict[tuple[str, tuple[str, ...], tuple[str, ...]], Candidate] = {}
    for cand in candidates:
        seam_ids = tuple(sorted(e.edge_id for e in cand.seam_edges))
        key = (
            cand.scope_id,
            seam_ids,
            tuple(sorted(cand.diff_anchors)),
        )
        previous = seen.get(key)
        if previous is None or cand.score.composite > previous.score.composite:
            seen[key] = cand
    return list(seen.values())


def _prioritize(candidates: list[Candidate], budget: int) -> list[Candidate]:
    ordered = sorted(candidates, key=lambda c: (-c.score.composite, c.candidate_id))
    return ordered[:budget]


def run_all(
    graph,
    manifest,
    mode,
    config,
    policy=None,
    *,
    run_context: RunContext,
    repo_root: Optional[Path] = None,
) -> tuple[list[Candidate], list[DetectorRunStats]]:
    if run_context is None:
        raise RuntimeError(
            "RunContext must be present in ctx before run_all is called. "
            "Build it once in pipeline.py and pass it through."
        )
    load_builtin()
    resolved_policy = load_policy(policy)
    pool: list[Candidate] = []
    stats: list[DetectorRunStats] = []
    for spec in sorted((row[0] for row in REGISTRY.values()), key=lambda s: s.name):
        if not resolved_policy.is_enabled(spec):
            continue
        if spec.semantic_requirement is not None and next(
            iter_eligible_scopes(graph, run_context, spec), None
        ) is None:
            continue
        _, runner = REGISTRY[spec.name]
        started = time.perf_counter()
        errors: list[dict[str, Any]] = []
        emitted: list[Candidate] = []
        try:
            emitted = runner(
                graph,
                manifest,
                mode,
                config,
                {
                    "detector": spec,
                    "policy": resolved_policy,
                    "pipeline_version": PIPELINE_VERSION,
                    "run_context": run_context,
                },
            )
        except Exception as exc:  # noqa: BLE001
            errors.append({"kind": "detector_error", "message": str(exc)})
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        for candidate in emitted:
            _enrich_candidate_score_from_context(
                graph, run_context, candidate, mode=mode, config=config
            )
            pool.append(
                _wrap_candidate(
                    spec,
                    candidate,
                    policy=resolved_policy,
                    mode=mode,
                    config=config,
                )
            )
        stats.append(
            DetectorRunStats(
                run_id="",
                detector_name=spec.name,
                detector_version=spec.version,
                candidates_emitted=len(emitted),
                mean_latency_ms=round(elapsed_ms, 3),
                errors=errors,
            )
        )
    deduped = _dedup(pool)
    return _prioritize(deduped, config.candidates.max_seeds), stats


__all__ = [
    "PIPELINE_VERSION",
    "REGISTRY",
    "get_detector",
    "list_detectors",
    "load_builtin",
    "register",
    "run_all",
]
