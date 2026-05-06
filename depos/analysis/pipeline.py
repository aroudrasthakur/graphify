"""Pipeline that orchestrates Modules 2\u20137 against a Module 1 enriched graph.

Kept as a thin composition layer so each module is independently
testable. The CLI layer is responsible for writing user-facing outputs;
this module returns a :class:`RunResult` plus the side effects of
writing module-specific audit files (reasoner queue, gray-zone audit,
observability JSONL).
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Optional

import networkx as nx

from depos.analysis.candidate_identifier import identify_candidates, resolve_change_manifest
from depos.analysis.config import IntelligenceConfig, PerfConfig
from depos.analysis.run_context import build_run_context
from depos.analysis.context_bundle import build_bundle
from depos.analysis.detectors import PIPELINE_VERSION, get_detector, list_detectors, load_builtin
from depos.analysis.gray_zone_evaluator import evaluate as evaluate_gray_zone
from depos.analysis.gray_zone_evaluator import persist as persist_gray_zone
from depos.analysis.observability import emit_event, timed_stage
from depos.analysis.ranker import rank, serialize_examples
from depos.analysis.reasoning_engine import (
    ReasonerSession,
    _preflight_ollama,
    _validate_ollama_model,
    resolve_ollama_base_url,
    run_all_modes,
)
from depos.analysis.schemas import (
    AnalysisMode,
    BundleTraceEntry,
    Candidate,
    ContextBundle,
    Finding,
    IngestReport,
    PreselectionInfo,
    RankerDiffFeatures,
    RankerInput,
    ReasonerCallStats,
    ReasonerMode,
    RunResult,
    RunMetadata,
    Universe,
    VerifierOutcome,
)
from depos.analysis.verifier import SourceSnippetCache, verify_all, verify_staged


# Mirrors depos.analysis.context_bundle._QUALITY_RANK so we can compare bundle
# evidence quality without reaching into a private symbol.
_QUALITY_RANK = {"missing": 0, "label_only": 1, "embedded": 2, "full": 3}


def _dominant_quality(evidence) -> str:
    if evidence.snippets_full > 0:
        return "full"
    if evidence.snippets_embedded > 0:
        return "embedded"
    if evidence.snippets_label_only > 0:
        return "label_only"
    return "missing"


def _reasoner_health_reason(stats: ReasonerCallStats, bundles_sent: int) -> str:
    if bundles_sent == 0 or stats.attempts == 0:
        return "no_bundles_sent_to_reasoner" if bundles_sent == 0 else ""
    if stats.successes == 0:
        worst_reason = max(stats.by_reason.items(), key=lambda kv: kv[1])[0] if stats.by_reason else "unknown"
        return f"all_calls_failed:{worst_reason}"
    if stats.successes / stats.attempts < 0.5:
        worst_reason = max(stats.by_reason.items(), key=lambda kv: kv[1])[0] if stats.by_reason else "unknown"
        return f"majority_failed:{worst_reason}"
    return ""


def _detector_spec_for_candidate(candidate: Candidate):
    detector_name = str(candidate.detector_payload.detector_name or "legacy")
    if detector_name == "legacy":
        return None
    try:
        return get_detector(detector_name)
    except Exception as e:  # noqa: BLE001
        import logging
        logging.getLogger(__name__).warning("Failed to get detector '%s' for candidate: %s", detector_name, e)
        return None


def _needs_llm_reasoning(
    candidate: Candidate,
    bundle: ContextBundle,
    *,
    detector_spec=None,
) -> bool:
    spec = detector_spec if detector_spec is not None else _detector_spec_for_candidate(candidate)
    if spec is None or not bool(getattr(spec, "requires_reasoner", False)):
        return False

    # Group C taint evidence gating: auto-gray-zone candidates without taint evidence
    requirement = getattr(spec, "semantic_requirement", None) if spec is not None else None
    if requirement == "taint":
        # For Group C candidates, require non-empty taint_edges to proceed to LLM
        if not bundle.taint_edges_available or len(bundle.taint_edges) == 0:
            return False

    score = candidate.score
    if score.taint_chain_present and bundle.taint_edges:
        return False

    seam_risk = float(score.seam_exposure)
    if (
        getattr(spec, "semantic_requirement", None) is None
        and seam_risk < 0.3
        and not candidate.diff_anchors
        and float(score.composite) < 0.4
    ):
        return False

    return True


def _reasoner_modes_for_candidate(
    candidate: Candidate,
    *,
    detector_spec=None,
) -> tuple[ReasonerMode, ...]:
    spec = detector_spec if detector_spec is not None else _detector_spec_for_candidate(candidate)
    requirement = getattr(spec, "semantic_requirement", None) if spec is not None else None
    if requirement == "cfg":
        return (ReasonerMode.B,)
    if requirement in {"dfg", "taint"}:
        return (ReasonerMode.C,)
    return (ReasonerMode.A,)


def _detector_policy_value(mapping: dict[str, Any], detector_name: str) -> Any:
    if detector_name in mapping:
        return mapping[detector_name]
    normalized = detector_name.replace("-", "_")
    if normalized in mapping:
        return mapping[normalized]
    return None


def _detector_policy_contains(values: set[str], detector_name: str) -> bool:
    return detector_name in values or detector_name.replace("-", "_") in values


def _empty_reasoner_policy_summary(config: IntelligenceConfig) -> dict[str, Any]:
    return {
        "disabled_detectors": sorted(config.reasoner_policy.disabled_detectors),
        "min_evidence_by_detector": dict(sorted(config.reasoner_policy.min_evidence_by_detector.items())),
        "max_candidates_by_detector": dict(sorted(config.reasoner_policy.max_candidates_by_detector.items())),
        "skipped_by_reason": {
            "detector_policy_disabled": 0,
            "detector_policy_min_evidence": 0,
            "detector_policy_max_candidates": 0,
        },
        "skipped_by_detector": {},
        "sent_to_reasoner_by_detector": {},
        "warnings": [],
    }


def _record_policy_skip(
    summary: dict[str, Any],
    *,
    detector_name: str,
    reason: str,
) -> None:
    summary["skipped_by_reason"][reason] = summary["skipped_by_reason"].get(reason, 0) + 1
    by_detector = summary["skipped_by_detector"].setdefault(
        detector_name,
        {
            "detector_policy_disabled": 0,
            "detector_policy_min_evidence": 0,
            "detector_policy_max_candidates": 0,
        },
    )
    by_detector[reason] = by_detector.get(reason, 0) + 1


def _record_reasoner_sent(summary: dict[str, Any], *, detector_name: str) -> None:
    sent = summary["sent_to_reasoner_by_detector"]
    sent[detector_name] = sent.get(detector_name, 0) + 1


def _slow_ollama_warnings(
    *,
    config: IntelligenceConfig,
    selected_reasoner_candidate_count: int,
    bundles_sent_to_reasoner: int,
) -> list[str]:
    if (config.llm.provider or "").lower() != "ollama":
        return []
    triggers: list[str] = []
    if selected_reasoner_candidate_count > 10 or bundles_sent_to_reasoner > 10:
        triggers.append(
            f"{max(selected_reasoner_candidate_count, bundles_sent_to_reasoner)} candidates may be sent to local Ollama"
        )
    if float(config.bundles.min_evidence_score_for_reasoner) < 0.3:
        triggers.append(
            f"min_evidence_score_for_reasoner={config.bundles.min_evidence_score_for_reasoner:.2f}"
        )
    if int(config.llm.default_max_tokens) >= 1000:
        triggers.append(f"default_max_tokens={config.llm.default_max_tokens}")
    if not triggers:
        return []
    return [
        "Local Ollama bulk reasoning may be slow ("
        + "; ".join(triggers)
        + "). Consider DEPOS_INTEL_MIN_EVIDENCE_SCORE=0.3 or 0.45, "
        "DEPOS_REASONER_MIN_EVIDENCE_BY_DETECTOR=graph_anomaly:0.45, "
        "DEPOS_REASONER_MAX_CANDIDATES_BY_DETECTOR=graph_anomaly:5, a smaller output token budget, "
        "and reasoner_attempts.jsonl / reasoner_attempt_summary for timeout calibration. "
        "Keep Ollama concurrency at 1 unless the hardware supports parallel inference."
    ]


def _emit_progress(progress: Callable[[str], None] | None, message: str) -> None:
    if progress is not None:
        progress(message)


def _build_ranker_input(candidate, bundle) -> RankerInput:
    cross_lang = len(bundle.cross_language_seams)
    changed_nodes = len(candidate.diff_anchors) + len([c for c in bundle.call_chain_in if c.get("depth", 0) == 1])
    raw = candidate.detector_payload.raw
    unresolved = int(raw.get("unresolved_symbol_count", 0) or 0)
    removed_refs = int(raw.get("removed_entity_references", 0) or 0)
    oracle_hints = dict(candidate.detector_payload.oracle_hints or {})
    missing_guard_signals = int(oracle_hints.get("missing_guard_signals", raw.get("missing_guard_signals", 0)) or 0)
    comp = float(candidate.score.composite)
    features = RankerDiffFeatures(
        changed_nodes_on_path=changed_nodes,
        cross_lang_seams_on_path=cross_lang,
        unresolved_symbols=unresolved,
        removed_entities_referenced=removed_refs,
        missing_guard_signals=missing_guard_signals,
        candidate_score_composite=comp,
    )
    return RankerInput(
        candidate_id=candidate.candidate_id,
        candidate_path=candidate.diff_anchors,
        edge_sequence=[s.relation for s in bundle.cross_language_seams],
        node_attrs={},
        diff_features=features,
    )


def _load_ingest_reports(graph: nx.DiGraph) -> list[IngestReport]:
    rows = graph.graph.get("run_metadata", {}).get("ingest_reports") or []
    return [IngestReport.model_validate(row) for row in rows if isinstance(row, dict)]


def _universes_present(graph: nx.DiGraph) -> list[Universe]:
    seen = {Universe.code}
    for _, attrs in graph.nodes(data=True):
        raw = attrs.get("universe")
        if not raw:
            continue
        try:
            seen.add(Universe(str(raw)))
        except ValueError:
            continue
    return sorted(seen, key=lambda value: value.value)


def _prepare_run_metadata(
    graph: nx.DiGraph,
    *,
    run_meta: RunMetadata,
    detector_policy: dict[str, Any] | None,
) -> None:
    from depos.analysis.detectors.policy import load_policy

    load_builtin()
    policy = load_policy(detector_policy)
    run_meta.pipeline_version = PIPELINE_VERSION
    run_meta.detector_versions = {spec.name: spec.version for spec in list_detectors()}
    run_meta.enabled_detectors = sorted(policy.enabled) if policy.enabled else sorted(
        spec.name for spec in list_detectors() if spec.enabled_by_default and spec.name not in policy.disabled
    )
    run_meta.disabled_detectors = sorted(policy.disabled)
    run_meta.universes_present = _universes_present(graph)
    ingest_reports = _load_ingest_reports(graph)
    run_meta.ingest_errors = [error for report in ingest_reports for error in report.errors]
    extra_errors = graph.graph.get("run_metadata", {}).get("ingest_errors") or []
    run_meta.ingest_errors.extend(error for error in extra_errors if isinstance(error, dict))


def run_modules_2_through_7(
    graph: nx.DiGraph,
    *,
    config: IntelligenceConfig,
    run_meta: RunMetadata,
    diff_path: Optional[str] = None,
    repo_root: Optional[Path] = None,
    detector_policy: dict[str, Any] | None = None,
    bundle_limit: int | None = None,
    selected_limit: int | None = None,
    min_score: float | None = None,
    progress: Callable[[str], None] | None = None,
    perf: Optional[PerfConfig] = None,
) -> RunResult:
    mode = run_meta.analysis_mode
    _emit_progress(progress, f"Pipeline: preparing run metadata for {mode.value} mode.")
    _prepare_run_metadata(graph, run_meta=run_meta, detector_policy=detector_policy)
    _emit_progress(
        progress,
        f"Pipeline: enabled detectors={len(run_meta.enabled_detectors)} disabled={len(run_meta.disabled_detectors)} universes={','.join(u.value for u in run_meta.universes_present)}.",
    )

    # Module 2 \u2014 candidates
    _emit_progress(progress, "Module 2: resolving change manifest.")
    manifest = resolve_change_manifest(
        graph,
        diff_path=diff_path,
        repo_root=repo_root,
    )
    _emit_progress(progress, f"Module 2: manifest resolved via {manifest.resolved_via}.")
    _emit_progress(progress, "Module 2: running detectors.")
    with timed_stage(config, run_meta.run_id, "detector_run"):
        run_context = build_run_context(
            graph,
            manifest,
            run_id=run_meta.run_id,
            repo_root=repo_root,
            config=config,
            perf=perf,
        )
        if (config.llm.provider or "stub").lower() == "ollama":
            base_url = resolve_ollama_base_url(config.llm.ollama_host)
            _emit_progress(
                progress,
                f"Pipeline: validating Ollama model tag '{config.llm.ollama_model}'.",
            )
            _validate_ollama_model(base_url, config.llm.ollama_model)
            _emit_progress(
                progress,
                f"Pipeline: preflighting Ollama model '{config.llm.ollama_model}'.",
            )
            _preflight_ollama(
                base_url,
                config.llm.ollama_model,
                timeout=config.llm.ollama_preflight_timeout,
            )
        candidates, manifest, detector_stats = identify_candidates(
            graph,
            run_context=run_context,
            config=config,
            mode=mode,
            diff_path=diff_path,
            repo_root=repo_root,
            detector_policy=detector_policy,
        )
    _emit_progress(progress, f"Module 2: detectors emitted {len(candidates)} candidates.")
    if not candidates:
        run_meta.reasoner_policy_summary = _empty_reasoner_policy_summary(config)
        run_meta.preselection_info = PreselectionInfo(
            total_candidates=0,
            eligible_candidates=0,
            bundled_candidates=0,
            selected_candidates=0,
            min_score=min_score,
            bundle_limit=bundle_limit,
            selected_limit=selected_limit,
        )
        for stat in detector_stats:
            stat.run_id = run_meta.run_id
        _emit_progress(progress, "Pipeline: no candidates emitted; stopping after Module 2.")
        return RunResult(
            findings=[],
            detector_stats=detector_stats,
            ingest_reports=_load_ingest_reports(graph),
            run_metadata=run_meta,
            change_manifest=manifest,
            candidates=[],
            bundles=[],
            verifier_audits=[],
            gray_zone_rows=[],
            bundle_trace=[],
        )

    all_candidates = list(candidates)
    eligible_candidates = (
        [candidate for candidate in all_candidates if float(candidate.score.composite) >= float(min_score)]
        if min_score is not None
        else all_candidates
    )
    bundle_candidates = (
        eligible_candidates[: max(0, int(bundle_limit))]
        if bundle_limit is not None
        else eligible_candidates
    )
    selected_candidates = (
        bundle_candidates[: max(0, int(selected_limit))]
        if selected_limit is not None
        else bundle_candidates
    )
    run_meta.preselection_info = PreselectionInfo(
        total_candidates=len(all_candidates),
        eligible_candidates=len(eligible_candidates),
        bundled_candidates=len(bundle_candidates),
        selected_candidates=len(selected_candidates),
        min_score=min_score,
        bundle_limit=bundle_limit,
        selected_limit=selected_limit,
    )

    all_findings: list[Finding] = []
    all_audits = []
    gray_zone_inputs: list[tuple[Finding, Any, Any]] = []
    ranker_inputs: list[RankerInput] = []
    labels: dict[str, tuple[str, str]] = {}
    full_repo_scan = mode == AnalysisMode.full_repo_scan
    detector_stats_by_name = {row.detector_name: row for row in detector_stats}
    reasoner_stats = ReasonerCallStats()
    bundles_sent_to_reasoner = 0
    bundles_skipped_low_evidence = 0
    bundles_skipped_deterministic_reasoner = 0
    evidence_quality_counts: dict[str, int] = {"full": 0, "embedded": 0, "label_only": 0, "missing": 0}
    bundle_trace: list[BundleTraceEntry] = []
    reasoner_policy_summary = _empty_reasoner_policy_summary(config)
    reasoner_sent_by_detector: dict[str, int] = {}
    selected_reasoner_candidate_count = 0
    quality_floor_name = config.bundles.min_evidence_quality_for_reasoner
    quality_floor = _QUALITY_RANK.get(quality_floor_name, _QUALITY_RANK["embedded"])
    score_floor = float(config.bundles.min_evidence_score_for_reasoner)
    reasoner_session = ReasonerSession(config)
    source_cache = SourceSnippetCache()

    bundles = {}
    built_bundles = []
    _emit_progress(progress, f"Module 3: building {len(bundle_candidates)} context bundles.")
    perf = getattr(run_context, "perf", None)
    bundle_n_jobs = (
        max(1, int(getattr(perf, "bundle_n_jobs", 1) or 1)) if perf is not None else 1
    )
    with timed_stage(config, run_meta.run_id, "bundle_build", candidates=len(bundle_candidates)):
        if bundle_n_jobs <= 1 or len(bundle_candidates) <= 1:
            for candidate in bundle_candidates:
                bundle = build_bundle(
                    graph, candidate, config=config, run_context=run_context
                )
                bundles[candidate.candidate_id] = bundle
                built_bundles.append(bundle)
                quality = _dominant_quality(bundle.evidence)
                evidence_quality_counts[quality] = evidence_quality_counts.get(quality, 0) + 1
        else:
            max_workers = min(bundle_n_jobs, len(bundle_candidates))

            def _one(cand: Any) -> Any:
                return build_bundle(graph, cand, config=config, run_context=run_context)

            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                built_bundles = list(ex.map(_one, bundle_candidates))
            for candidate, bundle in zip(bundle_candidates, built_bundles, strict=True):
                bundles[candidate.candidate_id] = bundle
                quality = _dominant_quality(bundle.evidence)
                evidence_quality_counts[quality] = evidence_quality_counts.get(quality, 0) + 1
    _emit_progress(progress, f"Module 3: built {len(built_bundles)} bundles.")

    # Modules 3 \u2192 6 per-candidate.
    total_candidates = len(selected_candidates)
    for index, candidate in enumerate(selected_candidates, start=1):
        bundle = bundles[candidate.candidate_id]
        detector_name = str(candidate.detector_payload.detector_name or "legacy")
        _emit_progress(progress, f"Candidate {index}/{total_candidates}: detector={detector_name} candidate_id={candidate.candidate_id}.")
        spec = _detector_spec_for_candidate(candidate)
        requires_reasoner = bool(spec is not None and spec.requires_reasoner)
        selected_modes = _reasoner_modes_for_candidate(candidate, detector_spec=spec) if requires_reasoner else ()
        needs_llm_reasoning = _needs_llm_reasoning(
            candidate,
            bundle,
            detector_spec=spec,
        )
        reasoner_out = {}
        deterministic_only = False
        if requires_reasoner and not needs_llm_reasoning:
            deterministic_only = True
            bundles_skipped_deterministic_reasoner += 1
            
            # Determine skip reason: check if it's due to missing taint evidence for Group C
            requirement = getattr(spec, "semantic_requirement", None) if spec is not None else None
            skip_reason = "deterministic_gate"
            if requirement == "taint" and (not bundle.taint_edges_available or len(bundle.taint_edges) == 0):
                skip_reason = "missing_taint_evidence"
            
            _emit_progress(
                progress,
                f"Module 4: skipped reasoner for candidate {index}/{total_candidates} "
                f"(deterministic verifier gate: taint={candidate.score.taint_chain_present}, "
                f"seam_exposure={candidate.score.seam_exposure:.2f}, composite={candidate.score.composite:.2f}).",
            )
            bundle_trace.append(
                BundleTraceEntry(
                    bundle_id=bundle.bundle_id,
                    candidate_id=bundle.candidate_id,
                    detector_name=detector_name,
                    candidate_score_composite=float(candidate.score.composite),
                    reasoner_modes_returned=[],
                    findings=0,
                    skipped_reason=skip_reason,
                    reasoner_skipped=True,
                    reasoner_skip_reason=skip_reason,
                    reasoner_skip_detail={"policy_source": "semantic_requirement"},
                    evidence_quality=_dominant_quality(bundle.evidence),
                    evidence_score=float(bundle.evidence.evidence_score),
                    reasoner_attempts=0,
                    reasoner_successes=0,
                    reasoner_failures=0,
                )
            )
        elif requires_reasoner:
            evidence = bundle.evidence
            quality = _dominant_quality(evidence)
            detector_threshold = _detector_policy_value(
                config.reasoner_policy.min_evidence_by_detector,
                detector_name,
            )
            effective_score_floor = float(detector_threshold) if detector_threshold is not None else score_floor
            passes_quality = _QUALITY_RANK.get(quality, 0) >= quality_floor
            passes_score = evidence.evidence_score >= effective_score_floor
            if not (passes_quality and passes_score):
                skip_reason = "detector_policy_min_evidence" if detector_threshold is not None and passes_quality else "low_evidence"
                if skip_reason == "detector_policy_min_evidence":
                    _record_policy_skip(
                        reasoner_policy_summary,
                        detector_name=detector_name,
                        reason=skip_reason,
                    )
                    emit_event(
                        config,
                        run_meta.run_id,
                        "reasoner_policy_skip",
                        candidate_id=candidate.candidate_id,
                        detector_name=detector_name,
                        reasoner_skipped=True,
                        reasoner_skip_reason=skip_reason,
                        reasoner_skip_detail={
                            "evidence_score": float(evidence.evidence_score),
                            "threshold": effective_score_floor,
                            "policy_source": "DEPOS_REASONER_MIN_EVIDENCE_BY_DETECTOR",
                        },
                    )
                bundles_skipped_low_evidence += 1
                _emit_progress(
                    progress,
                    f"Module 4: skipped reasoner for candidate {index}/{total_candidates} "
                    f"(evidence_quality={quality}, score={evidence.evidence_score:.2f} "
                    f"< floor quality={quality_floor_name}/score={effective_score_floor:.2f}).",
                )
                bundle_trace.append(
                    BundleTraceEntry(
                        bundle_id=bundle.bundle_id,
                        candidate_id=bundle.candidate_id,
                        detector_name=detector_name,
                        candidate_score_composite=float(candidate.score.composite),
                        reasoner_modes_returned=[],
                        findings=0,
                        skipped_reason=skip_reason,
                        reasoner_skipped=True,
                        reasoner_skip_reason=skip_reason,
                        reasoner_skip_detail={
                            "evidence_score": float(evidence.evidence_score),
                            "threshold": effective_score_floor,
                            "policy_source": (
                                "DEPOS_REASONER_MIN_EVIDENCE_BY_DETECTOR"
                                if skip_reason == "detector_policy_min_evidence"
                                else "DEPOS_INTEL_MIN_EVIDENCE_SCORE"
                            ),
                            "evidence_quality": quality,
                            "quality_floor": quality_floor_name,
                        },
                        evidence_quality=quality,
                        evidence_score=float(evidence.evidence_score),
                        reasoner_attempts=0,
                        reasoner_successes=0,
                        reasoner_failures=0,
                    )
                )
            else:
                policy_skip_reason = ""
                policy_skip_detail: dict[str, Any] = {}
                if _detector_policy_contains(config.reasoner_policy.disabled_detectors, detector_name):
                    policy_skip_reason = "detector_policy_disabled"
                    policy_skip_detail = {
                        "policy_source": "DEPOS_REASONER_DISABLED_DETECTORS",
                    }
                detector_cap = _detector_policy_value(
                    config.reasoner_policy.max_candidates_by_detector,
                    detector_name,
                )
                sent_for_detector = reasoner_sent_by_detector.get(detector_name, 0)
                if not policy_skip_reason and detector_cap is not None and sent_for_detector >= int(detector_cap):
                    policy_skip_reason = "detector_policy_max_candidates"
                    policy_skip_detail = {
                        "sent_to_reasoner": sent_for_detector,
                        "max_candidates": int(detector_cap),
                        "policy_source": "DEPOS_REASONER_MAX_CANDIDATES_BY_DETECTOR",
                    }
                if policy_skip_reason:
                    _record_policy_skip(
                        reasoner_policy_summary,
                        detector_name=detector_name,
                        reason=policy_skip_reason,
                    )
                    emit_event(
                        config,
                        run_meta.run_id,
                        "reasoner_policy_skip",
                        candidate_id=candidate.candidate_id,
                        detector_name=detector_name,
                        reasoner_skipped=True,
                        reasoner_skip_reason=policy_skip_reason,
                        reasoner_skip_detail=policy_skip_detail,
                    )
                    _emit_progress(
                        progress,
                        f"Module 4: skipped reasoner for candidate {index}/{total_candidates} "
                        f"(detector policy: {policy_skip_reason}).",
                    )
                    bundle_trace.append(
                        BundleTraceEntry(
                            bundle_id=bundle.bundle_id,
                            candidate_id=bundle.candidate_id,
                            detector_name=detector_name,
                            candidate_score_composite=float(candidate.score.composite),
                            reasoner_modes_returned=[],
                            findings=0,
                            skipped_reason=policy_skip_reason,
                            reasoner_skipped=True,
                            reasoner_skip_reason=policy_skip_reason,
                            reasoner_skip_detail=policy_skip_detail,
                            evidence_quality=quality,
                            evidence_score=float(evidence.evidence_score),
                            reasoner_attempts=0,
                            reasoner_successes=0,
                            reasoner_failures=0,
                        )
                    )
                else:
                    selected_reasoner_candidate_count += 1
                    reasoner_sent_by_detector[detector_name] = sent_for_detector + 1
                    _record_reasoner_sent(reasoner_policy_summary, detector_name=detector_name)
                    bundles_sent_to_reasoner += 1
                    mode_labels = ",".join(mode.value for mode in selected_modes) or "-"
                    _emit_progress(
                        progress,
                        f"Module 4: running reasoner for candidate {index}/{total_candidates} (modes={mode_labels}).",
                    )
                    bundle_stats = ReasonerCallStats()
                    with timed_stage(config, run_meta.run_id, "reasoner_run", candidate_id=candidate.candidate_id):
                        reasoner_out = run_all_modes(
                            bundle,
                            config=config,
                            run_id=run_meta.run_id,
                            ranking_phase=run_meta.ranking_phase,
                            stats=bundle_stats,
                            session=reasoner_session,
                            modes=selected_modes,
                            detector_name=detector_name,
                        )
                    reasoner_stats.merge(bundle_stats)
                    failure_suffix = ""
                    if bundle_stats.failures > 0 and bundle_stats.by_reason:
                        top_reasons = sorted(
                            bundle_stats.by_reason.items(), key=lambda kv: (-kv[1], kv[0])
                        )
                        failure_suffix = (
                            " Failures: "
                            + ", ".join(f"{reason}={count}" for reason, count in top_reasons)
                            + "."
                        )
                    _emit_progress(
                        progress,
                        f"Module 4: reasoner returned {len(reasoner_out)} mode outputs for "
                        f"candidate {index}/{total_candidates} "
                        f"across {len(selected_modes)} selected mode(s) "
                        f"({bundle_stats.successes}/{bundle_stats.attempts} calls succeeded)."
                        + failure_suffix,
                    )
                    bundle_trace.append(
                        BundleTraceEntry(
                            bundle_id=bundle.bundle_id,
                            candidate_id=bundle.candidate_id,
                            detector_name=detector_name,
                            candidate_score_composite=float(candidate.score.composite),
                            reasoner_modes_returned=sorted(mode.value for mode in reasoner_out.keys()),
                            findings=0,
                            skipped_reason="",
                            evidence_quality=quality,
                            evidence_score=float(evidence.evidence_score),
                            reasoner_attempts=bundle_stats.attempts,
                            reasoner_successes=bundle_stats.successes,
                            reasoner_failures=bundle_stats.failures,
                        )
                    )
        else:
            _emit_progress(progress, f"Module 4: skipped reasoner for candidate {index}/{total_candidates} (mechanical detector).")
            bundle_trace.append(
                BundleTraceEntry(
                    bundle_id=bundle.bundle_id,
                    candidate_id=bundle.candidate_id,
                    detector_name=detector_name,
                    candidate_score_composite=float(candidate.score.composite),
                    reasoner_modes_returned=[],
                    findings=0,
                    skipped_reason="mechanical_detector",
                    reasoner_skipped=True,
                    reasoner_skip_reason="mechanical_detector",
                    reasoner_skip_detail={"policy_source": "detector_requires_reasoner"},
                    evidence_quality=_dominant_quality(bundle.evidence),
                    evidence_score=float(bundle.evidence.evidence_score),
                    reasoner_attempts=0,
                    reasoner_successes=0,
                    reasoner_failures=0,
                )
            )
        _emit_progress(progress, f"Module 6: verifying candidate {index}/{total_candidates}.")
        audits, findings = verify_all(
            candidate=candidate,
            bundle=bundle,
            reasoner_outputs=reasoner_out,
            config=config,
            full_repo_scan=full_repo_scan,
            deterministic_only=deterministic_only,
        )
        audits = verify_staged(audits, bundle=bundle, cache=source_cache)
        if bundle_trace:
            bundle_trace[-1].findings = len(findings)
        _emit_progress(progress, f"Module 6: candidate {index}/{total_candidates} produced {len(findings)} findings and {len(audits)} audits.")
        all_findings.extend(findings)
        all_audits.extend(audits)
        gray_zone_inputs.extend((finding, audit, bundle) for finding, audit in zip(findings, audits, strict=True))
        ranker_inputs.append(_build_ranker_input(candidate, bundle))
        stat = detector_stats_by_name.get(detector_name)
        if stat is not None:
            stat.verified_confirmed += sum(1 for audit in audits if audit.verifier_outcome == VerifierOutcome.confirmed)
            stat.verified_invalid += sum(1 for audit in audits if audit.verifier_outcome == VerifierOutcome.invalid_reasoning)
        # Derive label for ranker training data.
        if any(a.verifier_outcome == VerifierOutcome.confirmed for a in audits):
            labels[candidate.candidate_id] = ("suspicious", "verifier_confirmed")
        elif audits and all(a.verifier_outcome == VerifierOutcome.invalid_reasoning for a in audits):
            labels[candidate.candidate_id] = ("not_suspicious", "verifier_contradicted")

    # Module 5 is post-selection: it annotates findings/training rows and does
    # not choose the initial top-N candidate set.
    _emit_progress(progress, f"Module 5: ranking {len(ranker_inputs)} candidates and writing training rows.")
    scores = rank(ranker_inputs, config=config)
    score_map = {s.candidate_id: s for s in scores}
    for f in all_findings:
        candidate_id = f.finding_id.split(":", 1)[0]
        s = score_map.get(candidate_id)
        if s is not None:
            f.ranking_phase = s.ranking_phase
    serialize_examples(
        ranker_inputs,
        labels,
        config=config,
        run_id=run_meta.run_id,
        repo_id=run_meta.repo_id,
        base_ref=run_meta.base_ref,
        head_ref=run_meta.head_ref,
    )
    _emit_progress(progress, f"Module 5: serialized {len(scores)} rank rows.")

    # Module 7 \u2014 gray-zone evaluator.
    _emit_progress(progress, f"Module 7: evaluating gray-zone cases across {len(all_findings)} findings.")
    gray_rows = evaluate_gray_zone(
        gray_zone_inputs,
        config=config,
        run_id=run_meta.run_id,
        run_low_stitcher_coverage=run_meta.low_stitcher_coverage,
    )
    persist_gray_zone(gray_rows, config=config, run_id=run_meta.run_id)
    _emit_progress(progress, f"Module 7: wrote {len(gray_rows)} gray-zone audit rows.")

    for stat in detector_stats:
        stat.run_id = run_meta.run_id

    bundles_built = len(built_bundles)
    health = reasoner_stats.health()
    health_reason = _reasoner_health_reason(reasoner_stats, bundles_sent_to_reasoner)
    warnings = _slow_ollama_warnings(
        config=config,
        selected_reasoner_candidate_count=selected_reasoner_candidate_count,
        bundles_sent_to_reasoner=bundles_sent_to_reasoner,
    )
    reasoner_policy_summary["warnings"] = warnings
    for warning in warnings:
        _emit_progress(progress, f"Warning: {warning}")
        emit_event(config, run_meta.run_id, "reasoner_policy_warning", warning=warning)
    evidence_summary = {
        "bundles_built": bundles_built,
        "bundles_sent_to_reasoner": bundles_sent_to_reasoner,
        "bundles_skipped_low_evidence": bundles_skipped_low_evidence,
        "bundles_skipped_deterministic_reasoner": bundles_skipped_deterministic_reasoner,
        "by_quality": evidence_quality_counts,
        "min_evidence_quality_for_reasoner": quality_floor_name,
        "min_evidence_score_for_reasoner": score_floor,
    }
    run_meta.reasoner_call_stats = reasoner_stats
    run_meta.reasoner_run_health = health
    run_meta.reasoner_health_reason = health_reason
    run_meta.bundles_built = bundles_built
    run_meta.bundles_sent_to_reasoner = bundles_sent_to_reasoner
    run_meta.bundles_skipped_low_evidence = bundles_skipped_low_evidence
    run_meta.evidence_summary = evidence_summary
    run_meta.reasoner_policy_summary = reasoner_policy_summary

    result = RunResult(
        findings=all_findings,
        detector_stats=detector_stats,
        ingest_reports=_load_ingest_reports(graph),
        run_metadata=run_meta,
        reasoner_call_stats=reasoner_stats,
        evidence_summary=evidence_summary,
        change_manifest=manifest,
        candidates=all_candidates,
        bundles=built_bundles,
        verifier_audits=all_audits,
        gray_zone_rows=gray_rows,
        bundle_trace=bundle_trace,
    )
    _emit_progress(
        progress,
        f"Pipeline: completed with {len(all_findings)} findings. "
        f"reasoner_run_health={health} (attempts={reasoner_stats.attempts}, "
        f"successes={reasoner_stats.successes}, failures={reasoner_stats.failures}).",
    )
    return result


__all__ = ["run_modules_2_through_7"]
