from __future__ import annotations

import logging

from depos.analysis.candidate_identifier import _graph_anomaly_candidates
from depos.analysis.detectors import register
from depos.analysis.detectors.builtin.common import simple_spec
from depos.analysis.schemas import AnalysisMode, Universe


logger = logging.getLogger(__name__)


SPEC = simple_spec(
    name="graph-anomaly",
    universe=Universe.code,
    verifier_checks=["graph_path_exists", "negation_witness"],
    requires_reasoner=True,
    severity="medium",
    semantic_requirement=None,)


def run(graph, manifest, mode, config, ctx):
    run_metadata = graph.graph.get("run_metadata") or {}
    coverage = run_metadata.get("coverage") or {}
    coverage_ratio = coverage.get("coverage_ratio")
    low_stitcher_coverage = bool(run_metadata.get("low_stitcher_coverage"))

    if not low_stitcher_coverage:
        try:
            low_stitcher_coverage = float(coverage_ratio) < float(config.low_stitcher_coverage_threshold)
        except (TypeError, ValueError):
            low_stitcher_coverage = False

    if mode == AnalysisMode.full_repo_scan and low_stitcher_coverage:
        logger.info(
            "graph_anomaly_suppressed_low_stitcher_coverage mode=%s threshold=%s coverage_ratio=%s",
            mode.value,
            config.low_stitcher_coverage_threshold,
            coverage_ratio,
        )
        return []

    return _graph_anomaly_candidates(graph, mode)


register(SPEC, run)
