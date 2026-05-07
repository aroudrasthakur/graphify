"""Bundle evidence_quality counts must match built bundles (serial vs parallel)."""
from __future__ import annotations

import contextlib
from pathlib import Path
from types import SimpleNamespace

import networkx as nx
import pytest

from depos.analysis.config import IntelligenceConfig, PerfConfig
from depos.analysis.pipeline import run_modules_2_through_7
from depos.analysis.schemas import (
    AnalysisMode,
    BundleEvidence,
    Candidate,
    CandidateScore,
    ChangeManifest,
    ContextBundle,
    DetectorPayload,
    PackManifest,
    RunMetadata,
    RunResult,
)


def _candidate(cid: str) -> Candidate:
    return Candidate(
        candidate_id=cid,
        scope_id=f"scope:{cid}",
        seed_type="graph_anomaly",
        score=CandidateScore(seam_exposure=0.8, composite=0.9),
        detector_payload=DetectorPayload(
            detector_name="graph_anomaly",
            detector_version="1",
            pipeline_version="2.0.0",
        ),
    )


def _bundle_for_candidate(candidate: Candidate) -> ContextBundle:
    """Rotate dominant evidence bucket by candidate id suffix."""
    tail = candidate.candidate_id[-1]
    if tail == "1":
        ev = BundleEvidence(snippet_count=1, snippets_full=1, evidence_score=1.0)
    elif tail == "2":
        ev = BundleEvidence(snippet_count=1, snippets_embedded=1, evidence_score=1.0)
    else:
        ev = BundleEvidence(snippet_count=1, snippets_label_only=1, evidence_score=1.0)
    return ContextBundle(
        bundle_id=f"bundle:{candidate.candidate_id}",
        candidate_id=candidate.candidate_id,
        scope_id=candidate.scope_id,
        pack_manifest=PackManifest(manifest_id=f"pack:{candidate.candidate_id}"),
        evidence=ev,
    )


def _stubbed_pipeline_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    bundle_n_jobs: int,
) -> RunResult:
    graph = nx.DiGraph()
    manifest = ChangeManifest(resolved_via="test")
    candidates = [_candidate("cand-1"), _candidate("cand-2"), _candidate("cand-3")]

    monkeypatch.setattr("depos.analysis.pipeline._prepare_run_metadata", lambda *args, **kwargs: None)
    monkeypatch.setattr("depos.analysis.pipeline.resolve_change_manifest", lambda *args, **kwargs: manifest)
    monkeypatch.setattr(
        "depos.analysis.pipeline.build_run_context",
        lambda *args, **kwargs: SimpleNamespace(
            perf=PerfConfig(bundle_n_jobs=bundle_n_jobs),
        ),
    )
    monkeypatch.setattr(
        "depos.analysis.pipeline.identify_candidates",
        lambda *args, **kwargs: (candidates, manifest, []),
    )
    monkeypatch.setattr(
        "depos.analysis.pipeline.build_bundle",
        lambda _g, cand, **kwargs: _bundle_for_candidate(cand),
    )
    monkeypatch.setattr(
        "depos.analysis.pipeline.resolve_detector_spec",
        lambda candidate: SimpleNamespace(requires_reasoner=True, semantic_requirement=None),
    )
    monkeypatch.setattr(
        "depos.analysis.pipeline.run_all_modes",
        lambda bundle, **kwargs: {},
    )
    monkeypatch.setattr("depos.analysis.pipeline.verify_all", lambda **kwargs: ([], []))
    monkeypatch.setattr("depos.analysis.pipeline.rank", lambda *args, **kwargs: [])
    monkeypatch.setattr("depos.analysis.pipeline.serialize_examples", lambda *args, **kwargs: None)
    monkeypatch.setattr("depos.analysis.pipeline.evaluate_gray_zone", lambda *args, **kwargs: [])
    monkeypatch.setattr("depos.analysis.pipeline.persist_gray_zone", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        "depos.analysis.pipeline.timed_stage",
        lambda *args, **kwargs: contextlib.nullcontext(),
    )

    config = IntelligenceConfig(data_dir=tmp_path / "data")
    return run_modules_2_through_7(
        graph,
        config=config,
        run_meta=RunMetadata(
            run_id=f"evidence-acct-{bundle_n_jobs}",
            analysis_mode=AnalysisMode.full_repo_scan,
            provider=config.llm.provider,
        ),
        repo_root=tmp_path,
        perf=PerfConfig(bundle_n_jobs=bundle_n_jobs),
    )


@pytest.mark.parametrize("bundle_n_jobs", [1, 4])
def test_evidence_by_quality_sums_to_bundle_count(tmp_path: Path, monkeypatch, bundle_n_jobs: int) -> None:
    result = _stubbed_pipeline_run(tmp_path, monkeypatch, bundle_n_jobs=bundle_n_jobs)
    by_quality = result.evidence_summary["by_quality"]
    total = sum(by_quality.values())
    assert total == len(result.bundles) == 3
    assert by_quality["full"] == 1
    assert by_quality["embedded"] == 1
    assert by_quality["label_only"] == 1
    assert by_quality["missing"] == 0
