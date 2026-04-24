from __future__ import annotations

import contextlib
import json
from pathlib import Path
from types import SimpleNamespace

import networkx as nx

from depos.analysis.config import IntelligenceConfig, load_config_from_env
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
)
from depos.cli.analyze import _write_run_summary


def _candidate(candidate_id: str, detector_name: str = "graph_anomaly") -> Candidate:
    return Candidate(
        candidate_id=candidate_id,
        scope_id=f"scope:{candidate_id}",
        seed_type="graph_anomaly",
        score=CandidateScore(seam_exposure=0.8, composite=0.9),
        detector_payload=DetectorPayload(
            detector_name=detector_name,
            detector_version="1",
            pipeline_version="2.0.0",
        ),
    )


def _bundle(candidate: Candidate, evidence_score: float = 1.0) -> ContextBundle:
    return ContextBundle(
        bundle_id=f"bundle:{candidate.candidate_id}",
        candidate_id=candidate.candidate_id,
        scope_id=candidate.scope_id,
        pack_manifest=PackManifest(manifest_id=f"pack:{candidate.candidate_id}"),
        evidence=BundleEvidence(snippet_count=1, snippets_full=1, evidence_score=evidence_score),
    )


def _run_policy_pipeline(
    tmp_path: Path,
    monkeypatch,
    config: IntelligenceConfig,
    candidates: list[Candidate],
    *,
    evidence_scores: dict[str, float] | None = None,
    provider_calls: list[str] | None = None,
):
    graph = nx.DiGraph()
    manifest = ChangeManifest(resolved_via="test")
    evidence_scores = evidence_scores or {}
    provider_calls = provider_calls if provider_calls is not None else []

    monkeypatch.setattr("depos.analysis.pipeline._prepare_run_metadata", lambda *args, **kwargs: None)
    monkeypatch.setattr("depos.analysis.pipeline.resolve_change_manifest", lambda *args, **kwargs: manifest)
    monkeypatch.setattr("depos.analysis.pipeline.build_run_context", lambda *args, **kwargs: object())
    monkeypatch.setattr(
        "depos.analysis.pipeline.identify_candidates",
        lambda *args, **kwargs: (candidates, manifest, []),
    )
    monkeypatch.setattr(
        "depos.analysis.pipeline.build_bundle",
        lambda _graph, candidate, **kwargs: _bundle(
            candidate,
            evidence_scores.get(candidate.candidate_id, 1.0),
        ),
    )
    monkeypatch.setattr(
        "depos.analysis.pipeline.get_detector",
        lambda name: SimpleNamespace(requires_reasoner=True, semantic_requirement=None),
    )
    monkeypatch.setattr(
        "depos.analysis.pipeline.run_all_modes",
        lambda bundle, **kwargs: provider_calls.append(bundle.candidate_id) or {},
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

    return run_modules_2_through_7(
        graph,
        config=config,
        run_meta=RunMetadata(
            run_id="reasoner-policy-test",
            analysis_mode=AnalysisMode.full_repo_scan,
            provider=config.llm.provider,
        ),
        repo_root=tmp_path,
    )


def test_detector_disabled_policy_skips_reasoner_and_preserves_candidate(tmp_path: Path, monkeypatch) -> None:
    config = IntelligenceConfig(data_dir=tmp_path / "data")
    config.reasoner_policy.disabled_detectors = {"graph_anomaly"}
    calls: list[str] = []

    result = _run_policy_pipeline(
        tmp_path,
        monkeypatch,
        config,
        [_candidate("cand-1")],
        provider_calls=calls,
    )

    assert calls == []
    assert [candidate.candidate_id for candidate in result.candidates] == ["cand-1"]
    assert result.bundle_trace[0].skipped_reason == "detector_policy_disabled"
    assert result.bundle_trace[0].reasoner_skip_reason == "detector_policy_disabled"
    attempts_path = tmp_path / "data" / config.run_output_subdir / "reasoner-policy-test" / "reasoner_attempts.jsonl"
    assert not attempts_path.exists()


def test_detector_min_evidence_policy_records_threshold_detail(tmp_path: Path, monkeypatch) -> None:
    config = IntelligenceConfig(data_dir=tmp_path / "data")
    config.reasoner_policy.min_evidence_by_detector = {"graph_anomaly": 0.45}
    calls: list[str] = []

    result = _run_policy_pipeline(
        tmp_path,
        monkeypatch,
        config,
        [_candidate("cand-1")],
        evidence_scores={"cand-1": 0.4333},
        provider_calls=calls,
    )

    assert calls == []
    trace = result.bundle_trace[0]
    assert trace.skipped_reason == "detector_policy_min_evidence"
    assert trace.reasoner_skip_detail["threshold"] == 0.45
    assert trace.reasoner_skip_detail["evidence_score"] == 0.4333
    assert result.run_metadata.reasoner_policy_summary["skipped_by_detector"]["graph_anomaly"]["detector_policy_min_evidence"] == 1


def test_detector_max_candidates_policy_caps_reasoner_sends(tmp_path: Path, monkeypatch) -> None:
    config = IntelligenceConfig(data_dir=tmp_path / "data")
    config.reasoner_policy.max_candidates_by_detector = {"graph_anomaly": 1}
    calls: list[str] = []

    result = _run_policy_pipeline(
        tmp_path,
        monkeypatch,
        config,
        [_candidate("cand-1"), _candidate("cand-2")],
        provider_calls=calls,
    )

    assert calls == ["cand-1"]
    assert result.bundle_trace[0].skipped_reason == ""
    assert result.bundle_trace[1].skipped_reason == "detector_policy_max_candidates"
    assert result.run_metadata.reasoner_policy_summary["sent_to_reasoner_by_detector"]["graph_anomaly"] == 1


def test_invalid_reasoner_policy_env_entries_warn_and_are_ignored(monkeypatch, caplog) -> None:
    monkeypatch.setenv(
        "DEPOS_REASONER_MIN_EVIDENCE_BY_DETECTOR",
        "graph_anomaly:notfloat, graph_anomaly:-1, malformed",
    )
    monkeypatch.setenv(
        "DEPOS_REASONER_MAX_CANDIDATES_BY_DETECTOR",
        "graph_anomaly:notint, graph_anomaly:-1, malformed",
    )

    config = load_config_from_env()

    assert config.reasoner_policy.min_evidence_by_detector == {}
    assert config.reasoner_policy.max_candidates_by_detector == {}
    assert "Ignoring" in caplog.text


def test_detector_threshold_overrides_global_min_evidence_for_matching_detector(tmp_path: Path, monkeypatch) -> None:
    config = IntelligenceConfig(data_dir=tmp_path / "data")
    config.bundles.min_evidence_score_for_reasoner = 0.5
    config.reasoner_policy.min_evidence_by_detector = {"graph_anomaly": 0.45}
    calls: list[str] = []

    result = _run_policy_pipeline(
        tmp_path,
        monkeypatch,
        config,
        [_candidate("cand-1"), _candidate("cand-2", detector_name="other-detector")],
        evidence_scores={"cand-1": 0.47, "cand-2": 0.47},
        provider_calls=calls,
    )

    assert calls == ["cand-1"]
    assert result.bundle_trace[0].skipped_reason == ""
    assert result.bundle_trace[1].skipped_reason == "low_evidence"


def test_slow_ollama_warning_is_recorded_in_run_summary(tmp_path: Path, monkeypatch) -> None:
    config = IntelligenceConfig(data_dir=tmp_path / "data")
    config.llm.provider = "ollama"
    config.bundles.min_evidence_score_for_reasoner = 0.0
    config.llm.default_max_tokens = 1000
    monkeypatch.setattr("depos.analysis.pipeline._validate_ollama_model", lambda *args, **kwargs: None)
    monkeypatch.setattr("depos.analysis.pipeline._preflight_ollama", lambda *args, **kwargs: None)

    result = _run_policy_pipeline(
        tmp_path,
        monkeypatch,
        config,
        [_candidate(f"cand-{idx}") for idx in range(11)],
    )
    summary = _write_run_summary(
        tmp_path / "run_summary.json",
        result=result,
    )

    warnings = summary["reasoner_policy_summary"]["warnings"]
    assert warnings
    assert "DEPOS_REASONER_MAX_CANDIDATES_BY_DETECTOR=graph_anomaly:5" in warnings[0]


def test_policy_skipped_candidates_do_not_emit_reasoner_attempts(tmp_path: Path, monkeypatch) -> None:
    config = IntelligenceConfig(data_dir=tmp_path / "data")
    config.reasoner_policy.disabled_detectors = {"graph_anomaly"}

    _run_policy_pipeline(
        tmp_path,
        monkeypatch,
        config,
        [_candidate("cand-1")],
    )

    run_dir = tmp_path / "data" / config.run_output_subdir / "reasoner-policy-test"
    assert not (run_dir / "reasoner_attempts.jsonl").exists()
    assert not (run_dir / "reasoner_queue.jsonl").exists()
