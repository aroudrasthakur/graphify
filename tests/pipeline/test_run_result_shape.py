from __future__ import annotations

import contextlib
import json
from pathlib import Path
from types import SimpleNamespace

import networkx as nx

from depos.analysis.config import IntelligenceConfig
from depos.analysis.pipeline import run_modules_2_through_7
from depos.analysis.schemas import (
    AnalysisMode,
    BundleEvidence,
    Candidate,
    CandidateScore,
    ChangeManifest,
    ContextBundle,
    DetectorPayload,
    Finding,
    PackManifest,
    ReasonerMode,
    RunMetadata,
    SeedType,
    TaintEdge,
    VerifierAuditEntry,
    VerifierCheckResult,
    VerifierOutcome,
)
from depos.enrichment.semantic_edges import enrich_graph


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_run_result_contains_detector_and_ingest_metadata(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    _write(repo_root / ".env", "APP_URL=https://example.com\n")
    _write(repo_root / "apps" / "web" / "package.json", json.dumps({"dependencies": {"react": "^18.2.0"}}, indent=2))
    _write(repo_root / "packages" / "ui" / "package.json", json.dumps({"dependencies": {"react": "^17.0.0"}}, indent=2))
    page = repo_root / "apps" / "web" / "app" / "page.tsx"
    _write(page, "export default function Page() { return process.env.MISSING_SECRET; }\n")

    graph = nx.DiGraph()
    graph.add_node("code::page", label="Page", source_file=str(page))

    config = IntelligenceConfig(data_dir=tmp_path / "depos-data")
    enriched, coverage = enrich_graph(graph, config=config, repo_root=repo_root)
    result = run_modules_2_through_7(
        enriched,
        config=config,
        run_meta=RunMetadata(
            run_id="detector-run-result",
            analysis_mode=AnalysisMode.full_repo_scan,
            provider="stub",
            stitcher_coverage=coverage,
            low_stitcher_coverage=coverage.low_coverage,
        ),
        repo_root=repo_root,
    )

    detector_names = {finding.detector_name for finding in result.findings}
    report_modules = {report.module for report in result.ingest_reports}
    stat_names = {stat.detector_name for stat in result.detector_stats if stat.candidates_emitted > 0}

    assert "dep-version-mismatch-across-workspaces" in detector_names
    assert "env-var-referenced-but-undefined" in detector_names
    assert "depos.ingest.manifests" in report_modules
    assert "depos.ingest.env_config" in report_modules
    assert "dep-version-mismatch-across-workspaces" in stat_names
    assert "env-var-referenced-but-undefined" in stat_names
    assert result.run_metadata.pipeline_version == "2.0.0"
    assert {universe.value for universe in result.run_metadata.universes_present} >= {"code", "deps", "env"}


def test_pipeline_preflights_ollama_before_candidate_processing(tmp_path: Path, monkeypatch) -> None:
    graph = nx.DiGraph()
    config = IntelligenceConfig(data_dir=tmp_path / "depos-data")
    config.llm.provider = "ollama"
    config.llm.ollama_host = "http://localhost:11434"
    config.llm.ollama_model = "gemma:2b"

    manifest = ChangeManifest(resolved_via="test")
    calls: list[tuple] = []

    monkeypatch.setattr("depos.analysis.pipeline._prepare_run_metadata", lambda *args, **kwargs: None)
    monkeypatch.setattr("depos.analysis.pipeline.resolve_change_manifest", lambda *args, **kwargs: manifest)
    monkeypatch.setattr("depos.analysis.pipeline.build_run_context", lambda *args, **kwargs: object())
    monkeypatch.setattr(
        "depos.analysis.pipeline._validate_ollama_model",
        lambda base_url, model: calls.append(("validate", base_url, model)),
    )
    monkeypatch.setattr(
        "depos.analysis.pipeline._preflight_ollama",
        lambda base_url, model, timeout: calls.append(("preflight", base_url, model, timeout)),
    )
    monkeypatch.setattr(
        "depos.analysis.pipeline.identify_candidates",
        lambda *args, **kwargs: ([], manifest, []),
    )
    monkeypatch.setattr(
        "depos.analysis.pipeline.timed_stage",
        lambda *args, **kwargs: contextlib.nullcontext(),
    )

    result = run_modules_2_through_7(
        graph,
        config=config,
        run_meta=RunMetadata(
            run_id="ollama-preflight",
            analysis_mode=AnalysisMode.full_repo_scan,
            provider="ollama",
        ),
        repo_root=tmp_path,
    )

    assert result.candidates == []
    assert calls == [
        ("validate", "http://localhost:11434", "gemma:2b"),
        ("preflight", "http://localhost:11434", "gemma:2b", config.llm.ollama_preflight_timeout),
    ]


def test_pipeline_skips_reasoner_for_deterministic_taint_candidate(tmp_path: Path, monkeypatch) -> None:
    graph = nx.DiGraph()
    config = IntelligenceConfig(data_dir=tmp_path / "depos-data")
    manifest = ChangeManifest(resolved_via="test")
    candidate = Candidate(
        candidate_id="cand-deterministic",
        scope_id="node:scope",
        seed_type=SeedType.graph_anomaly,
        score=CandidateScore(
            taint_chain_present=True,
            seam_exposure=0.6,
            composite=0.9,
        ),
        detector_payload=DetectorPayload(
            detector_name="reasoner-candidate",
            detector_version="1",
            pipeline_version="2.0.0",
        ),
    )
    bundle = ContextBundle(
        bundle_id="bundle-deterministic",
        candidate_id=candidate.candidate_id,
        scope_id=candidate.scope_id,
        pack_manifest=PackManifest(manifest_id="pack-deterministic"),
        taint_edges=[
            TaintEdge(
                source_node="input",
                sink_node="sink",
                intermediate_path=["input", "sink"],
                scope="scope",
            )
        ],
    )

    verify_calls: list[bool] = []

    monkeypatch.setattr("depos.analysis.pipeline._prepare_run_metadata", lambda *args, **kwargs: None)
    monkeypatch.setattr("depos.analysis.pipeline.resolve_change_manifest", lambda *args, **kwargs: manifest)
    monkeypatch.setattr("depos.analysis.pipeline.build_run_context", lambda *args, **kwargs: object())
    monkeypatch.setattr(
        "depos.analysis.pipeline.identify_candidates",
        lambda *args, **kwargs: ([candidate], manifest, []),
    )
    monkeypatch.setattr("depos.analysis.pipeline.build_bundle", lambda *args, **kwargs: bundle)
    monkeypatch.setattr(
        "depos.analysis.pipeline.get_detector",
        lambda name: SimpleNamespace(requires_reasoner=True, semantic_requirement=None),
    )
    monkeypatch.setattr(
        "depos.analysis.pipeline.run_all_modes",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("reasoner should be skipped")),
    )
    monkeypatch.setattr(
        "depos.analysis.pipeline.verify_all",
        lambda *, deterministic_only, **kwargs: (
            verify_calls.append(deterministic_only) or [
                VerifierAuditEntry(
                    finding_id="cand-deterministic:na:test",
                    verifier_outcome=VerifierOutcome.partially_confirmed,
                    checks_run=[VerifierCheckResult(name="graph_path_exists", result="pass")],
                    pack_manifest_id="pack-deterministic",
                )
            ],
            [
                Finding(
                    finding_id="cand-deterministic:na:test",
                    trust_level=VerifierOutcome.partially_confirmed,
                    verifier_outcome=VerifierOutcome.partially_confirmed,
                    bug_type="test",
                    description="deterministic fallback",
                    pack_manifest_id="pack-deterministic",
                    detector_name="reasoner-candidate",
                    detector_version="1",
                    pipeline_version="2.0.0",
                )
            ],
        ),
    )
    monkeypatch.setattr("depos.analysis.pipeline.rank", lambda *args, **kwargs: [])
    monkeypatch.setattr("depos.analysis.pipeline.serialize_examples", lambda *args, **kwargs: None)
    monkeypatch.setattr("depos.analysis.pipeline.evaluate_gray_zone", lambda *args, **kwargs: [])
    monkeypatch.setattr("depos.analysis.pipeline.persist_gray_zone", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        "depos.analysis.pipeline.timed_stage",
        lambda *args, **kwargs: contextlib.nullcontext(),
    )

    result = run_modules_2_through_7(
        graph,
        config=config,
        run_meta=RunMetadata(
            run_id="deterministic-skip",
            analysis_mode=AnalysisMode.full_repo_scan,
            provider="stub",
        ),
        repo_root=tmp_path,
    )

    assert verify_calls == [True]
    assert len(result.findings) == 1
    assert result.evidence_summary["bundles_skipped_deterministic_reasoner"] == 1
    assert result.bundle_trace[0].skipped_reason == "deterministic_gate"


def test_pipeline_routes_taint_reasoner_candidates_to_mode_c_only(tmp_path: Path, monkeypatch) -> None:
    graph = nx.DiGraph()
    config = IntelligenceConfig(data_dir=tmp_path / "depos-data")
    manifest = ChangeManifest(resolved_via="test")
    candidate = Candidate(
        candidate_id="cand-mode-c",
        scope_id="node:scope",
        seed_type=SeedType.graph_anomaly,
        score=CandidateScore(
            seam_exposure=0.6,
            composite=0.9,
        ),
        detector_payload=DetectorPayload(
            detector_name="taint-reasoner-candidate",
            detector_version="1",
            pipeline_version="2.0.0",
        ),
    )
    bundle = ContextBundle(
        bundle_id="bundle-mode-c",
        candidate_id=candidate.candidate_id,
        scope_id=candidate.scope_id,
        pack_manifest=PackManifest(manifest_id="pack-mode-c"),
        evidence=BundleEvidence(
            snippet_count=1,
            snippets_full=1,
            evidence_score=1.0,
        ),
    )

    seen_modes: list[tuple[ReasonerMode, ...]] = []

    monkeypatch.setattr("depos.analysis.pipeline._prepare_run_metadata", lambda *args, **kwargs: None)
    monkeypatch.setattr("depos.analysis.pipeline.resolve_change_manifest", lambda *args, **kwargs: manifest)
    monkeypatch.setattr("depos.analysis.pipeline.build_run_context", lambda *args, **kwargs: object())
    monkeypatch.setattr(
        "depos.analysis.pipeline.identify_candidates",
        lambda *args, **kwargs: ([candidate], manifest, []),
    )
    monkeypatch.setattr("depos.analysis.pipeline.build_bundle", lambda *args, **kwargs: bundle)
    monkeypatch.setattr(
        "depos.analysis.pipeline.get_detector",
        lambda name: SimpleNamespace(requires_reasoner=True, semantic_requirement="taint"),
    )
    monkeypatch.setattr(
        "depos.analysis.pipeline.run_all_modes",
        lambda *args, modes, **kwargs: seen_modes.append(tuple(modes)) or {},
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

    run_modules_2_through_7(
        graph,
        config=config,
        run_meta=RunMetadata(
            run_id="taint-mode-c-only",
            analysis_mode=AnalysisMode.full_repo_scan,
            provider="stub",
        ),
        repo_root=tmp_path,
    )

    assert seen_modes == [(ReasonerMode.C,)]
