"""run_manifest.json contract for repo/diff outputs."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from depos.analysis.config import IntelligenceConfig
from depos.analysis.schemas import AnalysisMode, RunMetadata, RunResult
from depos.cli import analyze as analyze_cli
from depos.graph_source import GraphifySource
from depos.output.run_manifest import RUN_MANIFEST_FILENAME, RUN_MANIFEST_SCHEMA_VERSION


def test_run_manifest_written_after_repo_run(monkeypatch, tmp_path: Path) -> None:
    fixture = Path(__file__).parent / "fixtures" / "acceptance_01_http_route.json"
    assert fixture.exists()

    cfg = IntelligenceConfig(data_dir=tmp_path)

    def fake_pipeline(source, config, run_meta, **kwargs):
        return RunResult(findings=[], detector_stats=[], ingest_reports=[], run_metadata=run_meta)

    monkeypatch.setenv("DEPOS_PRODUCT_OUTPUTS_ENABLED", "0")
    monkeypatch.setattr(analyze_cli, "load_config_from_env", lambda: cfg)
    monkeypatch.setattr(
        analyze_cli,
        "_build_graph_source",
        lambda args: GraphifySource(graph_json_path=fixture),
    )
    monkeypatch.setattr(analyze_cli, "_run_pipeline", fake_pipeline)

    import sys

    monkeypatch.setattr(sys, "argv", ["depos-intel", "analyze", "repo", "--path", str(tmp_path)])

    class Args:
        path = str(tmp_path)
        output = None
        mode = "A,B,C"
        provider = None
        export_training = False
        max_seeds = None
        detectors = []
        no_reasoner = False
        print_detector_stats = False
        n_jobs = 1
        no_parallel = False
        taint_n_jobs = None
        cfg_dfg_n_jobs = None
        bundle_n_jobs = None
        no_expensive_metrics = False
        metrics_backend = None
        no_cache = False
        cache_dir = None
        cache_clear = False
        pyinstrument_html = None
        run_profile = "full"

    rc = analyze_cli.run_repo(Args())
    assert rc == 0
    intel_root = tmp_path / "intelligence"
    run_dirs = [p for p in intel_root.iterdir() if p.is_dir()]
    assert len(run_dirs) == 1
    out_dir = run_dirs[0]
    mf = out_dir / RUN_MANIFEST_FILENAME
    assert mf.is_file()
    data = json.loads(mf.read_text(encoding="utf-8"))
    assert data["schema_version"] == RUN_MANIFEST_SCHEMA_VERSION
    assert data["run_id"]
    assert out_dir.name == data["run_id"]
    assert "violations.json" in data["artifacts"]
    assert "gate_result.json" in data["artifacts"]
    assert data["artifacts"]["violations.json"].get("sha256")


def test_build_run_manifest_marks_missing_optional_files(tmp_path: Path) -> None:
    from depos.output.run_manifest import build_run_manifest

    (tmp_path / "violations.json").write_text('{"x":1}', encoding="utf-8")
    meta = RunMetadata(
        run_id="r1",
        analysis_mode=AnalysisMode.full_repo_scan,
        provider="stub",
        token_estimator="chars4",
    )
    result = RunResult(findings=[], detector_stats=[], ingest_reports=[], run_metadata=meta)
    cfg = IntelligenceConfig(data_dir=tmp_path)
    m = build_run_manifest(
        out_dir=tmp_path,
        result=result,
        config=cfg,
        cli={"prog": "t", "argv": [], "run_profile": "full"},
        repo_root=None,
        detector_policy={},
        product_paths=None,
        extra_artifact_relative_names=["missing.json"],
        generated_at="2026-01-01T00:00:00+00:00",
    )
    assert m["artifacts"]["missing.json"]["missing"] is True
    assert "sha256" in m["artifacts"]["violations.json"]
