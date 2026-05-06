"""Core pipeline import failures and CLI exit codes (production v1 hardening)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import depos.analysis.pipeline as pipeline_mod
from depos.analysis.config import IntelligenceConfig
from depos.analysis.schemas import AnalysisMode, RunMetadata
from depos.cli import analyze as analyze_cli
from depos.graph_source import GraphifySource


def _args_repo(tmp_path: Path) -> object:
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

    return Args()


def _args_diff(tmp_path: Path, diff_file: str | None) -> object:
    dp = diff_file

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
        diff_path = dp

    return Args()


def test_run_repo_runtime_error_from_pipeline_returns_three(monkeypatch, tmp_path: Path, capsys) -> None:
    fixture = Path(__file__).parent / "fixtures" / "acceptance_01_http_route.json"
    assert fixture.exists()
    cfg = IntelligenceConfig(data_dir=tmp_path)

    def boom(*args, **kwargs):
        raise RuntimeError("simulated pipeline wiring failure")

    monkeypatch.setenv("DEPOS_PRODUCT_OUTPUTS_ENABLED", "0")
    monkeypatch.setattr(analyze_cli, "load_config_from_env", lambda: cfg)
    monkeypatch.setattr(
        analyze_cli,
        "_build_graph_source",
        lambda args: GraphifySource(graph_json_path=fixture),
    )
    monkeypatch.setattr(analyze_cli, "_run_pipeline", boom)

    rc = analyze_cli.run_repo(_args_repo(tmp_path))
    assert rc == 3
    err = capsys.readouterr().err
    assert "simulated pipeline wiring failure" in err


def test_run_diff_runtime_error_from_pipeline_returns_three(monkeypatch, tmp_path: Path, capsys) -> None:
    fixture = Path(__file__).parent / "fixtures" / "acceptance_01_http_route.json"
    assert fixture.exists()
    cfg = IntelligenceConfig(data_dir=tmp_path)

    def boom(*args, **kwargs):
        raise RuntimeError("simulated diff pipeline failure")

    monkeypatch.setenv("DEPOS_PRODUCT_OUTPUTS_ENABLED", "0")
    monkeypatch.setattr(analyze_cli, "load_config_from_env", lambda: cfg)
    monkeypatch.setattr(
        analyze_cli,
        "_build_graph_source",
        lambda args: GraphifySource(graph_json_path=fixture),
    )
    monkeypatch.setattr(analyze_cli, "_run_pipeline", boom)

    rc = analyze_cli.run_diff(_args_diff(tmp_path, None))
    assert rc == 3
    err = capsys.readouterr().err
    assert "simulated diff pipeline failure" in err


def test_run_pipeline_missing_core_symbol_raises_runtime_error(
    monkeypatch, tmp_path: Path
) -> None:
    """If ``run_modules_2_through_7`` cannot be imported, fail loudly."""
    fixture = Path(__file__).parent / "fixtures" / "acceptance_01_http_route.json"
    src = GraphifySource(graph_json_path=fixture)
    cfg = IntelligenceConfig(data_dir=tmp_path)
    meta = RunMetadata(
        run_id="t-pipeline-import",
        analysis_mode=AnalysisMode.full_repo_scan,
        provider="stub",
        token_estimator="chars4",
    )

    def light_enrich(graph, **kwargs):
        from depos.analysis.schemas import StitcherCoverageReport

        return graph, StitcherCoverageReport()

    monkeypatch.setattr("depos.enrichment.semantic_edges.enrich_graph", light_enrich)
    monkeypatch.delattr(pipeline_mod, "run_modules_2_through_7", raising=False)

    with pytest.raises(RuntimeError, match="run_modules_2_through_7"):
        analyze_cli._run_pipeline(src, cfg, meta, progress=lambda _m: None)
