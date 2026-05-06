"""Smoke test for the ``depos-intel`` CLI layer.

We do not shell out to the console script (the packaging environment
may not have installed it yet); we call :func:`depos.cli.main` in-
process with synthesized argv. This catches broken dispatch / missing
lazy imports.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from io import StringIO
from pathlib import Path

import pytest

from depos.cli import main
from depos.analysis.config import IntelligenceConfig
from depos.analysis.schemas import RunMetadata, RunResult


def _run_cli(argv, capsys) -> tuple[int, str]:
    rc = main(argv)
    captured = capsys.readouterr()
    return rc, captured.out


def test_cli_help_exits_zero(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    # --help exits with 0 via argparse.
    assert exc.value.code == 0


def test_cli_coverage_reads_real_migrations(capsys, tmp_path: Path) -> None:
    fixture = Path(__file__).parent / "fixtures" / "acceptance_01_http_route.json"
    assert fixture.exists()
    rc, out = _run_cli(["analyze", "coverage", "--graph-json", str(fixture)], capsys)
    assert rc == 0
    payload = json.loads(out)
    # We ship 6 migrations in supabase/migrations, so the CLI should see them.
    assert payload["migration_files_found"] >= 1
    assert "coverage_ratio" in payload


def test_cli_score_bundles_help_exits_zero(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["analyze", "score-bundles", "--help"])
    assert exc.value.code == 0


def test_cli_bundle_pipeline_help_exits_zero(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["analyze", "bundle-pipeline", "--help"])
    assert exc.value.code == 0


def test_cli_normalize_dataset_help_exits_zero(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["analyze", "normalize-dataset", "--help"])
    assert exc.value.code == 0


def test_cli_prepare_dataset_help_exits_zero(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["analyze", "prepare-dataset", "--help"])
    assert exc.value.code == 0


def test_cli_dataset_pipeline_help_exits_zero(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["analyze", "dataset-pipeline", "--help"])
    assert exc.value.code == 0


def test_cli_cache_flags_parse_for_pipeline_commands(tmp_path: Path) -> None:
    from depos.cli import _build_parser

    cache_dir = tmp_path / "cache"
    parser = _build_parser(prog="depos-intel")
    repo = parser.parse_args(
        [
            "analyze",
            "repo",
            "--path",
            ".",
            "--no-cache",
            "--cache-dir",
            str(cache_dir),
            "--cache-clear",
        ]
    )
    diff = parser.parse_args(
        [
            "analyze",
            "diff",
            "--graph-json",
            "graph.json",
            "--cache-dir",
            str(cache_dir),
        ]
    )
    dataset = parser.parse_args(
        [
            "analyze",
            "dataset-pipeline",
            "--dataset-dir",
            "dataset",
            "--output-dir",
            "out",
            "--no-cache",
        ]
    )

    assert repo.no_cache is True
    assert repo.cache_dir == str(cache_dir)
    assert repo.cache_clear is True
    assert diff.cache_dir == str(cache_dir)
    assert dataset.no_cache is True


def test_apply_cache_overrides_freezes_default_root(tmp_path: Path) -> None:
    from depos.cli import analyze as analyze_cli

    cfg = IntelligenceConfig(data_dir=tmp_path)
    args = argparse.Namespace(no_cache=False, cache_dir=None, cache_clear=False)

    analyze_cli._apply_cache_overrides(cfg, args)

    assert cfg.cache.enabled is True
    assert cfg.cache.cache_dir == tmp_path / "cache"


def test_cli_detectors_list_outputs_registry(capsys) -> None:
    rc, out = _run_cli(["detectors", "list", "--json"], capsys)
    assert rc == 0
    payload = json.loads(out)
    names = {row["name"] for row in payload["detectors"]}
    assert "dep-version-mismatch-across-workspaces" in names
    assert "env-var-referenced-but-undefined" in names


def test_cli_detectors_explain_outputs_spec(capsys) -> None:
    rc, out = _run_cli(["detectors", "explain", "env-var-referenced-but-undefined", "--json"], capsys)
    assert rc == 0
    payload = json.loads(out)
    assert payload["name"] == "env-var-referenced-but-undefined"


def test_run_repo_honors_provider_override(monkeypatch, tmp_path: Path, capsys) -> None:
    from depos.cli import analyze as analyze_cli

    cfg = IntelligenceConfig(data_dir=tmp_path)
    cfg.llm.provider = "gemma"

    class DummySource:
        def get_source_metadata(self) -> dict[str, str]:
            return {"repo_path": str(tmp_path)}

    seen: dict[str, str] = {}

    def fake_run_pipeline(source, config, run_meta, **kwargs):
        seen["provider"] = config.llm.provider
        return RunResult(findings=[], detector_stats=[], ingest_reports=[], run_metadata=run_meta)

    monkeypatch.setattr(analyze_cli, "load_config_from_env", lambda: cfg)
    monkeypatch.setattr(analyze_cli, "_build_graph_source", lambda args: DummySource())
    monkeypatch.setattr(analyze_cli, "_run_pipeline", fake_run_pipeline)

    args = argparse.Namespace(
        path=str(tmp_path),
        output=None,
        mode="A,B,C",
        provider="stub",
        export_training=False,
        max_seeds=None,
        detectors=[],
        no_reasoner=False,
        print_detector_stats=False,
    )

    rc = analyze_cli.run_repo(args)
    assert rc == 0
    assert seen["provider"] == "stub"


def test_run_repo_profile_wraps_pipeline(monkeypatch, tmp_path: Path) -> None:
    from contextlib import contextmanager

    import depos._perf as perf
    from depos.cli import analyze as analyze_cli

    cfg = IntelligenceConfig(data_dir=tmp_path)
    profile_path = tmp_path / "profile.html"
    calls: list[str] = []

    class DummySource:
        def get_source_metadata(self) -> dict[str, str]:
            return {"repo_path": str(tmp_path)}

    @contextmanager
    def fake_profile(path):
        calls.append(str(path))
        yield

    def fake_run_pipeline(source, config, run_meta, **kwargs):
        assert calls == [str(profile_path)]
        return RunResult(findings=[], detector_stats=[], ingest_reports=[], run_metadata=run_meta)

    monkeypatch.setattr(perf, "pyinstrument_session", fake_profile)
    monkeypatch.setattr(analyze_cli, "load_config_from_env", lambda: cfg)
    monkeypatch.setattr(analyze_cli, "_build_graph_source", lambda args: DummySource())
    monkeypatch.setattr(analyze_cli, "_run_pipeline", fake_run_pipeline)

    args = argparse.Namespace(
        path=str(tmp_path),
        output=None,
        mode="A,B,C",
        provider=None,
        export_training=False,
        max_seeds=None,
        detectors=[],
        no_reasoner=False,
        print_detector_stats=False,
        pyinstrument_html=str(profile_path),
        run_profile="full",
    )

    assert analyze_cli.run_repo(args) == 0
    assert calls == [str(profile_path)]


def test_new_run_metadata_uses_timestamp_prefixed_run_id(tmp_path: Path) -> None:
    from depos.cli import analyze as analyze_cli

    cfg = IntelligenceConfig(data_dir=tmp_path)

    class DummySource:
        def get_source_metadata(self) -> dict[str, str]:
            return {"repo_path": str(tmp_path)}

    meta_mode = analyze_cli.AnalysisMode.full_repo_scan
    meta = analyze_cli._new_run_metadata(cfg, DummySource(), mode=meta_mode)

    assert meta.analysis_mode == meta_mode
    assert re.fullmatch(r"\d{8}-\d{6}-[0-9a-f]{6}", meta.run_id)


def test_run_repo_emits_progress_to_stderr(monkeypatch, tmp_path: Path, capsys) -> None:
    from depos.cli import analyze as analyze_cli

    cfg = IntelligenceConfig(data_dir=tmp_path)

    class DummySource:
        def get_source_metadata(self) -> dict[str, str]:
            return {"repo_path": str(tmp_path)}

    def fake_run_pipeline(source, config, run_meta, **kwargs):
        progress = kwargs.get("progress")
        if progress is not None:
            progress("Module 2: detectors emitted 0 candidates.")
        return RunResult(findings=[], detector_stats=[], ingest_reports=[], run_metadata=run_meta)

    monkeypatch.setattr(analyze_cli, "load_config_from_env", lambda: cfg)
    monkeypatch.setattr(analyze_cli, "_build_graph_source", lambda args: DummySource())
    monkeypatch.setattr(analyze_cli, "_run_pipeline", fake_run_pipeline)

    args = argparse.Namespace(
        path=str(tmp_path),
        output=None,
        mode="A,B,C",
        provider=None,
        export_training=False,
        max_seeds=None,
        detectors=[],
        no_reasoner=False,
        print_detector_stats=False,
    )

    rc = analyze_cli.run_repo(args)
    captured = capsys.readouterr()
    assert rc == 0
    assert "[depos-intel]" in captured.err
    assert "Module 2: detectors emitted 0 candidates." in captured.err
    payload = json.loads(captured.out)
    assert payload["findings"] == 0
