from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path

from depos.analysis.config import IntelligenceConfig
from depos.analysis.schemas import AnalysisMode, ChangeManifest, RunResult
from depos.cli import analyze as analyze_cli
from depos.cli import main


def _empty_result(run_meta) -> RunResult:
    return RunResult(
        findings=[],
        detector_stats=[],
        ingest_reports=[],
        run_metadata=run_meta,
        change_manifest=ChangeManifest(entries=[], resolved_via="empty"),
        candidates=[],
        bundles=[],
        gray_zone_rows=[],
        bundle_trace=[],
    )


def test_repo_diff_and_dataset_pipeline_share_canonical_runner(tmp_path, monkeypatch) -> None:
    cfg = IntelligenceConfig(data_dir=tmp_path / "depos-data")
    seen: list[tuple[AnalysisMode, dict[str, object]]] = []

    class DummySource:
        def get_source_metadata(self) -> dict[str, str]:
            return {"repo_path": str(tmp_path / "repo")}

    def fake_run_pipeline(source, config, run_meta, **kwargs):
        seen.append((run_meta.analysis_mode, kwargs))
        return _empty_result(run_meta)

    def fake_normalize_dataset_to_graph(**kwargs):
        graph_output = kwargs["graph_output"]
        graph_output.parent.mkdir(parents=True, exist_ok=True)
        graph_output.write_text(json.dumps({"nodes": [], "edges": []}), encoding="utf-8")
        return {"nodes": [], "edges": []}, graph_output

    monkeypatch.setattr(analyze_cli, "load_config_from_env", lambda: cfg.model_copy(deep=True))
    monkeypatch.setattr(analyze_cli, "_build_graph_source", lambda args: DummySource())
    monkeypatch.setattr(analyze_cli, "_run_pipeline", fake_run_pipeline)
    monkeypatch.setattr(analyze_cli, "_normalize_dataset_to_graph", fake_normalize_dataset_to_graph)

    repo_args = Namespace(
        path=str(tmp_path / "repo"),
        output=None,
        mode="A,B,C",
        provider=None,
        export_training=False,
        max_seeds=None,
        detectors=[],
        no_reasoner=False,
        print_detector_stats=False,
    )
    diff_args = Namespace(
        cpg_path=None,
        graph_json=str(tmp_path / "graph.json"),
        diff_path=str(tmp_path / "sample.diff"),
        output=None,
        mode="A,B,C",
        provider=None,
        export_training=False,
        detectors=[],
        no_reasoner=False,
        print_detector_stats=False,
    )
    dataset_dir = tmp_path / "dataset"
    dataset_dir.mkdir()
    repo_root = tmp_path / "repo-root"
    repo_root.mkdir()
    dataset_args = Namespace(
        dataset_dir=str(dataset_dir),
        output_dir=str(tmp_path / "dataset-out"),
        repo_root=str(repo_root),
        provider=None,
        top_n=5,
        max_bundles=7,
        min_score=0.42,
        write_extraction=False,
        model_name="",
        cache_dir=None,
        device=None,
        local_files_only=False,
        source_root=[],
        path_alias=[],
        min_evidence=None,
        strict=False,
    )

    assert analyze_cli.run_repo(repo_args) == 0
    assert analyze_cli.run_diff(diff_args) == 0
    assert analyze_cli.run_dataset_pipeline(dataset_args) == 0

    assert [mode for mode, _ in seen] == [
        AnalysisMode.full_repo_scan,
        AnalysisMode.diff_aware,
        AnalysisMode.full_repo_scan,
    ]
    assert seen[2][1]["repo_root"] == repo_root
    assert seen[2][1]["bundle_limit"] == 7
    assert seen[2][1]["selected_limit"] == 5
    assert seen[2][1]["min_score"] == 0.42


def test_bundle_pipeline_is_deprecated_shim(capsys) -> None:
    rc = main(["analyze", "bundle-pipeline", "--bundles-json", "unused.json"])
    captured = capsys.readouterr()

    assert rc == 2
    payload = json.loads(captured.out)
    assert payload["deprecated"] is True
    assert payload["command"] == "bundle-pipeline"
    assert "deprecated" in captured.err.lower()
