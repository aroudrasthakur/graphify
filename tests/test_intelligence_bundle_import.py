from __future__ import annotations

import json
from pathlib import Path

import pytest

from depos.intelligence_bundle_import import load_bundle_sidecars, run_bundle_dict_from_directory, verify_manifest_checksums
from depos.api_server import IntelligenceRunCreate


def test_run_bundle_dict_from_violations_roundtrips_create_model(tmp_path: Path) -> None:
    out = tmp_path / "run"
    out.mkdir()
    doc = {
        "run_id": "abc",
        "run_metadata": {
            "run_id": "abc",
            "analysis_mode": "full_repo_scan",
            "pipeline_version": "2.0.0",
            "provider": "stub",
            "reasoner_run_health": "ok",
        },
        "findings": [
            {
                "finding_id": "f1",
                "trust_level": "unconfirmed",
                "verifier_outcome": "unconfirmed",
                "bug_type": "x",
                "description": "y",
                "detector_name": "d",
                "severity": "medium",
            }
        ],
        "detector_stats": [],
        "ingest_reports": [],
    }
    (out / "violations.json").write_text(json.dumps(doc), encoding="utf-8")
    payload = run_bundle_dict_from_directory(out, repo_slug="my-repo", verify_checksums=False)
    IntelligenceRunCreate.model_validate(payload)
    assert payload["repo_slug"] == "my-repo"
    assert payload["findings"][0]["trust_level"] == "evaluator_surfaced"


def test_verify_manifest_checksum_detects_tamper(tmp_path: Path) -> None:
    d = tmp_path / "b"
    d.mkdir()
    (d / "violations.json").write_text("{}", encoding="utf-8")
    manifest = {
        "schema_version": "1.0",
        "artifacts": {"violations.json": {"sha256": "0" * 64}},
    }
    with pytest.raises(ValueError, match="checksum mismatch"):
        verify_manifest_checksums(d, manifest)


def test_load_bundle_sidecars_reads_gate_and_manifest(tmp_path: Path) -> None:
    d = tmp_path / "bundle"
    d.mkdir()
    (d / "gate_result.json").write_text(
        '{"schema_version":"1.0","outcome":"pass","exit_code":0}',
        encoding="utf-8",
    )
    (d / "run_manifest.json").write_text(
        '{"schema_version":"1.0","artifacts":{"a.json":{},"b.json":{}}}',
        encoding="utf-8",
    )
    s = load_bundle_sidecars(d)
    assert s["gate_result"]["outcome"] == "pass"
    assert s["run_manifest_summary"]["artifact_count"] == 2
    assert s["run_manifest_summary"]["schema_version"] == "1.0"


def test_load_bundle_sidecars_empty_dir(tmp_path: Path) -> None:
    d = tmp_path / "empty"
    d.mkdir()
    assert load_bundle_sidecars(d) == {}
