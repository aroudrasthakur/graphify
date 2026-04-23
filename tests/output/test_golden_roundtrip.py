from __future__ import annotations

import json

import pytest

from depos.output.canonical import enrich_violations_payload, verifier_to_status
from depos.output.json import render_violations_document
from depos.output.pr_comment import render_violations_pr_comment
from depos.output.sarif import render_sarif, violations_to_sarif_runs


@pytest.fixture
def sample_violations_doc() -> dict:
    return {
        "run_id": "r1",
        "run_metadata": {"pipeline_version": "9", "run_id": "r1"},
        "findings": [
            {
                "finding_id": "cand:a:high:bug",
                "trust_level": "confirmed",
                "verifier_outcome": "confirmed",
                "bug_type": "sql_drift",
                "description": "Example confirmed finding for export tests.",
                "witness_path": ["node:db", "node:api"],
                "detector_name": "example-detector",
                "severity": "high",
            }
        ],
    }


def test_verifier_to_status_maps_confirmed() -> None:
    assert verifier_to_status("confirmed") == "CONFIRMED"


def test_golden_enrich_then_json_sarif_pr_share_status(sample_violations_doc) -> None:
    enriched = enrich_violations_payload(sample_violations_doc)
    assert enriched["status"] == "CONFIRMED"
    f0 = enriched["findings"][0]
    assert f0["status"] == "CONFIRMED"
    assert f0["evidence_chain"]["witness_path"] == ["node:db", "node:api"]
    assert "blast_radius" in f0
    assert f0["recommended_action"]

    jtxt = render_violations_document(sample_violations_doc, enrich=True)
    roundtrip = json.loads(jtxt)
    assert roundtrip["findings"][0]["status"] == "CONFIRMED"

    sarif_txt = render_sarif(sample_violations_doc)
    sarif = json.loads(sarif_txt)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["properties"]["depOS_status"] == "CONFIRMED"

    md = render_violations_pr_comment(sample_violations_doc)
    assert "CONFIRMED" in md
    assert "example-detector" in md


def test_sarif_runs_list_matches_findings_count(sample_violations_doc) -> None:
    runs = violations_to_sarif_runs(sample_violations_doc)
    assert len(runs) == 1
    assert len(runs[0]["results"]) == 1
