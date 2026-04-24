from __future__ import annotations

import json

import pytest

from depos.analysis.schemas import VerifierOutcome
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


def test_verifier_outcome_canonical_maps_gray_zone_variants() -> None:
    assert VerifierOutcome.confirmed.canonical == "CONFIRMED"
    assert VerifierOutcome.partially_confirmed.canonical == "GRAY-ZONE"
    assert VerifierOutcome.unconfirmed.canonical == "GRAY-ZONE"
    assert VerifierOutcome.evaluator_surfaced.canonical == "GRAY-ZONE"
    assert verifier_to_status("partially_confirmed") == "GRAY-ZONE"


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


def test_gray_zone_outputs_include_failed_rule_details() -> None:
    doc = {
        "run_id": "r2",
        "run_metadata": {"pipeline_version": "9", "run_id": "r2"},
        "findings": [
            {
                "finding_id": "cand:gray:1",
                "trust_level": "partially_confirmed",
                "verifier_outcome": "partially_confirmed",
                "bug_type": "null_deref",
                "description": "Potential null dereference with incomplete CFG evidence.",
                "detector_name": "null-dereference-approx",
                "severity": "medium",
                "failed_rule": "cfg_summary",
                "missing_evidence": ["cfg_summary", "null_paths"],
                "confidence_range": [0.3, 0.65],
                "recommended_action": "MONITOR",
            }
        ],
    }

    sarif = json.loads(render_sarif(doc))
    message = sarif["runs"][0]["results"][0]["message"]["text"]
    assert "Failed rule: cfg_summary" in message
    assert "Missing evidence: cfg_summary, null_paths" in message

    md = render_violations_pr_comment(doc)
    assert "<summary>Why gray-zone?</summary>" in md
    assert "**Failed rule:** cfg_summary" in md
