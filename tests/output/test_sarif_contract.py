"""SARIF 2.1.0 shape for depOS exporters."""
from __future__ import annotations

import json

from depos.output.sarif import render_sarif


def test_sarif_includes_partial_fingerprint_and_schema() -> None:
    doc = {
        "run_id": "r-sarif",
        "run_metadata": {"pipeline_version": "2.0.0"},
        "findings": [
            {
                "finding_id": "f1",
                "trust_level": "partially_confirmed",
                "verifier_outcome": "partially_confirmed",
                "bug_type": "xss",
                "description": "secret: token=abc123",
                "detector_name": "custom-detector",
                "severity": "high",
                "witness_path": ["src/a.py"],
            }
        ],
    }
    sarif = json.loads(render_sarif(doc))
    assert sarif["version"] == "2.1.0"
    res = sarif["runs"][0]["results"][0]
    assert res["partialFingerprints"]["depOSFindingId/v1"]
    assert "locations" in res
    assert "abc123" not in json.dumps(res)
