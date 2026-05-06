"""gate_result.json contract and precedence vs legacy gate."""
from __future__ import annotations

import json
from pathlib import Path

from depos.output.gate_result import GATE_RESULT_FILENAME, build_gate_result, write_gate_result_for_directory


def test_build_gate_result_pass_empty() -> None:
    doc = {
        "run_metadata": {"reasoner_run_health": "ok", "reasoner_health_reason": ""},
        "findings": [],
    }
    r = build_gate_result(doc, allowlist=set())
    assert r["outcome"] == "pass"
    assert r["exit_code"] == 0
    assert r["blocking_finding_ids"] == []


def test_build_gate_result_block_on_confirmed_high() -> None:
    doc = {
        "run_metadata": {"reasoner_run_health": "ok"},
        "findings": [
            {
                "finding_id": "f1",
                "severity": "high",
                "verifier_outcome": "confirmed",
                "status": "CONFIRMED",
            }
        ],
    }
    r = build_gate_result(doc, allowlist=set())
    assert r["outcome"] == "block"
    assert r["exit_code"] == 1
    assert "f1" in r["blocking_finding_ids"]


def test_write_gate_result_for_directory(tmp_path: Path) -> None:
    vdir = tmp_path / "run"
    vdir.mkdir()
    (vdir / "violations.json").write_text(
        json.dumps(
            {
                "run_metadata": {"reasoner_run_health": "ok"},
                "findings": [],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    p = write_gate_result_for_directory(vdir, allowlist_path=tmp_path / "no_allow")  # missing == empty allowlist
    assert p.name == GATE_RESULT_FILENAME
    data = json.loads(p.read_text(encoding="utf-8"))
    assert data["outcome"] == "pass"
