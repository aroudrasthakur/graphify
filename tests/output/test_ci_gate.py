from __future__ import annotations

import json
from pathlib import Path

from depos.output.gate import evaluate_gate, finding_triggers_gate, load_allowlist


def test_gate_blocks_on_confirmed_high() -> None:
    findings = [
        {
            "finding_id": "f1",
            "verifier_outcome": "confirmed",
            "severity": "high",
            "description": "x",
        }
    ]
    fail, blocking = evaluate_gate(findings, allowlist=set())
    assert fail
    assert len(blocking) == 1
    assert blocking[0]["finding_id"] == "f1"


def test_gate_blocks_on_confirmed_critical() -> None:
    findings = [
        {
            "finding_id": "c1",
            "verifier_outcome": "confirmed",
            "severity": "critical",
        }
    ]
    assert finding_triggers_gate(findings[0]) is True
    fail, _ = evaluate_gate(findings, allowlist=set())
    assert fail


def test_gate_passes_clean_low_severity() -> None:
    findings = [
        {
            "finding_id": "a",
            "verifier_outcome": "confirmed",
            "severity": "low",
        }
    ]
    fail, blocking = evaluate_gate(findings, allowlist=set())
    assert not fail
    assert blocking == []


def test_gate_passes_partially_confirmed_high() -> None:
    findings = [
        {
            "finding_id": "p",
            "verifier_outcome": "partially_confirmed",
            "severity": "high",
        }
    ]
    fail, _ = evaluate_gate(findings, allowlist=set())
    assert not fail


def test_gate_allowlist_skips_finding() -> None:
    findings = [
        {
            "finding_id": "known",
            "verifier_outcome": "confirmed",
            "severity": "critical",
        }
    ]
    fail, blocking = evaluate_gate(findings, allowlist={"known"})
    assert not fail
    assert blocking == []


def test_expired_allowlist_entry_does_not_suppress_confirmed_finding(tmp_path: Path) -> None:
    allowlist_path = tmp_path / "allowlist.json"
    allowlist_path.write_text(
        json.dumps(
            [
                {
                    "finding_id": "expired",
                    "reason": "legacy waiver",
                    "expires": "2000-01-01",
                }
            ]
        ),
        encoding="utf-8",
    )
    findings = [
        {
            "finding_id": "expired",
            "verifier_outcome": "confirmed",
            "severity": "high",
        }
    ]

    fail, blocking = evaluate_gate(findings, allowlist=load_allowlist(allowlist_path))

    assert fail
    assert len(blocking) == 1


def test_valid_allowlist_entry_suppresses_confirmed_finding(tmp_path: Path) -> None:
    allowlist_path = tmp_path / "allowlist.json"
    allowlist_path.write_text(
        json.dumps(
            [
                {
                    "finding_id": "valid",
                    "reason": "accepted risk",
                    "expires": "2999-01-01",
                }
            ]
        ),
        encoding="utf-8",
    )
    findings = [
        {
            "finding_id": "valid",
            "verifier_outcome": "confirmed",
            "severity": "high",
        }
    ]

    fail, blocking = evaluate_gate(findings, allowlist=load_allowlist(allowlist_path))

    assert not fail
    assert blocking == []


def test_cli_gate_runs_with_zero_exit_code_subprocess() -> None:
    from depos.cli import main

    p = {
        "run_id": "t",
        "findings": [
            {
                "finding_id": "ok",
                "verifier_outcome": "unconfirmed",
                "severity": "info",
            }
        ],
    }
    path = Path(__file__).resolve().parent / "_tmp_gate_pass.json"
    try:
        path.write_text(json.dumps(p), encoding="utf-8")
        rc = main(["gate", "--violations", str(path)])
        assert rc == 0
    finally:
        if path.exists():
            path.unlink()


def test_cli_gate_nonzero_on_block() -> None:
    from depos.cli import main

    p = {
        "findings": [
            {
                "finding_id": "bad",
                "verifier_outcome": "confirmed",
                "severity": "high",
            }
        ],
    }
    path = Path(__file__).resolve().parent / "_tmp_gate_fail.json"
    try:
        path.write_text(json.dumps(p), encoding="utf-8")
        rc = main(
            [
                "gate",
                "--violations",
                str(path),
                "--allow-finding-id",
                "bad",
            ]
        )
        assert rc == 0
        rc2 = main(["gate", "--violations", str(path)])
        assert rc2 == 1
    finally:
        if path.exists():
            path.unlink()
