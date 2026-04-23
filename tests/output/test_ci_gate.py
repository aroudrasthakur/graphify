from __future__ import annotations

from depos.output.gate import evaluate_gate, finding_triggers_gate


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


def test_cli_gate_runs_with_zero_exit_code_subprocess() -> None:
    import json
    from pathlib import Path

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
    import json
    from pathlib import Path

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
