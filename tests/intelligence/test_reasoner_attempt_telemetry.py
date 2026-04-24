from __future__ import annotations

import json
from pathlib import Path

from depos.analysis.config import IntelligenceConfig
from depos.analysis.reasoning_engine import ProviderError, run_reasoner, summarize_reasoner_attempts
from depos.analysis.schemas import ContextBundle, PackManifest, ReasonerMode, RunMetadata, RunResult
from depos.cli.analyze import _write_run_summary


REQUIRED_ATTEMPT_KEYS = {
    "event_type",
    "run_id",
    "candidate_id",
    "detector_name",
    "mode",
    "provider",
    "model",
    "attempt_idx",
    "max_retries",
    "timeout_seconds",
    "prompt_chars",
    "prompt_bytes",
    "max_prompt_tokens",
    "requested_output_tokens",
    "elapsed_ms",
    "success",
    "failure_type",
    "failure_message",
    "recovered_by_retry",
}


def _bundle(candidate_id: str) -> ContextBundle:
    return ContextBundle(
        bundle_id=f"bundle-{candidate_id}",
        candidate_id=candidate_id,
        scope_id="scope",
        pack_manifest=PackManifest(manifest_id="pack"),
        token_budget=8000,
    )


def _mode_a_payload(description: str) -> str:
    return json.dumps(
        {
            "mode": "A",
            "findings": [
                {
                    "bug_type": "fake_bug",
                    "description": description,
                    "trigger_condition": "fake condition",
                    "affected_path": ["scope"],
                    "confidence": 0.8,
                    "graph_anchor_nodes": ["scope"],
                }
            ],
        }
    )


class _SuccessProvider:
    name = "fake-provider"
    model = "fake-model"

    def complete(self, prompt: str, *, max_tokens: int):
        return _mode_a_payload("success"), {"model": self.model, "response_path_used": "literal"}


class _FailOnceThenSucceedProvider:
    name = "fake-provider"
    model = "fake-model"

    def __init__(self) -> None:
        self.calls = 0

    def complete(self, prompt: str, *, max_tokens: int):
        self.calls += 1
        if self.calls == 1:
            raise ProviderError("transport", "read timeout " + ("x" * 700))
        return _mode_a_payload("recovered"), {"model": self.model, "response_path_used": "literal"}


def test_reasoner_attempts_record_success_failure_and_recovered_retry(monkeypatch, tmp_path: Path) -> None:
    cfg = IntelligenceConfig(data_dir=tmp_path)
    cfg.llm.provider = "gemma"
    cfg.llm.gemma_api_url = "http://unused.invalid"
    cfg.llm.max_retries = 1
    cfg.llm.read_timeout_seconds = 12.5
    cfg.llm.default_max_tokens = 321
    cfg.bundles.max_prompt_tokens = 1234
    providers = [_SuccessProvider(), _FailOnceThenSucceedProvider()]

    from depos.analysis import reasoning_engine as re_mod

    monkeypatch.setattr(re_mod, "get_provider", lambda *_args, **_kwargs: providers.pop(0))

    assert run_reasoner(
        _bundle("cand-success"),
        mode=ReasonerMode.A,
        config=cfg,
        run_id="run-attempts",
        detector_name="fake-detector",
    ) is not None
    assert run_reasoner(
        _bundle("cand-retry"),
        mode=ReasonerMode.A,
        config=cfg,
        run_id="run-attempts",
        detector_name="fake-detector",
    ) is not None

    attempts_path = tmp_path / cfg.run_output_subdir / "run-attempts" / "reasoner_attempts.jsonl"
    records = [json.loads(line) for line in attempts_path.read_text(encoding="utf-8").splitlines()]

    assert len(records) == 3
    assert all(REQUIRED_ATTEMPT_KEYS == set(record) for record in records)
    assert [record["attempt_idx"] for record in records] == [1, 1, 2]
    assert all(record["timeout_seconds"] == 12.5 for record in records)
    assert all(isinstance(record["elapsed_ms"], (int, float)) for record in records)
    assert all(record["prompt_chars"] > 0 for record in records)
    assert all(record["prompt_bytes"] >= record["prompt_chars"] for record in records)
    assert all(record["max_prompt_tokens"] == 1234 for record in records)
    assert all(record["requested_output_tokens"] == 321 for record in records)
    assert records[1]["success"] is False
    assert records[1]["failure_type"] == "transport"
    assert len(records[1]["failure_message"]) <= 500
    assert records[1]["recovered_by_retry"] is True

    observability_path = tmp_path / cfg.run_output_subdir / "run-attempts" / "observability.jsonl"
    observability_rows = [
        json.loads(line) for line in observability_path.read_text(encoding="utf-8").splitlines()
    ]
    assert sum(1 for row in observability_rows if row.get("event_type") == "reasoner_attempt") == 3

    summary_path = tmp_path / cfg.run_output_subdir / "run-attempts" / "run_summary.json"
    summary = _write_run_summary(
        summary_path,
        result=RunResult(run_metadata=RunMetadata(run_id="run-attempts")),
    )
    attempt_summary = summary["reasoner_attempt_summary"]

    assert attempt_summary["total_attempts"] == 3
    assert attempt_summary["successful_attempts"] == 2
    assert attempt_summary["failed_attempts"] == 1
    assert attempt_summary["recovered_failures"] == 1
    assert attempt_summary["timeouts"] == 1
    assert attempt_summary["provider"] == "fake-provider"
    assert attempt_summary["model"] == "fake-model"
    assert attempt_summary["by_detector"]["fake-detector"]["candidates"] == 2
    assert attempt_summary["by_detector"]["fake-detector"]["attempts"] == 3
    assert attempt_summary["by_detector"]["fake-detector"]["successes"] == 2
    assert attempt_summary["by_detector"]["fake-detector"]["failures"] == 1
    assert attempt_summary["by_detector"]["fake-detector"]["recovered_failures"] == 1

    roundtrip = json.loads(summary_path.read_text(encoding="utf-8"))
    assert roundtrip["reasoner_attempt_summary"]["total_attempts"] == 3


def test_reasoner_attempt_summary_no_attempts(tmp_path: Path) -> None:
    summary = summarize_reasoner_attempts(tmp_path / "missing" / "reasoner_attempts.jsonl")

    assert summary["total_attempts"] == 0
    assert summary["p50_attempt_ms"] is None
    assert summary["p75_attempt_ms"] is None
    assert summary["p90_attempt_ms"] is None
    assert summary["p95_attempt_ms"] is None
    assert summary["by_detector"] == {}
