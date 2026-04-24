from __future__ import annotations

import httpx
import json
from types import SimpleNamespace

from depos.analysis.config import IntelligenceConfig
from depos.analysis.reasoning_engine import run_all_modes, run_reasoner
from depos.analysis.schemas import ContextBundle, PackManifest, ReasonerMode


def _bundle() -> ContextBundle:
    return ContextBundle(
        bundle_id="bundle-1",
        candidate_id="cand-1",
        scope_id="scope-1",
        pack_manifest=PackManifest(manifest_id="pack-1"),
        token_budget=8000,
    )


def test_run_reasoner_queues_http_provider_errors(monkeypatch, tmp_path) -> None:
    class BrokenProvider:
        def complete(self, prompt: str, *, max_tokens: int) -> str:
            request = httpx.Request("POST", "http://localhost:11434/api/generate")
            response = httpx.Response(500, request=request)
            raise httpx.HTTPStatusError("boom", request=request, response=response)

    config = IntelligenceConfig(data_dir=tmp_path)
    config.llm.max_retries = 0
    monkeypatch.setattr("depos.analysis.reasoning_engine.get_provider", lambda config, mode: BrokenProvider())

    result = run_reasoner(
        _bundle(),
        mode=ReasonerMode.A,
        config=config,
        run_id="testrun",
    )

    assert result is None
    queue_path = tmp_path / config.run_output_subdir / "testrun" / "reasoner_queue.jsonl"
    assert queue_path.exists()
    lines = queue_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1


def test_run_reasoner_queues_raw_response_for_validation_errors(monkeypatch, tmp_path) -> None:
    class SchemaDriftProvider:
        name = "ollama-fake"

        def complete(self, prompt: str, *, max_tokens: int):
            return (
                json.dumps(
                    {
                        "mode": "C",
                        "findings": [{}],
                    }
                ),
                {"model": "fake", "response_path_used": "response"},
            )

    config = IntelligenceConfig(data_dir=tmp_path)
    config.llm.max_retries = 0
    monkeypatch.setattr(
        "depos.analysis.reasoning_engine.get_provider",
        lambda config, mode: SchemaDriftProvider(),
    )

    result = run_reasoner(
        _bundle(),
        mode=ReasonerMode.C,
        config=config,
        run_id="testrun-schema",
    )

    assert result is None
    queue_path = tmp_path / config.run_output_subdir / "testrun-schema" / "reasoner_queue.jsonl"
    row = json.loads(queue_path.read_text(encoding="utf-8").strip())
    assert row["failure_reason"] == "json_but_invalid_schema"
    assert row["raw_response_excerpt"] == '{"mode": "C", "findings": [{}]}'


def test_run_all_modes_honors_selected_modes(monkeypatch, tmp_path) -> None:
    seen: list[ReasonerMode] = []

    def _fake_run_reasoner(bundle, *, mode, **kwargs):
        seen.append(mode)
        return SimpleNamespace(mode=mode, findings=[])

    monkeypatch.setattr("depos.analysis.reasoning_engine.run_reasoner", _fake_run_reasoner)

    result = run_all_modes(
        _bundle(),
        config=IntelligenceConfig(data_dir=tmp_path),
        run_id="testrun-selected-modes",
        modes=(ReasonerMode.C,),
    )

    assert seen == [ReasonerMode.C]
    assert list(result.keys()) == [ReasonerMode.C]
