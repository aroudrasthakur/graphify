from __future__ import annotations

import json
import logging

import httpx
import pytest

from depos.analysis.config import IntelligenceConfig
from depos.analysis.reasoning_engine import (
    GemmaProvider,
    OllamaProvider,
    OpenAIProvider,
    ProviderError,
    ReasonerSession,
    ReasonerMode,
    _parse,
    _preflight_ollama,
    _validate_ollama_model,
    get_provider,
    run_reasoner,
)
from depos.analysis.schemas import (
    ContextBundle,
    PackManifest,
    ReasonerCallStats,
)


def _minimal_bundle() -> ContextBundle:
    return ContextBundle(
        bundle_id="bundle-failure-1",
        candidate_id="cand-failure-1",
        scope_id="node:scope",
        pack_manifest=PackManifest(manifest_id="pack-1"),
        token_budget=1000,
        score_composite=0.5,
    )


def test_get_provider_threads_timeouts_into_http_providers(tmp_path) -> None:
    cfg = IntelligenceConfig(data_dir=tmp_path)
    cfg.llm.connect_timeout_seconds = 1.25
    cfg.llm.read_timeout_seconds = 7.5

    cfg.llm.provider = "ollama"
    cfg.llm.ollama_host = "http://example.invalid:11434"
    p = get_provider(cfg, ReasonerMode.A)
    assert isinstance(p, OllamaProvider)
    assert p.connect_timeout == pytest.approx(1.25)
    assert p.read_timeout == pytest.approx(7.5)

    cfg.llm.provider = "gemma"
    cfg.llm.gemma_api_url = "http://example.invalid:8000"
    g = get_provider(cfg, ReasonerMode.A)
    assert isinstance(g, GemmaProvider)
    assert g.connect_timeout == pytest.approx(1.25)
    assert g.read_timeout == pytest.approx(7.5)

    cfg.llm.provider = "openai"
    cfg.llm.openai_api_key = "sk-test"
    o = get_provider(cfg, ReasonerMode.A)
    assert isinstance(o, OpenAIProvider)
    assert o.connect_timeout == pytest.approx(1.25)
    assert o.read_timeout == pytest.approx(7.5)


def test_run_reasoner_logs_readable_failure_reason(tmp_path, caplog, monkeypatch) -> None:
    cfg = IntelligenceConfig(data_dir=tmp_path)
    cfg.llm.provider = "gemma"
    cfg.llm.gemma_api_url = "http://unused.invalid"
    cfg.llm.max_retries = 0  # single attempt

    from depos.analysis import reasoning_engine as re_mod

    class _AlwaysFailProvider:
        name = "gemma-fake"

        def complete(self, prompt, *, max_tokens):
            raise ProviderError("transport", "gemma-fake HTTP 404", http_status=404)

    monkeypatch.setattr(re_mod, "get_provider", lambda *_args, **_kw: _AlwaysFailProvider())

    bundle = _minimal_bundle()
    stats = ReasonerCallStats()

    caplog.set_level(logging.WARNING, logger="depos.analysis.reasoning_engine")
    result = run_reasoner(
        bundle, mode=ReasonerMode.A, config=cfg, run_id="run-fail", stats=stats
    )
    assert result is None
    assert stats.failures == 1
    assert stats.by_reason.get("transport") == 1

    messages = [rec.getMessage() for rec in caplog.records]
    assert any("reasoner_call_failed" in m and "reason=transport" in m and "http_status=404" in m for m in messages)
    assert any("reasoner_call_exhausted" in m and "reason=transport" in m for m in messages)


def test_run_reasoner_counts_retry_failure_before_success(tmp_path, monkeypatch) -> None:
    cfg = IntelligenceConfig(data_dir=tmp_path)
    cfg.llm.provider = "gemma"
    cfg.llm.gemma_api_url = "http://unused.invalid"
    cfg.llm.max_retries = 2

    from depos.analysis import reasoning_engine as re_mod

    class _FailOnceThenSucceedProvider:
        name = "gemma-fake"

        def __init__(self) -> None:
            self.calls = 0

        def complete(self, prompt, *, max_tokens):
            self.calls += 1
            if self.calls == 1:
                raise ProviderError("transport", "gemma-fake timeout")
            return (
                json.dumps(
                    {
                        "mode": "A",
                        "findings": [
                            {
                                "bug_type": "missing_error_handling",
                                "description": "Recovered on retry.",
                                "trigger_condition": "retry path",
                                "affected_path": ["scope"],
                                "confidence": 0.7,
                                "graph_anchor_nodes": ["scope"],
                            }
                        ],
                    }
                ),
                {"model": "fake", "response_path_used": "response"},
            )

    provider = _FailOnceThenSucceedProvider()
    monkeypatch.setattr(re_mod, "get_provider", lambda *_args, **_kw: provider)

    stats = ReasonerCallStats()
    result = run_reasoner(
        _minimal_bundle(),
        mode=ReasonerMode.A,
        config=cfg,
        run_id="run-retry-success",
        stats=stats,
    )

    assert result is not None
    assert stats.attempts == 2
    assert stats.successes == 1
    assert stats.failures == 1
    assert stats.by_reason.get("transport") == 1
    assert stats.by_mode.get("A") == {"successes": 1, "failures": 1}


def test_reasoner_session_uses_tiered_ollama_timeouts(monkeypatch, tmp_path) -> None:
    cfg = IntelligenceConfig(data_dir=tmp_path)
    cfg.llm.provider = "ollama"
    cfg.llm.read_timeout_seconds = 60.0
    cfg.llm.ollama_first_call_timeout = 300.0
    cfg.llm.ollama_subsequent_timeout = 90.0

    seen: list[float] = []

    def fake_get_provider(config, mode):
        seen.append(config.llm.read_timeout_seconds)
        return object()

    monkeypatch.setattr("depos.analysis.reasoning_engine.get_provider", fake_get_provider)

    session = ReasonerSession(cfg)
    session.get_provider(ReasonerMode.A)
    session.get_provider(ReasonerMode.B)
    session.get_provider(ReasonerMode.C)

    assert seen == [300.0, 90.0, 90.0]


def test_validate_ollama_model_raises_for_missing_tag(monkeypatch) -> None:
    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {"models": [{"name": "gemma:2b"}, {"name": "llama3:8b"}]}

    monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: FakeResponse())

    with pytest.raises(RuntimeError, match="Ollama model 'gemma:27b' is not pulled"):
        _validate_ollama_model("http://localhost:11434", "gemma:27b")


def test_preflight_ollama_timeout_has_clear_message(monkeypatch) -> None:
    monkeypatch.setattr(
        httpx,
        "post",
        lambda *args, **kwargs: (_ for _ in ()).throw(httpx.ReadTimeout("timed out")),
    )

    with pytest.raises(RuntimeError, match="did not respond within 9.5s"):
        _preflight_ollama("http://localhost:11434", "gemma:2b", timeout=9.5)


def test_parse_repairs_generic_mode_b_payload() -> None:
    raw = json.dumps(
        {
            "mode": "B",
            "findings": [
                {
                    "bug_type": "semantic_mismatch",
                    "description": "Client and server disagree.",
                    "graph_anchor_nodes": ["client", "server"],
                    "remediation_suggestion": "Check both sides.",
                }
            ],
        }
    )

    parsed, repairs = _parse(ReasonerMode.B, raw)

    assert parsed.findings[0].violation_type == "semantic_mismatch"
    assert parsed.findings[0].component_a == "client"
    assert parsed.findings[0].component_b == "server"
    assert parsed.findings[0].disagreement == "Client and server disagree."
    assert "normalize_mode_specific_fields" in repairs


def test_parse_repairs_generic_mode_c_payload() -> None:
    raw = json.dumps(
        {
            "mode": "C",
            "findings": [
                {
                    "bug_type": "missing_guard",
                    "description": "Guard is missing on a risky path.",
                    "remediation_suggestion": "Add a null check.",
                    "graph_anchor_nodes": ["scope"],
                }
            ],
        }
    )

    parsed, repairs = _parse(ReasonerMode.C, raw)

    assert parsed.findings[0].flow_bug_type == "missing_guard"
    assert parsed.findings[0].operation == "unknown"
    assert parsed.findings[0].violating_path == ["scope"]
    assert parsed.findings[0].missing_guard == "Add a null check."
    assert "normalize_mode_specific_fields" in repairs
