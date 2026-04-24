from __future__ import annotations

from argparse import Namespace
from pathlib import Path

from depos.analysis.config import IntelligenceConfig, load_config_from_env
from depos.cli import analyze as analyze_cli


def test_replay_config_reads_intel_path_env(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("DEPOS_INTEL_DATA_DIR", str(tmp_path / "out"))
    monkeypatch.setenv("DEPOS_INTEL_RUN_OUTPUT_SUBDIR", ".canonical")
    base = load_config_from_env()
    assert base.data_dir != tmp_path / "out"  # replay env must not alter global config
    cfg = analyze_cli._replay_intelligence_config(base, Namespace())
    assert cfg.data_dir == tmp_path / "out"
    assert cfg.run_output_subdir == ".canonical"


def test_replay_intelligence_config_cli_overrides(tmp_path) -> None:
    base = IntelligenceConfig(data_dir=Path("depos-data"), run_output_subdir="intelligence")
    args = Namespace(data_dir=str(tmp_path / "dataset-out"), run_subdir=".canonical")
    cfg = analyze_cli._replay_intelligence_config(base, args)
    assert cfg.data_dir == tmp_path / "dataset-out"
    assert cfg.run_output_subdir == ".canonical"


def test_load_config_from_env_llm_timeouts(monkeypatch) -> None:
    monkeypatch.setenv("DEPOS_LLM_CONNECT_TIMEOUT", "2.5")
    monkeypatch.setenv("DEPOS_LLM_READ_TIMEOUT", "45")
    monkeypatch.setenv("DEPOS_LLM_OLLAMA_PREFLIGHT_TIMEOUT", "12")
    monkeypatch.setenv("DEPOS_LLM_OLLAMA_FIRST_CALL_TIMEOUT", "240")
    monkeypatch.setenv("DEPOS_LLM_OLLAMA_SUBSEQUENT_TIMEOUT", "75")
    monkeypatch.setenv("DEPOS_BUNDLE_MAX_CALLER_TEXTS", "2")
    monkeypatch.setenv("DEPOS_BUNDLE_MAX_CALLEE_TEXTS", "4")
    monkeypatch.setenv("DEPOS_BUNDLE_MAX_SEAM_NEIGHBOR_TEXTS", "5")
    monkeypatch.setenv("DEPOS_BUNDLE_MAX_SNIPPET_CHARS", "300")
    monkeypatch.setenv("DEPOS_BUNDLE_MAX_PROMPT_TOKENS", "1500")
    cfg = load_config_from_env()
    assert cfg.llm.connect_timeout_seconds == 2.5
    assert cfg.llm.read_timeout_seconds == 45.0
    assert cfg.llm.ollama_preflight_timeout == 12.0
    assert cfg.llm.ollama_first_call_timeout == 240.0
    assert cfg.llm.ollama_subsequent_timeout == 75.0
    assert cfg.bundles.max_caller_texts == 2
    assert cfg.bundles.max_callee_texts == 4
    assert cfg.bundles.max_seam_neighbor_texts == 5
    assert cfg.bundles.max_snippet_chars == 300
    assert cfg.bundles.max_prompt_tokens == 1500
