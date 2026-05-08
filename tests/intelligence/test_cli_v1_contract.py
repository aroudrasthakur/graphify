"""depOS v1 CLI contract: umbrella ``depos`` entrypoint, profiles, serve hint."""
from __future__ import annotations

import pytest

from depos.cli import _build_parser, main, main_depos
from depos.cli.v1_profile import apply_v1_profile, validate_v1_profile


def test_main_depos_help_shows_v1_epilog(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        main_depos(["--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert "depos analyze repo" in combined or "V1 quick start" in combined


def test_depos_serve_exits_zero(capsys) -> None:
    rc = main_depos(["serve"])
    assert rc == 0
    err = capsys.readouterr().err
    assert "depos-api" in err


def test_repo_parser_has_run_profile_default_full() -> None:
    p = _build_parser(prog="depos-intel")
    ns = p.parse_args(["analyze", "repo", "--path", "."])
    assert ns.run_profile == "full"


def test_repo_parser_profile_preset_default_custom() -> None:
    p = _build_parser(prog="depos-intel")
    ns = p.parse_args(["analyze", "repo", "--path", "."])
    assert ns.profile_preset == "custom"


def test_repo_parser_profile_preset_pr_fast() -> None:
    p = _build_parser(prog="depos-intel")
    ns = p.parse_args(["analyze", "repo", "--path", ".", "--profile-preset", "pr-fast"])
    assert ns.profile_preset == "pr-fast"


def test_perf_preset_pr_fast_disables_expensive_without_env(monkeypatch) -> None:
    monkeypatch.delenv("DEPOS_PERF_GRAPH_METRICS_EXPENSIVE", raising=False)
    from types import SimpleNamespace

    from depos.cli.analyze import _perf_config_from_args

    perf = _perf_config_from_args(
        SimpleNamespace(
            profile_preset="pr-fast",
            no_parallel=False,
            taint_n_jobs=None,
            bundle_n_jobs=None,
            cfg_dfg_n_jobs=None,
            no_expensive_metrics=False,
            metrics_backend=None,
        )
    )
    assert perf.graph_metrics_expensive is False


def test_perf_preset_pr_fast_respects_env_expensive(monkeypatch) -> None:
    monkeypatch.setenv("DEPOS_PERF_GRAPH_METRICS_EXPENSIVE", "1")
    from types import SimpleNamespace

    from depos.cli.analyze import _perf_config_from_args

    perf = _perf_config_from_args(
        SimpleNamespace(
            profile_preset="pr-fast",
            no_parallel=False,
            taint_n_jobs=None,
            bundle_n_jobs=None,
            cfg_dfg_n_jobs=None,
            no_expensive_metrics=False,
            metrics_backend=None,
        )
    )
    assert perf.graph_metrics_expensive is True


def test_perf_preset_nightly_deep_prefers_rustworkx_when_unset(monkeypatch) -> None:
    monkeypatch.delenv("DEPOS_PERF_METRICS_BACKEND", raising=False)
    monkeypatch.delenv("DEPOS_PERF_GRAPH_METRICS_EXPENSIVE", raising=False)
    from types import SimpleNamespace

    from depos.cli.analyze import _perf_config_from_args

    perf = _perf_config_from_args(
        SimpleNamespace(
            profile_preset="nightly-deep",
            no_parallel=False,
            taint_n_jobs=None,
            bundle_n_jobs=None,
            cfg_dfg_n_jobs=None,
            no_expensive_metrics=False,
            metrics_backend=None,
        )
    )
    assert perf.graph_metrics_expensive is True
    assert perf.metrics_backend == "rustworkx"


def test_apply_profile_preset_pr_fast_caps_seeds() -> None:
    from types import SimpleNamespace

    from depos.analysis.config import CandidateBudget, IntelligenceConfig
    from depos.cli.analyze import _apply_profile_preset_to_config

    cfg = IntelligenceConfig(candidates=CandidateBudget(max_seeds=80))
    out = _apply_profile_preset_to_config(cfg, SimpleNamespace(profile_preset="pr-fast", max_seeds=None))
    assert out.candidates.max_seeds == 50


def test_apply_profile_preset_skips_seed_cap_when_max_seeds_cli() -> None:
    from types import SimpleNamespace

    from depos.analysis.config import CandidateBudget, IntelligenceConfig
    from depos.cli.analyze import _apply_profile_preset_to_config

    cfg = IntelligenceConfig(candidates=CandidateBudget(max_seeds=80))
    out = _apply_profile_preset_to_config(cfg, SimpleNamespace(profile_preset="pr-fast", max_seeds=200))
    assert out.candidates.max_seeds == 80
    with pytest.raises(ValueError, match="invalid"):
        validate_v1_profile("nope")


def test_apply_v1_profile_local_sets_stub(monkeypatch) -> None:
    monkeypatch.delenv("DEPOS_INTEL_PROVIDER", raising=False)
    monkeypatch.delenv("DEPOS_GRAY_ZONE_ENABLED", raising=False)
    apply_v1_profile("local")
    import os

    assert os.environ.get("DEPOS_INTEL_PROVIDER") == "stub"
    assert os.environ.get("DEPOS_GRAY_ZONE_ENABLED") == "0"


def test_apply_v1_profile_respects_existing_env(monkeypatch) -> None:
    monkeypatch.setenv("DEPOS_INTEL_PROVIDER", "openai")
    monkeypatch.setenv("DEPOS_GRAY_ZONE_ENABLED", "1")
    apply_v1_profile("local")
    import os

    assert os.environ.get("DEPOS_INTEL_PROVIDER") == "openai"
    assert os.environ.get("DEPOS_GRAY_ZONE_ENABLED") == "1"


def test_main_intelligence_dispatch_unchanged(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["analyze", "dataset-pipeline", "--help"])
    assert exc.value.code == 0
