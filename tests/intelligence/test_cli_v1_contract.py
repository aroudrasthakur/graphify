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


def test_validate_v1_profile_invalid() -> None:
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
