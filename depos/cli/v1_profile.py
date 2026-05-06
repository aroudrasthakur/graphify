"""depOS v1 analysis profiles (CLI-first local workflows).

Config precedence (documented): CLI flags > environment > project defaults > profile presets.

Profiles only set environment variables when those keys are **not** already set,
so operators can always override via ``export DEPOS_INTEL_PROVIDER=...``.
"""
from __future__ import annotations

import os
from typing import Literal

V1Profile = Literal["local", "full", "llm"]

_PROFILE_ENV_LOCAL: dict[str, str] = {
    # Deterministic / offline-friendly reasoner (no network by default).
    "DEPOS_INTEL_PROVIDER": "stub",
    # Skip gray-zone LLM panel for fully local runs unless explicitly enabled.
    "DEPOS_GRAY_ZONE_ENABLED": "0",
}

_PROFILE_ENV_LLM: dict[str, str] = {
    # Prefer real providers when user chose llm profile; do not force stub.
    "DEPOS_GRAY_ZONE_ENABLED": "1",
}


def apply_v1_profile(profile: str | None) -> None:
    """Apply preset environment for ``--run-profile`` before :func:`load_config_from_env`.

    - ``local``: stub reasoner, gray-zone off (unless env already set).
    - ``full``: no automatic env changes (use existing ``DEPOS_*`` / defaults).
    - ``llm``: re-enable gray-zone if unset; does not set provider (use env or flags).
    """
    if not profile or profile == "full":
        return
    p = profile.strip().lower()
    if p == "local":
        for key, val in _PROFILE_ENV_LOCAL.items():
            if key not in os.environ or not str(os.environ.get(key, "")).strip():
                os.environ[key] = val
        return
    if p == "llm":
        for key, val in _PROFILE_ENV_LLM.items():
            if key not in os.environ or not str(os.environ.get(key, "")).strip():
                os.environ[key] = val
        return
    raise ValueError(f"unknown v1 profile: {profile!r}; expected local, full, or llm")


def validate_v1_profile(profile: str | None) -> str:
    """Return normalized profile name or raise ``ValueError``."""
    if profile is None or str(profile).strip() == "":
        return "full"
    p = str(profile).strip().lower()
    if p not in ("local", "full", "llm"):
        raise ValueError(f"invalid --run-profile {profile!r}; choose local, full, or llm")
    return p
