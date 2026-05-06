"""Redaction helpers used across SARIF/exports."""
from __future__ import annotations

import pytest

from depos.output.redaction import redact_obj, redact_secrets


def test_redact_api_key_assignment() -> None:
    s = 'export API_KEY="supersecret123"'
    out = redact_secrets(s)
    assert "supersecret123" not in out
    assert "redacted" in out.lower()


def test_redact_sk_openai_style() -> None:
    s = "token sk-abcdefghijklmnopqrstuvwxyz"
    out = redact_secrets(s)
    assert "sk-ant" not in out.replace("redacted", "")  # pattern is sk- + alnum
    assert "redacted" in out


def test_redact_obj_nested() -> None:
    d = {"a": {"b": "password: hunter2"}}
    o = redact_obj(d)
    assert "hunter2" not in str(o)
