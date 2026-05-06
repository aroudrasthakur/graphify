"""Shared redaction for snippets, SARIF, PR comments, exports."""
from __future__ import annotations

import re
from typing import Any

# High-signal patterns only; avoid aggressive redaction of non-secrets.
_ASSIGN = re.compile(
    r'(?i)(api[_-]?key|secret|token|password|bearer)(\s*[:=]\s*)(?:"[^"]+"|\'[^\']+\'|[^\s"\']+)'
)


def _replace_assignment(m: re.Match[str]) -> str:
    return f'{m.group(1)}{m.group(2)}"**redacted**"'


_PATTERNS: tuple[tuple[re.Pattern[str], Any], ...] = (
    (_ASSIGN, _replace_assignment),
    (
        re.compile(
            r"(?i)-----BEGIN [A-Z ]+PRIVATE KEY-----[^-]+-----END [A-Z ]+PRIVATE KEY-----"
        ),
        "**redacted_pem**",
    ),
    (re.compile(r"\bsk-[A-Za-z0-9]{10,}\b"), "sk-**redacted**"),
)


def redact_secrets(text: str) -> str:
    if not text:
        return text
    out = text
    for pat, repl in _PATTERNS:
        if callable(repl):
            out = pat.sub(repl, out)
        else:
            out = pat.sub(repl, out)
    return out


def redact_obj(obj: Any) -> Any:
    """Recursively redact string leaves (dict/list/tuple)."""
    if isinstance(obj, str):
        return redact_secrets(obj)
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_obj(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(redact_obj(v) for v in obj)
    return obj
