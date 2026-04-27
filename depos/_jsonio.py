"""Fast JSON I/O adapter — orjson when available, stdlib json otherwise.

Usage::

    from depos._jsonio import dumps, loads

Both paths produce the same logical output. Raw bytes may differ between
orjson and stdlib json — never compare bytes cross-path. For artifacts
that need byte-stable output, use one writer end-to-end.

Byte-stable product artifacts are written directly by ``product_outputs.py``
via ``json.dumps(payload, indent=2)`` — do NOT route those files through
this module. The files in question:
    findings.json, impact_paths.json, mcp_context.json,
    triage_backlog.json, product_summary.json
"""
from __future__ import annotations

import json
from typing import Any

try:
    import orjson as _orjson

    def dumps(obj: Any, *, sort_keys: bool = True) -> bytes:
        """Serialize *obj* to compact UTF-8 JSON bytes."""
        opts = _orjson.OPT_NON_STR_KEYS
        if sort_keys:
            opts |= _orjson.OPT_SORT_KEYS
        return _orjson.dumps(obj, option=opts)

    def loads(data: bytes | str) -> Any:
        """Deserialize JSON *data* to a Python object."""
        return _orjson.loads(data)

except ImportError:

    def dumps(obj: Any, *, sort_keys: bool = True) -> bytes:  # type: ignore[misc]
        """Serialize *obj* to compact UTF-8 JSON bytes (stdlib fallback)."""
        return json.dumps(obj, sort_keys=sort_keys, separators=(",", ":")).encode()

    def loads(data: bytes | str) -> Any:  # type: ignore[misc]
        """Deserialize JSON *data* to a Python object (stdlib fallback)."""
        if isinstance(data, bytes):
            data = data.decode()
        return json.loads(data)


__all__ = ["dumps", "loads"]
