"""Canonical JSON export for depOS violations and findings."""
from __future__ import annotations

import json
from typing import Any

from depos.output.canonical import enrich_violations_payload


def render_findings(
    data: list[dict[str, Any]] | dict[str, Any], *, indent: int = 2
) -> str:
    return json.dumps(data, indent=indent, default=str)


def render_violations_document(
    doc: dict[str, Any], *, indent: int = 2, enrich: bool = True
) -> str:
    """Render ``violations.json``-shaped document; by default add ``status`` per finding."""
    out = enrich_violations_payload(doc) if enrich else doc
    return json.dumps(out, indent=indent, default=str)


__all__ = ["render_findings", "render_violations_document"]
