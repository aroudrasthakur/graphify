"""Load intent artifacts from disk."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from depos.intent_context.schemas import (
    CoverageTagRecord,
    IntentChunkRecord,
    IntentManifest,
    IntentTraceHints,
    IntentUnit,
)


def load_manifest(intent_dir: Path) -> IntentManifest:
    raw = json.loads((intent_dir / "intent_manifest.json").read_text(encoding="utf-8"))
    return IntentManifest(**raw)


def load_units(intent_dir: Path) -> list[IntentUnit]:
    path = intent_dir / "intent_units.json"
    if not path.exists():
        return []
    raw = json.loads(path.read_text(encoding="utf-8"))
    return [IntentUnit(**row) for row in raw]


def load_chunks(intent_dir: Path) -> dict[str, tuple[str, int, int]]:
    """chunk_id -> (source_relpath, start_line, end_line)."""
    out: dict[str, tuple[str, int, int]] = {}
    path = intent_dir / "intent_chunks.jsonl"
    if not path.exists():
        return out
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = IntentChunkRecord(**json.loads(line))
            out[rec.chunk_id] = (rec.source_relpath, rec.start_line, rec.end_line)
    return out


def load_trace_hints(intent_dir: Path) -> IntentTraceHints | None:
    path = intent_dir / "intent_trace_hints.json"
    if not path.exists():
        return None
    raw = json.loads(path.read_text(encoding="utf-8"))
    return IntentTraceHints(**raw)


def load_coverage_tags(intent_dir: Path) -> list[CoverageTagRecord]:
    path = intent_dir / "intent_coverage_tags.jsonl"
    if not path.exists():
        return []
    out: list[CoverageTagRecord] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            out.append(CoverageTagRecord(**json.loads(line)))
    return out
