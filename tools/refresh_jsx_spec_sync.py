#!/usr/bin/env python3
"""Regenerate ``tests/fixtures/jsx_spec_sync_manifest.json`` from file contents (SHA-256).

This is the only sanctioned way to update the JSX/spec sync manifest after
editing any tracked file. Run from repo root:

    python tools/refresh_jsx_spec_sync.py
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SPEC = REPO / "docs" / "depos-pipeline.md"
JSX = REPO / "depos-pipeline.jsx"
MANIFEST = REPO / "tests" / "fixtures" / "jsx_spec_sync_manifest.json"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tracked_paths() -> list[Path]:
    paths: list[Path] = [SPEC, JSX]
    analysis = REPO / "depos" / "analysis"
    for p in sorted(analysis.rglob("*.py")):
        if "__pycache__" in p.parts:
            continue
        paths.append(p)
    return paths


def main() -> int:
    if not REPO.is_dir():
        print("error: could not find repo root", file=sys.stderr)
        return 1
    data: dict[str, str] = {}
    for path in tracked_paths():
        if not path.is_file():
            print(f"error: missing {path}", file=sys.stderr)
            return 1
        rel = path.relative_to(REPO).as_posix()
        data[rel] = _sha256_bytes(path.read_bytes())
    payload = {
        "version": 1,
        "files": data,
    }
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {len(data)} content hashes to {MANIFEST}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
