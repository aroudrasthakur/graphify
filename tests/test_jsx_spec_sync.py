"""Content-hash sync between ``docs/depos-pipeline.md``, ``depos/analysis/**``, and ``depos-pipeline.jsx``.

**Forbidden (anti-patterns):** using ``os.path.exists``, ``os.path.getmtime``,
``Path.stat().st_mtime``, git log timestamps, or "touched in last commit" to
decide pass/fail. Only SHA-256 over raw file bytes.

**Proof scenarios (manual / CI review):**
1. Edit any tracked ``depos/analysis/*.py`` without changing ``depos-pipeline.jsx`` or
   re-running ``python tools/refresh_jsx_spec_sync.py`` → this test fails.
2. ``touch depos-pipeline.jsx`` (mtime only) → content hash unchanged → still fails if
   manifest is stale; mtime alone never fixes a real drift.
3. Edit JSX + run the refresh script → all hashes match → test passes.

**Render check:** import ``DeposPipelineDiagram`` from ``depos-pipeline.jsx`` in any
React 18+ app or use ``npx vite`` with ``@vitejs/plugin-react`` and a one-line import.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "tests" / "fixtures" / "jsx_spec_sync_manifest.json"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def test_jsx_spec_manifest_matches_file_contents() -> None:
    assert MANIFEST.is_file(), "run: python tools/refresh_jsx_spec_sync.py"
    raw = json.loads(MANIFEST.read_text(encoding="utf-8"))
    files: dict[str, str] = raw.get("files") or {}
    assert files, "manifest has no files entry"
    for rel, expected in sorted(files.items()):
        path = REPO.joinpath(*rel.split("/"))
        assert path.is_file(), f"missing tracked file: {rel}"
        actual = _sha256_file(path)
        assert actual == expected, (
            f"content drift: {rel}\n"
            f"  expected sha256={expected}\n"
            f"  actual   sha256={actual}\n"
            "Update depos-pipeline.jsx to reflect spec/pipeline changes, then run:\n"
            "  python tools/refresh_jsx_spec_sync.py"
        )


def test_refresh_script_is_listed_in_manifest() -> None:
    raw = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert "docs/depos-pipeline.md" in raw["files"]
    assert "depos-pipeline.jsx" in raw["files"]
    assert any(x.startswith("depos/analysis/") for x in raw["files"])
