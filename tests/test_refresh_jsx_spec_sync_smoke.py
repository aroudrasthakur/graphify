"""Smoke test: refresh script runs and produces valid JSON with expected shape."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def test_refresh_jsx_spec_sync_script_exits_zero() -> None:
    proc = subprocess.run(
        [sys.executable, str(REPO / "tools" / "refresh_jsx_spec_sync.py")],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    manifest = REPO / "tests" / "fixtures" / "jsx_spec_sync_manifest.json"
    data = json.loads(manifest.read_text(encoding="utf-8"))
    assert data.get("version") == 1
    assert isinstance(data.get("files"), dict)
    assert len(data["files"]) >= 3
