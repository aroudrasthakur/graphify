"""Rolling precision rollup for per-detector false-positive feedback."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def rollup_path(data_dir: Path) -> Path:
    return Path(data_dir) / "detector_precision_rollup.json"


def load_rollup(path: Path) -> dict[str, float]:
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    if not isinstance(raw, dict):
        return {}
    out: dict[str, float] = {}
    for k, v in raw.items():
        try:
            out[str(k)] = float(v)
        except (TypeError, ValueError):
            continue
    return out


def save_rollup(path: Path, data: dict[str, float]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def merge_run_precision(
    existing: dict[str, float],
    stats: list[Any],
    *,
    alpha: float = 0.35,
) -> dict[str, float]:
    """Update rollup using per-detector verified_confirmed / (confirmed+invalid)."""

    out = dict(existing)
    for row in stats:
        name = str(getattr(row, "detector_name", "") or "").strip()
        if not name:
            continue
        vc = int(getattr(row, "verified_confirmed", 0) or 0)
        vi = int(getattr(row, "verified_invalid", 0) or 0)
        denom = vc + vi
        if denom <= 0:
            continue
        sample = vc / denom
        old = float(out.get(name, sample))
        out[name] = float(alpha) * sample + (1.0 - float(alpha)) * old
    return out
