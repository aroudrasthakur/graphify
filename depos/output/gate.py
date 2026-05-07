"""CI gate: non-zero when CONFIRMED findings hit high/critical severity (allowlistable)."""
from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any

from depos.output.canonical import enrich_finding, verifier_to_status


def load_violations_path(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("violations file must be a JSON object")
    return data


def load_allowlist(path: str | Path = ".depOS/allowlist.json") -> set[str]:
    allowlist_path = Path(path)
    try:
        raw = json.loads(allowlist_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return set()
    if not isinstance(raw, list):
        return set()
    today = datetime.date.today().isoformat()
    allowed: set[str] = set()
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        finding_id = str(entry.get("finding_id") or "").strip()
        expires = str(entry.get("expires") or "").strip()
        if not finding_id:
            continue
        if expires and expires < today:
            continue
        allowed.add(finding_id)
    return allowed


def finding_triggers_gate(f: dict[str, Any]) -> bool:
    """True when this finding should fail a strict CI policy."""
    row = enrich_finding(f) if "status" not in f else f
    st = row.get("status") or verifier_to_status(str(f.get("verifier_outcome", "")))
    sev = str(f.get("severity") or "medium").lower()
    if st == "CONFIRMED" and sev in ("critical", "high"):
        return True
    return False


def evaluate_gate(
    findings: list[dict[str, Any]],
    *,
    allowlist: set[str],
    auto_suppress: set[str] | None = None,
) -> tuple[bool, list[dict[str, Any]]]:
    """Return (should_fail, blocking_findings).

    ``auto_suppress`` is merged with ``allowlist`` (e.g. ids from a rolling
    invalid-reasoning digest). ``finding_id_legacy`` is honored when stable ids are enabled.
    """
    suppressed = set(allowlist)
    if auto_suppress:
        suppressed |= auto_suppress
    blocking: list[dict[str, Any]] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        fid = str(f.get("finding_id") or "")
        leg = str(f.get("finding_id_legacy") or "")
        if fid and fid in suppressed:
            continue
        if leg and leg in suppressed:
            continue
        if finding_triggers_gate(f):
            blocking.append(f)
    return (len(blocking) > 0, blocking)


def load_auto_suppress(path: str | Path) -> set[str]:
    """Load optional JSON array of ``finding_id`` strings to treat as allowlisted."""

    p = Path(path)
    if not p.is_file():
        return set()
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return set()
    if isinstance(raw, dict) and "finding_ids" in raw:
        raw = raw["finding_ids"]
    if not isinstance(raw, list):
        return set()
    return {str(x).strip() for x in raw if str(x).strip()}


__all__ = [
    "evaluate_gate",
    "finding_triggers_gate",
    "load_allowlist",
    "load_auto_suppress",
    "load_violations_path",
]
