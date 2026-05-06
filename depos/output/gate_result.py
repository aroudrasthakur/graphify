"""Authoritative ``gate_result.json`` — unified CI/review outcome for a run directory."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from depos.output.gate import evaluate_gate, load_allowlist, load_violations_path

GATE_RESULT_SCHEMA_VERSION = "1.0"
GATE_RESULT_FILENAME = "gate_result.json"


def _product_ci_from_dir(out_dir: Path) -> tuple[bool | None, list[str]]:
    """Load optional ``product_summary.json`` and return (should_block, blocking_ids)."""
    path = out_dir / "product_summary.json"
    if not path.is_file():
        return None, []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None, []
    decision = data.get("ci_decision") if isinstance(data, dict) else None
    if not isinstance(decision, dict):
        return None, []
    should_block = decision.get("should_block")
    ids = decision.get("blocking_finding_ids") or []
    if not isinstance(should_block, bool):
        should_block = None
    if not isinstance(ids, list):
        ids = []
    return should_block, [str(x) for x in ids]


def build_gate_result(
    violations_doc: dict[str, Any],
    *,
    allowlist: set[str],
    product_should_block: bool | None = None,
    product_blocking_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Compute gate outcome with precedence: legacy violations gate ∪ product CI block.

    ``reasoner_run_health`` is surfaced for operators but does not flip ``outcome``
    to ``block`` unless a separate strict mode is enabled (see ``depos-intel analyze --strict``).
    """
    findings = list(violations_doc.get("findings") or [])
    legacy_fail, legacy_blocking = evaluate_gate(findings, allowlist=allowlist)
    legacy_ids = [str(b.get("finding_id")) for b in legacy_blocking if b.get("finding_id")]

    product_fail = bool(product_should_block) if product_should_block is not None else False
    product_ids = list(product_blocking_ids or [])

    block = legacy_fail or product_fail
    combined_ids = sorted(set(legacy_ids + product_ids))

    meta = violations_doc.get("run_metadata") or {}
    health = str(meta.get("reasoner_run_health") or "ok")
    health_reason = str(meta.get("reasoner_health_reason") or "")

    review_only_count = 0
    gray_count = 0
    for f in findings:
        if not isinstance(f, dict):
            continue
        st = str(f.get("verifier_outcome") or "").lower()
        if "gray" in st or str(f.get("trust_level") or "").lower() in {"gray_zone", "evaluator_surfaced"}:
            gray_count += 1
        # Heuristic: partially confirmed / unconfirmed are review signals, not CI blockers here.
        if st in {"partially_confirmed", "unconfirmed"}:
            review_only_count += 1

    if block:
        outcome = "block"
        exit_code = 1
        reasons = ["legacy_confirmed_high_critical" if legacy_fail else None, "product_ci_block" if product_fail else None]
    elif health in {"failed", "degraded"}:
        outcome = "degraded"
        exit_code = 0
        reasons = ["reasoner_run_health"]
    elif review_only_count or gray_count:
        outcome = "review_needed"
        exit_code = 0
        reasons = []
        if review_only_count:
            reasons.append(f"inconclusive_findings={review_only_count}")
        if gray_count:
            reasons.append(f"gray_zone_rows={gray_count}")
    else:
        outcome = "pass"
        exit_code = 0
        reasons = []

    reasons = [r for r in reasons if r]

    return {
        "schema_version": GATE_RESULT_SCHEMA_VERSION,
        "outcome": outcome,
        "exit_code": exit_code,
        "blocking_finding_ids": combined_ids,
        "legacy_gate_failed": legacy_fail,
        "legacy_blocking_finding_ids": sorted(set(legacy_ids)),
        "product_ci_should_block": product_should_block,
        "product_blocking_finding_ids": sorted(set(product_ids)),
        "reasoner_run_health": health,
        "reasoner_health_reason": health_reason,
        "precedence": "block_if_legacy_or_product_ci_else_surface_health_and_review_hints",
        "reasons": reasons,
    }


def write_gate_result_for_directory(
    out_dir: Path,
    *,
    allowlist_path: Path | None = None,
) -> Path:
    """Read ``violations.json`` (+ optional product summary) and write ``gate_result.json``."""
    out_dir = Path(out_dir)
    vpath = out_dir / "violations.json"
    doc = load_violations_path(vpath)
    allow = load_allowlist(allowlist_path if allowlist_path is not None else Path(".depOS/allowlist.json"))
    prod_block, prod_ids = _product_ci_from_dir(out_dir)
    result = build_gate_result(
        doc,
        allowlist=allow,
        product_should_block=prod_block,
        product_blocking_ids=prod_ids,
    )
    dest = out_dir / GATE_RESULT_FILENAME
    dest.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    return dest


__all__ = [
    "GATE_RESULT_SCHEMA_VERSION",
    "GATE_RESULT_FILENAME",
    "build_gate_result",
    "write_gate_result_for_directory",
]
