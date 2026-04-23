"""Map verifier findings to a stable, CI-friendly ``status`` and export shape."""
from __future__ import annotations

from typing import Any, Literal

# Uppercase labels for IDEs and SARIF; aligned with :class:`VerifierOutcome`.
StatusLabel = Literal[
    "CLEAN",
    "CONFIRMED",
    "PARTIALLY_CONFIRMED",
    "UNCONFIRMED",
    "INVALID_REASONING",
    "EVALUATOR_SURFACED",
    "UNKNOWN",
]

_VERIFIER_TO_STATUS: dict[str, StatusLabel] = {
    "confirmed": "CONFIRMED",
    "partially_confirmed": "PARTIALLY_CONFIRMED",
    "unconfirmed": "UNCONFIRMED",
    "invalid_reasoning": "INVALID_REASONING",
    "evaluator_surfaced": "EVALUATOR_SURFACED",
}


def verifier_to_status(verifier_outcome: str | None) -> StatusLabel:
    if not verifier_outcome:
        return "UNKNOWN"
    return _VERIFIER_TO_STATUS.get(str(verifier_outcome), "UNKNOWN")


def default_recommended_action(
    status: StatusLabel, severity: str | None, *, uncited: bool = False
) -> str:
    if uncited and status in {"CONFIRMED", "PARTIALLY_CONFIRMED"}:
        return "REVIEW_REQUIRED"
    if status == "CONFIRMED" and severity in ("critical", "high"):
        return "REMEDIATE"
    if status in ("CONFIRMED", "PARTIALLY_CONFIRMED"):
        return "REVIEW"
    if status == "EVALUATOR_SURFACED":
        return "REVIEW_REQUIRED"
    return "MONITOR"


def enrich_finding(
    row: dict[str, Any],
    *,
    candidate_score: dict[str, Any] | None = None,
    seam_edges: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return a copy of a finding with ``status``, ``evidence_chain``, and metadata."""
    vo = row.get("verifier_outcome")
    st = verifier_to_status(vo if isinstance(vo, str) else getattr(vo, "value", None))
    sev = str(row.get("severity") or "medium")
    uncited = bool(row.get("uncited"))
    witness = list(row.get("witness_path") or [])
    out = {**row}
    out["status"] = st
    out["evidence_chain"] = {
        "witness_path": witness,
        "description": row.get("description") or "",
        "evidence_text": row.get("evidence_text") or "",
    }
    out["blast_radius"] = {
        "witness_hops": len(witness),
    }
    out["seam_edges"] = seam_edges or []
    out["candidate_score"] = candidate_score or {}
    out["recommended_action"] = default_recommended_action(
        st, sev, uncited=uncited
    )
    return out


def enrich_violations_payload(
    doc: dict[str, Any],
    *,
    per_finding_extras: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Add ``status``/evidence to each finding; set document ``status`` roll-up.

    ``doc`` matches ``violations.json``: ``run_id``, ``run_metadata``, ``findings``.
    """
    findings_in = list(doc.get("findings") or [])
    extras = per_finding_extras or {}
    findings_out: list[dict[str, Any]] = []
    worst: StatusLabel = "CLEAN"
    order = {
        "CLEAN": 0,
        "UNCONFIRMED": 1,
        "PARTIALLY_CONFIRMED": 2,
        "INVALID_REASONING": 2,
        "EVALUATOR_SURFACED": 3,
        "CONFIRMED": 4,
        "UNKNOWN": 1,
    }
    for f in findings_in:
        if not isinstance(f, dict):
            continue
        fid = str(f.get("finding_id") or "")
        extra = extras.get(fid, {})
        enriched = enrich_finding(
            f,
            candidate_score=extra.get("candidate_score"),
            seam_edges=extra.get("seam_edges"),
        )
        findings_out.append(enriched)
        s = enriched["status"]
        if order.get(s, 0) >= order.get(worst, 0):
            worst = s

    out = {**doc, "findings": findings_out}
    out["status"] = "CLEAN" if not findings_out else worst
    return out


__all__ = [
    "StatusLabel",
    "default_recommended_action",
    "enrich_finding",
    "enrich_violations_payload",
    "verifier_to_status",
]
