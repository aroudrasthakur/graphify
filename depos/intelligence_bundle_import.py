"""Load CLI ``violations.json`` (+ optional manifest) into API run-create shape."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _normalize_trust_level(raw: str | None) -> str:
    if raw in ("confirmed", "partially_confirmed", "evaluator_surfaced"):
        return raw
    if raw in ("unconfirmed", "invalid_reasoning"):
        return "evaluator_surfaced"
    return "partially_confirmed"


def verify_manifest_checksums(bundle_dir: Path, manifest: dict[str, Any]) -> None:
    import hashlib

    if manifest.get("schema_version") is None:
        raise ValueError("run_manifest missing schema_version")
    artifacts = manifest.get("artifacts") or {}

    def _sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as fp:
            for chunk in iter(lambda: fp.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    for name, meta in artifacts.items():
        if not isinstance(meta, dict) or meta.get("missing"):
            continue
        expected = meta.get("sha256")
        if not expected:
            continue
        path = bundle_dir / name
        if not path.is_file():
            raise ValueError(f"artifact {name} missing on disk")
        h = _sha256_file(path)
        if h != expected:
            raise ValueError(f"checksum mismatch for {name}: expected {expected}, got {h}")


def run_bundle_dict_from_directory(
    bundle_dir: Path,
    *,
    repo_slug: str,
    verify_checksums: bool = True,
) -> dict[str, Any]:
    """Return a dict compatible with :class:`IntelligenceRunCreate` validation."""
    bundle_dir = bundle_dir.resolve()
    viol = bundle_dir / "violations.json"
    if not viol.is_file():
        raise FileNotFoundError(f"violations.json not found under {bundle_dir}")
    doc = json.loads(viol.read_text(encoding="utf-8"))
    meta = doc.get("run_metadata") or {}
    manifest_path = bundle_dir / "run_manifest.json"
    if verify_checksums and manifest_path.is_file():
        verify_manifest_checksums(bundle_dir, json.loads(manifest_path.read_text(encoding="utf-8")))

    findings_out: list[dict[str, Any]] = []
    for row in doc.get("findings") or []:
        if not isinstance(row, dict):
            continue
        tl = row.get("trust_level") or row.get("verifier_outcome")
        findings_out.append(
            {
                "trust_level": _normalize_trust_level(str(tl) if tl is not None else None),
                "mode": row.get("mode"),
                "bug_type": str(row.get("bug_type") or ""),
                "description": str(row.get("description") or ""),
                "affected_components": list(row.get("affected_components") or []),
                "witness_path": list(row.get("witness_path") or []),
                "missing_guard": row.get("missing_guard"),
                "recommended_fix": row.get("recommended_fix"),
                "reasoner_confidence": float(row.get("reasoner_confidence") or 0.0),
                "ranking_phase": int(row.get("ranking_phase") or 0),
                "verifier_outcome": str(row.get("verifier_outcome") or tl or ""),
                "verifier_checks_passed": list(row.get("verifier_checks_passed") or []),
                "verifier_checks_inconclusive": list(row.get("verifier_checks_inconclusive") or []),
                "rls_verdict": row.get("rls_verdict"),
                "migration_state_facts": dict(row.get("migration_state_facts") or {}),
                "caveats": dict(row.get("caveats") or {}),
                "detector_name": str(row.get("detector_name") or "legacy"),
                "detector_version": str(row.get("detector_version") or "0"),
                "pipeline_version": str(row.get("pipeline_version") or meta.get("pipeline_version") or "0"),
                "severity": str(row.get("severity") or "medium"),
            }
        )

    stats_out: list[dict[str, Any]] = []
    for row in doc.get("detector_stats") or []:
        if not isinstance(row, dict):
            continue
        stats_out.append(
            {
                "detector_name": str(row.get("detector_name") or "legacy"),
                "detector_version": str(row.get("detector_version") or "0"),
                "candidates_emitted": int(row.get("candidates_emitted") or 0),
                "verified_confirmed": int(row.get("verified_confirmed") or 0),
                "verified_invalid": int(row.get("verified_invalid") or 0),
                "mean_latency_ms": float(row.get("mean_latency_ms") or 0.0),
                "errors": list(row.get("errors") or []),
            }
        )

    return {
        "repo_slug": repo_slug,
        "base_ref": meta.get("base_ref"),
        "head_ref": meta.get("head_ref"),
        "analysis_mode": meta.get("analysis_mode") or "full_repo_scan",
        "provider": meta.get("provider"),
        "low_stitcher_coverage": bool(meta.get("low_stitcher_coverage", False)),
        "token_estimator": str(meta.get("token_estimator") or "chars4"),
        "ranking_phase": int(meta.get("ranking_phase") or 0),
        "status": "succeeded",
        "pack_manifest_id": meta.get("pack_manifest_id"),
        "pipeline_version": str(meta.get("pipeline_version") or "0"),
        "ingest_errors": list(meta.get("ingest_errors") or []),
        "universes_present": list(meta.get("universes_present") or []),
        "enabled_detectors": list(meta.get("enabled_detectors") or []),
        "reasoner_run_health": meta.get("reasoner_run_health") or "ok",
        "reasoner_health_reason": str(meta.get("reasoner_health_reason") or ""),
        "reasoner_attempts": int(meta.get("reasoner_attempts") or 0),
        "reasoner_successes": int(meta.get("reasoner_successes") or 0),
        "reasoner_failures": int(meta.get("reasoner_failures") or 0),
        "reasoner_failure_breakdown": dict(meta.get("reasoner_failure_breakdown") or {}),
        "evidence_summary": dict(meta.get("evidence_summary") or {}),
        "bundles_built": int(meta.get("bundles_built") or 0),
        "bundles_sent_to_reasoner": int(meta.get("bundles_sent_to_reasoner") or 0),
        "bundles_skipped_low_evidence": int(meta.get("bundles_skipped_low_evidence") or 0),
        "dataset_path_resolution": dict(meta.get("dataset_path_resolution") or {}),
        "detector_stats": stats_out,
        "findings": findings_out,
    }


def load_bundle_sidecars(bundle_dir: Path) -> dict[str, Any]:
    """Load optional v1 bundle files for API/UI echo (not persisted on ``IntelligenceRun`` rows).

    ``gate_result.json`` is returned in full when valid JSON. ``run_manifest.json`` is
    summarized to avoid large payloads.
    """
    bundle_dir = Path(bundle_dir)
    out: dict[str, Any] = {}
    gate_path = bundle_dir / "gate_result.json"
    if gate_path.is_file():
        try:
            out["gate_result"] = json.loads(gate_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            out["gate_result"] = None
    manifest_path = bundle_dir / "run_manifest.json"
    if manifest_path.is_file():
        try:
            raw = json.loads(manifest_path.read_text(encoding="utf-8"))
            arts = raw.get("artifacts") if isinstance(raw, dict) else None
            n = len(arts) if isinstance(arts, dict) else 0
            out["run_manifest_summary"] = {
                "schema_version": raw.get("schema_version") if isinstance(raw, dict) else None,
                "artifact_count": n,
                "present": True,
            }
        except (json.JSONDecodeError, OSError):
            out["run_manifest_summary"] = {"present": True, "parse_error": True}
    return out
