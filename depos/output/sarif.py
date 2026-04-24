"""SARIF 2.1.0 export for depOS (GitHub Security tab + IDEs)."""
from __future__ import annotations

import json
from typing import Any

from depos.output.canonical import enrich_violations_payload


def _level(status: str | None, severity: str | None) -> str:
    if status == "GRAY-ZONE":
        return "note"
    if status != "CONFIRMED":
        return "note"
    s = (severity or "medium").lower()
    if s in ("critical", "high"):
        return "error"
    if s in ("medium",):
        return "warning"
    return "note"


def _gray_zone_message(finding: dict[str, Any]) -> str:
    description = str(finding.get("description") or finding.get("bug_type") or "finding")
    if str(finding.get("status") or "") != "GRAY-ZONE":
        return description
    failed_rule = str(finding.get("failed_rule") or "").strip()
    missing = finding.get("missing_evidence") or []
    missing_text = ", ".join(str(item) for item in missing) if isinstance(missing, list) else str(missing)
    parts = [description]
    if failed_rule:
        parts.append(f"Failed rule: {failed_rule}")
    if missing_text:
        parts.append(f"Missing evidence: {missing_text}")
    return "\n".join(parts)


def violations_to_sarif_runs(
    doc: dict[str, Any], *, run_index: int = 0, enrich: bool = True
) -> list[dict[str, Any]]:
    """Build one SARIF run from a ``violations.json``-style dict."""
    payload = enrich_violations_payload(doc) if enrich else doc
    meta = payload.get("run_metadata") or {}
    version = str(meta.get("pipeline_version") or "1")
    driver: dict[str, Any] = {
        "name": "depOS",
        "version": version,
        "fullName": "depOS static analysis",
    }
    results: list[dict[str, Any]] = []
    for f in payload.get("findings") or []:
        if not isinstance(f, dict):
            continue
        status = str(f.get("status") or "")
        if status == "CLEAN":
            continue
        fid = str(f.get("finding_id") or "")
        rule_id = str(f.get("detector_name") or "depos.finding")
        results.append(
            {
                "ruleId": rule_id,
                "message": {
                    "text": _gray_zone_message(f)
                },
                "level": _level(status, str(f.get("severity"))),
                "properties": {
                    "depOS_finding_id": fid,
                    "depOS_status": status,
                    "depOS_verifier_outcome": f.get("verifier_outcome"),
                },
            }
        )
    # Minimal rules array (some consumers require ruleIndex alignment)
    rules = [
        {
            "id": "depos.finding",
            "name": "depOS finding",
            "shortDescription": {"text": "depOS pipeline finding"},
        }
    ]
    if results:
        driver["rules"] = rules
    run = {
        "tool": {
            "driver": driver,
        },
        "results": results,
    }
    if payload.get("run_id"):
        run["automationDetails"] = {
            "id": f"depos/{payload.get('run_id', run_index)}"
        }
    return [run]


def render_sarif(
    doc: dict[str, Any],
    *,
    indent: int = 2,
    enrich: bool = True,
) -> str:
    out: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": violations_to_sarif_runs(doc, enrich=enrich),
    }
    return json.dumps(out, indent=indent, default=str)


__all__ = ["render_sarif", "violations_to_sarif_runs"]
