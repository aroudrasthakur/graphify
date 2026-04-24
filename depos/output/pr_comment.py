"""Inline PR / MR comment body (GitHub / GitLab compatible Markdown)."""
from __future__ import annotations

from typing import Any

from depos.output.canonical import enrich_finding, enrich_violations_payload


def render_pr_comment(finding: dict[str, Any], *, include_status: bool = True) -> str:
    enriched = enrich_finding(finding) if "status" not in finding else finding
    sev = finding.get("severity", "info")
    desc = finding.get("description", "")
    status = enriched.get("status", "")
    head = f"**depOS** [{sev}]"
    if include_status and status:
        head += f" `status={status}`"
    det = finding.get("detector_name", "")
    return f"{head} ({det}): {desc}\n"


def _gray_zone_details(finding: dict[str, Any]) -> list[str]:
    if str(finding.get("status") or "") != "GRAY-ZONE":
        return []
    failed_rule = str(finding.get("failed_rule") or "").strip() or "unspecified"
    missing = finding.get("missing_evidence") or []
    if isinstance(missing, list):
        missing_text = ", ".join(str(item) for item in missing) if missing else "None recorded"
    else:
        missing_text = str(missing or "None recorded")
    confidence = finding.get("confidence_range") or (0.0, 1.0)
    if isinstance(confidence, (list, tuple)) and len(confidence) == 2:
        lower = float(confidence[0])
        upper = float(confidence[1])
    else:
        lower, upper = 0.0, 1.0
    action = str(finding.get("recommended_action") or "REVIEW_REQUIRED")
    return [
        "<details>",
        "<summary>Why gray-zone?</summary>",
        "",
        f"**Failed rule:** {failed_rule}",
        f"**Missing evidence:** {missing_text}",
        f"**Confidence:** {lower:.0%} - {upper:.0%}",
        f"**Action:** {action}",
        "</details>",
    ]


def render_violations_pr_comment(
    doc: dict[str, Any], *, enrich: bool = True, title: str = "## depOS scan"
) -> str:
    """Multi-finding PR body for a full ``violations.json`` run."""
    payload = enrich_violations_payload(doc) if enrich else doc
    lines = [title, ""]
    for finding in payload.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        status = finding.get("status", "")
        severity = finding.get("severity", "medium")
        detector = finding.get("detector_name", "")
        description = (finding.get("description") or "")[:2000]
        lines.append(f"- **{status}** | `{severity}` | `{detector}` | {description}")
        lines.extend(_gray_zone_details(finding))
    if len(lines) == 2:
        lines.append("_No findings._")
    lines.append("")
    return "\n".join(lines)


__all__ = ["render_pr_comment", "render_violations_pr_comment"]
