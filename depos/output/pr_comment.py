"""Inline PR / MR comment body (GitHub / GitLab compatible Markdown)."""
from __future__ import annotations

from typing import Any

from depos.output.canonical import enrich_finding, enrich_violations_payload


def render_pr_comment(finding: dict[str, Any], *, include_status: bool = True) -> str:
    f = enrich_finding(finding) if "status" not in finding else finding
    sev = finding.get("severity", "info")
    desc = finding.get("description", "")
    st = f.get("status", "")
    head = f"**depOS** [{sev}]"
    if include_status and st:
        head += f" `status={st}`"
    det = finding.get("detector_name", "")
    return f"{head} ({det}): {desc}\n"


def render_violations_pr_comment(
    doc: dict[str, Any], *, enrich: bool = True, title: str = "## depOS scan"
) -> str:
    """Multi-finding PR body for a full ``violations.json`` run."""
    payload = enrich_violations_payload(doc) if enrich else doc
    lines = [title, ""]
    for f in payload.get("findings") or []:
        if not isinstance(f, dict):
            continue
        st = f.get("status", "")
        sev = f.get("severity", "medium")
        det = f.get("detector_name", "")
        desc = (f.get("description") or "")[:2000]
        lines.append(
            f"- **{st}** · `{sev}` · `{det}` — {desc}"
        )
    if len(lines) == 2:
        lines.append("_No findings._")
    lines.append("")
    return "\n".join(lines)


__all__ = ["render_pr_comment", "render_violations_pr_comment"]
