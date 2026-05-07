"""Dependency-finding rollup for violations / SARIF / dashboards."""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

_DEPS_DETECTORS: frozenset[str] = frozenset(
    {
        "phantom-dep",
        "vulnerable-dep",
        "lockfile-drift",
        "dep-version-mismatch-across-workspaces",
        "unused-dep",
        "peer-dep-unsatisfied",
        "transitive-pin-conflict",
    }
)

_PHANTOM_NODE = re.compile(r"^pkg::phantom:(.+)$")


def _package_from_witnesses(witness_path: Any) -> str | None:
    if not isinstance(witness_path, list):
        return None
    for raw in witness_path:
        s = str(raw)
        m = _PHANTOM_NODE.match(s)
        if m:
            return m.group(1)
    return None


def resolve_dependency_package(finding: dict[str, Any]) -> str | None:
    raw = finding.get("dependency_package")
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    return _package_from_witnesses(finding.get("witness_path"))


def build_dep_summary(findings: list[Any]) -> dict[str, Any]:
    """Roll up dependency-related findings by package name (when known)."""
    by_package: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_detector: dict[str, int] = defaultdict(int)
    without_package: list[dict[str, Any]] = []

    for f in findings:
        if not isinstance(f, dict):
            continue
        det = str(f.get("detector_name") or "")
        if det not in _DEPS_DETECTORS:
            continue
        by_detector[det] += 1
        pkg = resolve_dependency_package(f)
        row = {
            "finding_id": f.get("finding_id"),
            "detector_name": det,
            "status": f.get("status"),
        }
        if pkg:
            by_package[pkg].append(row)
        else:
            without_package.append(row)

    return {
        "detectors": sorted(_DEPS_DETECTORS),
        "counts_by_detector": dict(sorted(by_detector.items())),
        "by_package": {k: v for k, v in sorted(by_package.items())},
        "without_package_key": without_package,
        "packages_affected": len(by_package),
        "findings_included": sum(by_detector.values()),
    }


__all__ = ["build_dep_summary", "resolve_dependency_package"]
