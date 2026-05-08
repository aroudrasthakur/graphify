"""Stable ``run_manifest.json`` for depOS local run bundles.

Written after primary artifacts (``violations.json``, product outputs, etc.)
so paths and checksums reflect the final on-disk state.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from importlib.metadata import PackageNotFoundError, version as package_version
except ImportError:  # pragma: no cover
    PackageNotFoundError = Exception
    package_version = None  # type: ignore[assignment]

from depos.analysis.config import IntelligenceConfig
from depos.analysis.schemas import RunResult

RUN_MANIFEST_SCHEMA_VERSION = "1.0"
RUN_MANIFEST_FILENAME = "run_manifest.json"


def _dist_version() -> str:
    if package_version is None:
        return "unknown"
    try:
        return package_version("graphifyy")
    except Exception:  # noqa: BLE001
        try:
            return package_version("graphify")
        except Exception:  # noqa: BLE001
            return "unknown"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda: fp.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _git_state(repo_root: Path | None) -> dict[str, Any]:
    if repo_root is None:
        return {"available": False, "reason": "no_repo_root"}
    try:
        root = repo_root.resolve()
    except OSError:
        return {"available": False, "reason": "resolve_failed"}
    if not (root / ".git").exists():
        return {"available": False, "reason": "not_a_git_checkout", "path": str(root)}
    try:
        head = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if head.returncode != 0:
            return {"available": False, "reason": "rev_parse_failed", "stderr": (head.stderr or "").strip()[:500]}
        sha = (head.stdout or "").strip()
        st = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        dirty = bool((st.stdout or "").strip()) if st.returncode == 0 else None
        return {"available": True, "head_sha": sha, "is_dirty": dirty, "path": str(root)}
    except (FileNotFoundError, subprocess.SubprocessError, OSError) as exc:
        return {"available": False, "reason": type(exc).__name__, "message": str(exc)[:500]}


def build_run_manifest(
    *,
    out_dir: Path,
    result: RunResult,
    config: IntelligenceConfig,
    cli: dict[str, Any],
    repo_root: Path | None,
    detector_policy: dict[str, Any] | None,
    product_paths: dict[str, str] | None,
    extra_artifact_relative_names: list[str] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Assemble the manifest dict (not written to disk)."""
    ts = generated_at or datetime.now(timezone.utc).isoformat()
    meta = result.run_metadata
    names = ["violations.json", "dep_report.json"]
    if product_paths:
        for logical, p in product_paths.items():
            try:
                rel = str(Path(p).resolve().relative_to(out_dir.resolve()))
                if rel not in names:
                    names.append(rel)
            except ValueError:
                names.append(Path(p).name)
    if extra_artifact_relative_names:
        for n in extra_artifact_relative_names:
            if n and n not in names:
                names.append(n)

    artifacts: dict[str, Any] = {}
    for name in sorted(set(names)):
        p = out_dir / name
        if p.is_file():
            artifacts[name] = {
                "sha256": _sha256_file(p),
                "bytes": p.stat().st_size,
            }
        else:
            artifacts[name] = {"missing": True}

    return {
        "schema_version": RUN_MANIFEST_SCHEMA_VERSION,
        "generated_at": ts,
        "package_version": _dist_version(),
        "run_id": meta.run_id,
        "analysis_mode": meta.analysis_mode.value if meta.analysis_mode else None,
        "cli": cli,
        "git": _git_state(repo_root),
        "graph_source": dict(meta.graph_source_metadata or {}),
        "intelligence": {
            "provider": meta.provider,
            "resolved_model": config.resolved_llm_model_label(),
            "gray_zone_enabled": bool(config.gray_zone.enabled),
            "reasoner_run_health": getattr(meta, "reasoner_run_health", None),
            "reasoner_health_reason": getattr(meta, "reasoner_health_reason", None) or "",
            "low_stitcher_coverage": bool(getattr(meta, "low_stitcher_coverage", False)),
            "token_estimator": meta.token_estimator,
        },
        "detector_policy": detector_policy or {},
        "findings_count": len(result.findings),
        "product_outputs": product_paths or {},
        "artifacts": artifacts,
        "redaction": {
            "product_outputs_use_standard_secret_patterns": True,
            "mcp_context_capped": True,
        },
    }


def write_run_manifest(
    out_dir: Path,
    manifest: dict[str, Any],
) -> Path:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / RUN_MANIFEST_FILENAME
    path.write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")
    return path


def write_run_manifest_for_bundle(
    *,
    out_dir: Path,
    result: RunResult,
    config: IntelligenceConfig,
    cli: dict[str, Any],
    repo_root: Path | None,
    detector_policy: dict[str, Any] | None,
    product_paths: dict[str, str] | None,
    extra_artifact_relative_names: list[str] | None = None,
) -> Path:
    manifest = build_run_manifest(
        out_dir=out_dir,
        result=result,
        config=config,
        cli=cli,
        repo_root=repo_root,
        detector_policy=detector_policy,
        product_paths=product_paths,
        extra_artifact_relative_names=extra_artifact_relative_names,
    )
    path = write_run_manifest(out_dir, manifest)
    result.run_metadata.output_paths["run_manifest"] = str(path)
    return path


__all__ = [
    "RUN_MANIFEST_SCHEMA_VERSION",
    "RUN_MANIFEST_FILENAME",
    "build_run_manifest",
    "write_run_manifest",
    "write_run_manifest_for_bundle",
]
