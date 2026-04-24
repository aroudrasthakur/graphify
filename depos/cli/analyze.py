"""Subcommand implementations for ``depos-intel analyze``.

Kept thin on purpose. Heavy lifting lives in the intelligence modules:
:mod:`depos.enrichment.semantic_edges`, :mod:`depos.analysis.*`. The CLI
layer is responsible for:

- Constructing a :class:`GraphSource` from the CLI flags.
- Orchestrating Module 1 \u2192 Module 7.
- Writing output artifacts (``violations.json``, audit jsonl files) under
  ``<DEPOS_DATA>/intelligence/<run_id>/`` with caveats attached at write
  time (single output-layer responsibility).
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from depos.analysis.config import IntelligenceConfig, load_config_from_env
from depos.analysis.detectors import get_detector, list_detectors, load_builtin
from depos.analysis.schemas import AnalysisMode, ContextBundle, Finding, RunResult, RunMetadata, StitcherCoverageReport
from depos.graph_source import GraphifySource, GraphSource


# Exit codes used under --strict (per plan §3.5).
STRICT_EXIT_REASONER_FAILED = 2
STRICT_EXIT_PATH_RESOLUTION = 3
STRICT_EXIT_INGEST_ERROR = 4

# Mirrors depos.analysis.context_bundle._QUALITY_RANK so the CLI can compare
# bundle evidence quality without importing the bundling module at module load.
_QUALITY_RANK = {"missing": 0, "label_only": 1, "embedded": 2, "full": 3}


def _dominant_quality(evidence) -> str:
    """Return the highest snippet-quality bucket present in the bundle.

    Falls back to ``missing`` when the bundle has zero snippets so empty bundles
    are correctly classified as low evidence.
    """
    if evidence.snippets_full > 0:
        return "full"
    if evidence.snippets_embedded > 0:
        return "embedded"
    if evidence.snippets_label_only > 0:
        return "label_only"
    return "missing"


def _reasoner_health_reason(stats, bundles_sent: int) -> str:
    if bundles_sent == 0 or stats.attempts == 0:
        return "no_bundles_sent_to_reasoner" if bundles_sent == 0 else ""
    if stats.successes == 0:
        worst_reason = max(stats.by_reason.items(), key=lambda kv: kv[1])[0] if stats.by_reason else "unknown"
        return f"all_calls_failed:{worst_reason}"
    if stats.successes / stats.attempts < 0.5:
        worst_reason = max(stats.by_reason.items(), key=lambda kv: kv[1])[0] if stats.by_reason else "unknown"
        return f"majority_failed:{worst_reason}"
    return ""


def _summarize_resolution_report(report: dict[str, Any]) -> dict[str, Any]:
    """Project the raw ast_normalize resolution report into the shape used by
    run_summary.json and the strict-mode exit-code helper."""
    total = int(report.get("total_dataset_files", 0))
    resolved = int(report.get("resolved", 0))
    unresolved = int(report.get("unresolved", max(total - resolved, 0)))
    ratio = float(report.get("resolution_ratio", (resolved / total) if total else 1.0))
    resolved_via_buckets: dict[str, int] = {}
    for via in (report.get("resolved_via") or {}).values():
        key = str(via or "unresolved")
        resolved_via_buckets[key] = resolved_via_buckets.get(key, 0) + 1
    return {
        "files_total": total,
        "files_resolved": resolved,
        "files_unresolved": unresolved,
        "resolution_ratio": ratio,
        "resolved_via_counts": resolved_via_buckets,
        "source_roots_tried": list(report.get("source_roots_tried", [])),
        "path_aliases": dict(report.get("path_aliases", {})),
        "unresolved_files": list(report.get("unresolved_files", []))[:50],
    }


def _strict_exit_code(*, reasoner_health: str, resolution_summary: dict[str, Any]) -> int:
    if reasoner_health == "failed":
        return STRICT_EXIT_REASONER_FAILED
    total = int(resolution_summary.get("files_total", 0))
    resolved = int(resolution_summary.get("files_resolved", 0))
    if total > 0 and resolved / total < 0.5:
        return STRICT_EXIT_PATH_RESOLUTION
    if reasoner_health == "degraded":
        return STRICT_EXIT_REASONER_FAILED
    return 0


def _parse_path_aliases(raw: list[str] | None) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for item in raw or []:
        if not item or "=" not in item:
            continue
        src, dst = item.split("=", 1)
        src = src.strip()
        dst = dst.strip()
        if src:
            aliases[src] = dst
    return aliases


def _apply_evidence_overrides(config: IntelligenceConfig, args) -> None:
    extras = [str(p) for p in (getattr(args, "source_root", None) or []) if p]
    if extras:
        config.bundles.extra_source_roots = list(
            dict.fromkeys(list(config.bundles.extra_source_roots) + extras)
        )
    aliases = _parse_path_aliases(getattr(args, "path_alias", None))
    if aliases:
        merged = dict(config.bundles.path_aliases)
        merged.update(aliases)
        config.bundles.path_aliases = merged
    min_evidence = getattr(args, "min_evidence", None)
    if min_evidence:
        config.bundles.min_evidence_quality_for_reasoner = min_evidence


def _build_source_roots(args, config: IntelligenceConfig) -> list[Path]:
    roots: list[Path] = []
    seen: set[Path] = set()

    def _add(p: Path) -> None:
        try:
            resolved = p.resolve()
        except OSError:
            resolved = p
        if resolved in seen:
            return
        seen.add(resolved)
        roots.append(p)

    repo_root = getattr(args, "repo_root", None)
    if repo_root:
        _add(Path(repo_root))
    for raw in getattr(args, "source_root", None) or []:
        if raw:
            _add(Path(raw))
    for raw in config.bundles.extra_source_roots:
        if raw:
            _add(Path(raw))
    if not roots:
        _add(Path.cwd())
    return roots


# ---------------------------------------------------------------------------
# Graph source construction
# ---------------------------------------------------------------------------

def _build_graph_source(args) -> GraphSource:
    path = getattr(args, "path", None)
    graph_json = getattr(args, "graph_json", None) or getattr(args, "cpg_path", None)
    if graph_json:
        gj = Path(graph_json)
        # Prefer GraphifySource JSON loader for production; keep the test
        # fixture loader for files authored as node-link fixtures.
        if gj.exists():
            return GraphifySource(graph_json_path=gj)
        raise SystemExit(f"graph json not found: {gj}")
    if path:
        return GraphifySource(root=Path(path))
    raise SystemExit("provide --path or --graph-json")


def _run_output_dir(config: IntelligenceConfig, run_id: str) -> Path:
    out = config.data_dir / config.run_output_subdir / run_id
    out.mkdir(parents=True, exist_ok=True)
    return out


def _apply_provider_override(config: IntelligenceConfig, args) -> None:
    provider = getattr(args, "provider", None)
    if provider:
        config.llm.provider = provider


def _replay_intelligence_config(base: IntelligenceConfig, args: Any) -> IntelligenceConfig:
    """Apply replay-only path overrides (CLI beats DEPOS_INTEL_* replay env vars).

    Dataset-pipeline runs use ``data_dir = <output-dir>`` and
    ``run_output_subdir = ".canonical"``; repo/diff runs use ``DEPOS_DATA`` and
    ``intelligence``. Replay must resolve ``prompts/`` and ``reasoner_queue.jsonl``
    under ``data_dir / run_output_subdir / <run_id>``.

    ``DEPOS_INTEL_DATA_DIR`` / ``DEPOS_INTEL_RUN_OUTPUT_SUBDIR`` are read here only
    (not in :func:`load_config_from_env`) so normal ``analyze repo``/``diff`` runs
    keep using ``DEPOS_DATA``."""
    cfg = base.model_copy(deep=True)
    data_dir = getattr(args, "data_dir", None)
    if not data_dir:
        env_data = os.environ.get("DEPOS_INTEL_DATA_DIR", "").strip()
        if env_data:
            data_dir = env_data
    if data_dir:
        cfg.data_dir = Path(str(data_dir))
    run_subdir = getattr(args, "run_subdir", None)
    if run_subdir is None or not str(run_subdir).strip():
        env_sub = os.environ.get("DEPOS_INTEL_RUN_OUTPUT_SUBDIR", "").strip()
        if env_sub:
            run_subdir = env_sub
    if run_subdir is not None and str(run_subdir).strip():
        cfg.run_output_subdir = str(run_subdir).strip()
    return cfg


def _make_progress_reporter(prefix: str = "depos-intel") -> Callable[[str], None]:
    def report(message: str) -> None:
        print(f"[{prefix}] {message}", file=sys.stderr, flush=True)

    return report


def _source_repo_root(source: GraphSource) -> Path | None:
    meta = source.get_source_metadata()
    repo_path = meta.get("repo_path")
    if repo_path:
        return Path(repo_path)
    return None


# ---------------------------------------------------------------------------
# coverage (Module 1 only, no reasoning)
# ---------------------------------------------------------------------------

def run_coverage(args) -> int:
    config = load_config_from_env()
    source = _build_graph_source(args)
    graph = source.get_graph()

    # Module 1 is built incrementally; import what exists and gracefully skip
    # probes whose code has not landed yet.
    try:
        from depos.enrichment.semantic_edges import enrich_graph
    except ImportError:
        enrich_graph = None

    if enrich_graph is None:
        report = StitcherCoverageReport()
    else:
        _, report = enrich_graph(graph, config=config, repo_root=_source_repo_root(source))

    # Emit as structured JSON so scripts can consume it.
    print(json.dumps(report.model_dump(), indent=2, default=str))
    return 0


# ---------------------------------------------------------------------------
# repo / diff / replay (placeholders wired to run output-layer caveats)
# ---------------------------------------------------------------------------

def _new_run_metadata(
    config: IntelligenceConfig,
    source: GraphSource,
    *,
    mode: AnalysisMode,
) -> RunMetadata:
    return RunMetadata(
        run_id=uuid.uuid4().hex,
        analysis_mode=mode,
        provider=config.llm.provider,
        token_estimator=config.bundles.token_estimator,
        graph_source_metadata=source.get_source_metadata(),
    )


def _write_violations(
    out_dir: Path,
    result: RunResult | list[Finding],
    run_meta: RunMetadata | None = None,
) -> None:
    if isinstance(result, list):
        assert run_meta is not None
        result = RunResult(findings=result, detector_stats=[], ingest_reports=[], run_metadata=run_meta)
    payload: dict[str, Any] = {
        "run_id": result.run_metadata.run_id,
        "run_metadata": result.run_metadata.model_dump(mode="json"),
        "ingest_reports": [report.model_dump(mode="json") for report in result.ingest_reports],
        "detector_stats": [stat.model_dump(mode="json") for stat in result.detector_stats],
        "findings": [f.model_dump(mode="json") for f in result.findings],
    }
    (out_dir / "violations.json").write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def _detector_policy_from_args(args) -> dict[str, Any]:
    load_builtin()
    policy: dict[str, Any] = {"enabled": [], "disabled": [], "severity_overrides": {}}
    for raw in getattr(args, "detectors", []) or []:
        if not raw or "=" not in raw:
            continue
        kind, value = raw.split("=", 1)
        names = [item.strip() for item in value.split(",") if item.strip()]
        if kind == "include":
            policy["enabled"].extend(names)
        elif kind == "exclude":
            policy["disabled"].extend(names)
    if getattr(args, "no_reasoner", False):
        policy["disabled"].extend(spec.name for spec in list_detectors() if spec.requires_reasoner)
    policy["enabled"] = sorted(set(policy["enabled"]))
    policy["disabled"] = sorted(set(policy["disabled"]))
    if not policy["enabled"] and not policy["disabled"] and not policy["severity_overrides"]:
        return {}
    return policy


def _attach_run_caveats(findings: list[Finding], run_meta: RunMetadata) -> None:
    """Single point where run-level caveats are attached to every finding.

    Individual modules MUST NOT write caveat strings; they only set
    ``run_metadata`` flags and this layer formats user-facing text.
    """
    if run_meta.low_stitcher_coverage:
        caveat = (
            "Stitcher coverage dropped below the configured threshold for this run. "
            "Findings are not suppressed, but cross-component signals may be incomplete."
        )
        for f in findings:
            f.low_stitcher_coverage_caveat = caveat


def run_repo(args) -> int:
    config = load_config_from_env()
    progress = _make_progress_reporter()
    _apply_provider_override(config, args)
    progress(f"Config loaded. provider={config.llm.provider} llm={config.resolved_llm_model_label()}.")
    source = _build_graph_source(args)
    progress(f"Graph source resolved from {source.get_source_metadata().get('repo_path') or source.get_source_metadata().get('graph_json_path') or 'unknown source'}.")
    run_meta = _new_run_metadata(config, source, mode=AnalysisMode.full_repo_scan)
    out_dir = _run_output_dir(config, run_meta.run_id)
    progress(f"Run {run_meta.run_id}: output directory {out_dir}.")

    result = _run_pipeline(
        source,
        config,
        run_meta,
        detector_policy=_detector_policy_from_args(args),
        progress=progress,
    )
    _attach_run_caveats(result.findings, run_meta)
    progress(f"Writing violations.json with {len(result.findings)} findings.")
    _write_violations(out_dir, result)
    payload: dict[str, Any] = {"run_id": run_meta.run_id, "output_dir": str(out_dir), "findings": len(result.findings)}
    if getattr(args, "print_detector_stats", False):
        payload["detector_stats"] = [row.model_dump(mode="json") for row in result.detector_stats]
    progress(f"Run {run_meta.run_id} complete.")
    print(json.dumps(payload, indent=2))
    return 0


def run_diff(args) -> int:
    config = load_config_from_env()
    progress = _make_progress_reporter()
    _apply_provider_override(config, args)
    progress(f"Config loaded. provider={config.llm.provider} llm={config.resolved_llm_model_label()}.")
    source = _build_graph_source(args)
    progress(f"Graph source resolved from {source.get_source_metadata().get('repo_path') or source.get_source_metadata().get('graph_json_path') or 'unknown source'}.")
    run_meta = _new_run_metadata(config, source, mode=AnalysisMode.diff_aware)
    out_dir = _run_output_dir(config, run_meta.run_id)
    progress(f"Run {run_meta.run_id}: output directory {out_dir}.")

    diff_path = getattr(args, "diff_path", None)
    if diff_path:
        run_meta.head_ref = Path(diff_path).stem

    result = _run_pipeline(
        source,
        config,
        run_meta,
        diff_path=diff_path,
        detector_policy=_detector_policy_from_args(args),
        progress=progress,
    )
    _attach_run_caveats(result.findings, run_meta)
    progress(f"Writing violations.json with {len(result.findings)} findings.")
    _write_violations(out_dir, result)
    payload: dict[str, Any] = {"run_id": run_meta.run_id, "output_dir": str(out_dir), "findings": len(result.findings)}
    if getattr(args, "print_detector_stats", False):
        payload["detector_stats"] = [row.model_dump(mode="json") for row in result.detector_stats]
    progress(f"Run {run_meta.run_id} complete.")
    print(json.dumps(payload, indent=2))
    return 0


def run_replay(args) -> int:
    config = _replay_intelligence_config(load_config_from_env(), args)
    _apply_provider_override(config, args)
    queue_path = Path(args.queue)
    if not queue_path.exists():
        raise SystemExit(f"queue file not found: {queue_path}")

    run_meta = RunMetadata(
        run_id=uuid.uuid4().hex,
        analysis_mode=AnalysisMode.diff_aware,
        provider=config.llm.provider,
        token_estimator=config.bundles.token_estimator,
    )
    out_dir = _run_output_dir(config, run_meta.run_id)

    now = datetime.now(tz=timezone.utc)
    stale_days = config.replay_stale_threshold_days
    findings: list[Finding] = []
    stale_count = 0
    with queue_path.open(encoding="utf-8") as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            queued_at_s = row.get("queued_at")
            queued_at = None
            if queued_at_s:
                try:
                    queued_at = datetime.fromisoformat(queued_at_s.replace("Z", "+00:00"))
                except ValueError:
                    queued_at = None
            is_stale = queued_at is not None and (now - queued_at).days > stale_days

            # Try to re-run the reasoner if the Module 4 wiring is in place;
            # otherwise just surface a placeholder "replayed" audit row.
            try:
                from depos.analysis.reasoning_engine import replay_one  # type: ignore
            except ImportError:
                replay_one = None
            if replay_one is not None:
                for f in replay_one(row, config=config):
                    if is_stale:
                        f.stale_diff_replay_caveat = (
                            f"Queue entry is older than {stale_days} days; treat replay as stale."
                        )
                        stale_count += 1
                    findings.append(f)

    _attach_run_caveats(findings, run_meta)
    _write_violations(out_dir, findings, run_meta)
    print(json.dumps(
        {"run_id": run_meta.run_id, "output_dir": str(out_dir), "findings": len(findings), "stale_flagged": stale_count},
        indent=2,
    ))
    return 0


def run_score_bundles(args) -> int:
    """Emit stub per-bundle score rows as a report-only sidecar over canonical bundles."""

    progress = _make_progress_reporter()
    bundles_path = Path(args.bundles_json)
    if not bundles_path.exists():
        raise SystemExit(f"bundles json not found: {bundles_path}")
    progress(f"Loading bundles from {bundles_path}.")
    data = json.loads(bundles_path.read_text(encoding="utf-8"))
    bundles: list[dict] = data if isinstance(data, list) else data.get("bundles", [])  # type: ignore[assignment]
    if not isinstance(bundles, list):
        bundles = []
    progress(f"Writing stub scores for {len(bundles)} bundles (ranking is CandidateScore.composite in-pipeline).")
    rows: list[dict] = [
        {
            "bundle_id": b.get("bundle_id", ""),
            "candidate_id": b.get("candidate_id", ""),
            "candidate_score_composite": 1.0,
            "note": "Stub scores; use run metadata / candidates.json for composite scores.",
        }
        for b in bundles
        if isinstance(b, dict)
    ]
    out_path = Path(args.output) if getattr(args, "output", None) else bundles_path.parent / "bundle-scores.json"
    out_path.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    progress(f"Wrote {len(rows)} bundle score rows to {out_path}.")
    print(json.dumps({"bundles": len(bundles), "scores": len(rows), "output": str(out_path)}, indent=2))
    return 0


def run_normalize_dataset(args) -> int:
    from graphify.build import build_from_json

    from depos.analysis.ast_normalize import normalize_dataset_dir
    from depos.snapshot import persist_graph_json

    progress = _make_progress_reporter()
    dataset_dir = Path(args.dataset_dir)
    if not dataset_dir.exists():
        raise SystemExit(f"dataset dir not found: {dataset_dir}")
    repo_root = Path(args.repo_root) if getattr(args, "repo_root", None) else None
    progress(f"Normalizing dataset AST files from {dataset_dir}.")
    extraction = normalize_dataset_dir(dataset_dir, repo_root=repo_root)
    if getattr(args, "extraction_output", None):
        extraction_path = Path(args.extraction_output)
        extraction_path.parent.mkdir(parents=True, exist_ok=True)
        extraction_path.write_text(json.dumps(extraction, indent=2), encoding="utf-8")
        progress(f"Wrote normalized extraction JSON to {extraction_path}.")
    progress(f"Building node-link graph from normalized extraction ({len(extraction.get('nodes', []))} nodes, {len(extraction.get('edges', []))} edges).")
    graph = build_from_json(extraction, directed=True)
    out_path = Path(args.output)
    persist_graph_json(graph, out_path)
    progress(f"Persisted normalized graph to {out_path}.")
    print(
        json.dumps(
            {
                "dataset_dir": str(dataset_dir),
                "repo_root": str(repo_root) if repo_root is not None else None,
                "nodes": len(extraction.get("nodes", [])),
                "edges": len(extraction.get("edges", [])),
                "output": str(out_path),
                "extraction_output": str(args.extraction_output) if getattr(args, "extraction_output", None) else None,
            },
            indent=2,
        )
    )
    return 0


def run_prepare_dataset(args) -> int:
    from depos.analysis.dataset_ast_export import prepare_dataset_from_source

    progress = _make_progress_reporter()
    dataset_root = Path(args.dataset_root)
    checkout_root = Path(args.checkout_root)
    progress(
        "Preparing raw AST dataset export from "
        + (f"repo URL {args.repo_url}" if getattr(args, "repo_url", None) else f"local repo {args.repo_root}")
        + f" into dataset root {dataset_root}."
    )
    result = prepare_dataset_from_source(
        repo_root=Path(args.repo_root) if getattr(args, "repo_root", None) else None,
        repo_url=getattr(args, "repo_url", None),
        dataset_root=dataset_root,
        checkout_root=checkout_root,
        repo_name=getattr(args, "repo_name", None),
        progress=progress,
    )
    progress(
        f"Prepared dataset at {result.dataset_dir} from repo_root={result.repo_root}. "
        f"Wrote {result.files_written} file(s), skipped {result.files_skipped}."
    )
    print(
        json.dumps(
            {
                "repo_name": result.repo_name,
                "repo_root": str(result.repo_root),
                "dataset_dir": str(result.dataset_dir),
                "commit_sha": result.commit_sha,
                "files_written": result.files_written,
                "files_skipped": result.files_skipped,
                "skipped_files": result.skipped_files[:50],
                "next_step": (
                    "Run `depos-intel analyze dataset-pipeline "
                    f"--dataset-dir {result.dataset_dir} --repo-root {result.repo_root} "
                    "--output-dir graphify-out/<run-name>`."
                ),
            },
            indent=2,
        )
    )
    return 0


def _normalize_dataset_to_graph(
    *,
    dataset_dir: Path,
    repo_root: Path | None,
    graph_output: Path,
    extraction_output: Path | None = None,
    progress: Callable[[str], None] | None = None,
    source_roots: list[Path] | None = None,
    path_aliases: dict[str, str] | None = None,
    resolution_report: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], Path]:
    from graphify.build import build_from_json

    from depos.analysis.ast_normalize import normalize_dataset_dir
    from depos.snapshot import persist_graph_json

    if progress is not None:
        progress(f"Dataset pipeline: normalizing AST dataset from {dataset_dir}.")
    extraction = normalize_dataset_dir(
        dataset_dir,
        repo_root=repo_root,
        source_roots=source_roots,
        path_aliases=path_aliases,
        resolution_report=resolution_report,
    )
    if extraction_output is not None:
        extraction_output.parent.mkdir(parents=True, exist_ok=True)
        extraction_output.write_text(json.dumps(extraction, indent=2), encoding="utf-8")
        if progress is not None:
            progress(f"Dataset pipeline: wrote normalized extraction to {extraction_output}.")
    if progress is not None:
        progress(
            "Dataset pipeline: building normalized graph "
            f"({len(extraction.get('nodes', []))} nodes, {len(extraction.get('edges', []))} edges)."
        )
    graph = build_from_json(extraction, directed=True)
    persist_graph_json(graph, graph_output)
    if progress is not None:
        progress(f"Dataset pipeline: persisted normalized graph to {graph_output}.")
    return extraction, graph_output


def _dataset_bundle_limit(args) -> int | None:
    raw = getattr(args, "max_bundles", None)
    return max(0, int(raw)) if raw is not None else None


def _dataset_selected_limit(args, *, bundle_limit: int | None) -> int | None:
    raw = getattr(args, "top_n", None)
    if raw is None:
        return bundle_limit
    selected = max(0, int(raw))
    if bundle_limit is None:
        return selected
    return min(bundle_limit, selected)


def _write_candidates_json(
    output_path: Path,
    *,
    result: RunResult,
    progress: Callable[[str], None] | None = None,
) -> None:
    manifest = result.change_manifest
    payload = {
        "resolved_via": manifest.resolved_via if manifest is not None else "empty",
        "candidate_count": len(result.candidates),
        "candidates": [candidate.model_dump(mode="json") for candidate in result.candidates],
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if progress is not None:
        progress(
            f"Dataset pipeline: wrote {len(result.candidates)} candidates to {output_path} "
            f"(resolved via {payload['resolved_via']})."
        )


def _write_bundles_json(
    output_path: Path,
    *,
    result: RunResult,
    progress: Callable[[str], None] | None = None,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps([bundle.model_dump(mode="json") for bundle in result.bundles], indent=2),
        encoding="utf-8",
    )
    if progress is not None:
        progress(f"Dataset pipeline: wrote {len(result.bundles)} bundles to {output_path}.")


def _bundle_score_rows(bundles: list[ContextBundle]) -> list[dict[str, Any]]:
    return [
        {
            "bundle_id": bundle.bundle_id,
            "candidate_id": bundle.candidate_id,
            "candidate_score_composite": 1.0,
            "rank_pattern": "stub",
        }
        for bundle in bundles
    ]


def _write_bundle_scores_json(
    output_path: Path,
    *,
    bundles: list[ContextBundle],
    progress: Callable[[str], None] | None = None,
) -> list[dict[str, Any]]:
    rows = _bundle_score_rows(bundles)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    if progress is not None:
        progress(
            f"Dataset pipeline: writing stub bundle rank scores for {len(bundles)} bundles "
            "(CandidateScore.composite in-pipeline)."
        )
        progress(f"Dataset pipeline: wrote {len(rows)} bundle scores to {output_path}.")
    return rows


def _mirror_run_artifacts(
    source_dir: Path,
    destination_dir: Path,
    *,
    progress: Callable[[str], None] | None = None,
) -> None:
    if not source_dir.exists():
        return
    destination_dir.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source_dir, destination_dir, dirs_exist_ok=True)
    if progress is not None:
        progress(f"Dataset pipeline: mirrored canonical run artifacts from {source_dir} to {destination_dir}.")


def _write_bundle_trace_json(
    output_path: Path,
    *,
    result: RunResult,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps([row.model_dump(mode="json") for row in result.bundle_trace], indent=2),
        encoding="utf-8",
    )


def _write_run_summary(
    output_path: Path,
    *,
    result: RunResult,
    dataset_path_resolution: dict[str, Any] | None = None,
) -> dict[str, Any]:
    summary = {
        "run_id": result.run_metadata.run_id,
        "output_dir": str(output_path.parent),
        "provider": result.run_metadata.provider,
        "selected_bundles": len(result.bundle_trace),
        "bundles_built": result.run_metadata.bundles_built,
        "bundles_sent_to_reasoner": result.run_metadata.bundles_sent_to_reasoner,
        "bundles_skipped_low_evidence": result.run_metadata.bundles_skipped_low_evidence,
        "findings": len(result.findings),
        "gray_zone_rows": len(result.gray_zone_rows),
        "reasoner_run_health": result.run_metadata.reasoner_run_health,
        "reasoner_health_reason": result.run_metadata.reasoner_health_reason,
        "reasoner_call_stats": result.reasoner_call_stats.model_dump(mode="json"),
        "evidence_summary": result.evidence_summary,
    }
    if dataset_path_resolution is not None:
        summary["dataset_path_resolution"] = dataset_path_resolution
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def run_bundle_pipeline(args) -> int:
    progress = _make_progress_reporter()
    message = (
        "Bundle pipeline is deprecated and no longer runs a separate Stage 4-11 path. "
        "Use `depos-intel analyze dataset-pipeline` for dataset-backed runs or "
        "`depos-intel analyze repo` / `depos-intel analyze diff` for canonical analysis."
    )
    progress(message)
    print(
        json.dumps(
            {
                "deprecated": True,
                "command": "bundle-pipeline",
                "message": message,
            },
            indent=2,
        )
    )
    return 2


def run_dataset_pipeline(args) -> int:
    config = load_config_from_env()
    if getattr(args, "provider", None):
        config.llm.provider = args.provider
    _apply_evidence_overrides(config, args)
    progress = _make_progress_reporter()
    progress(f"Dataset pipeline: config loaded. provider={config.llm.provider}.")

    dataset_dir = Path(args.dataset_dir)
    if not dataset_dir.exists():
        raise SystemExit(f"dataset dir not found: {dataset_dir}")
    repo_root = Path(args.repo_root) if getattr(args, "repo_root", None) else None
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    progress(f"Dataset pipeline: output directory {out_dir}.")

    source_roots = _build_source_roots(args, config)
    path_aliases = dict(config.bundles.path_aliases)
    progress(
        "Dataset pipeline: source resolution roots = ["
        + ", ".join(str(r) for r in source_roots)
        + "]"
        + (f" with {len(path_aliases)} path alias(es)." if path_aliases else ".")
    )

    graph_output = out_dir / "dataset-normalized-node-link.json"
    extraction_output = out_dir / "dataset-normalized-extraction.json" if getattr(args, "write_extraction", False) else None
    candidates_output = out_dir / "candidates.json"
    bundles_output = out_dir / "bundles.json"
    scores_output = out_dir / "bundle-scores.json"
    resolution_output = out_dir / "dataset_path_resolution.json"
    final_run_dir = out_dir / "gemma4-run"

    resolution_report: dict[str, Any] = {
        "source_roots": [str(p) for p in source_roots],
        "path_aliases": path_aliases,
        "files": {},
        "by_root": {},
        "aliases_applied": {},
    }

    extraction, graph_json = _normalize_dataset_to_graph(
        dataset_dir=dataset_dir,
        repo_root=repo_root,
        graph_output=graph_output,
        extraction_output=extraction_output,
        progress=progress,
        source_roots=source_roots,
        path_aliases=path_aliases,
        resolution_report=resolution_report,
    )

    resolution_summary = _summarize_resolution_report(resolution_report)
    resolution_output.write_text(
        json.dumps(
            {
                "summary": resolution_summary,
                "report": resolution_report,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    progress(
        f"Dataset pipeline: path resolution {resolution_summary['files_resolved']}/"
        f"{resolution_summary['files_total']} files resolved "
        f"({resolution_summary['files_unresolved']} unresolved, "
        f"ratio={resolution_summary['resolution_ratio']:.2f}). "
        f"Wrote {resolution_output}."
    )

    bundle_limit = _dataset_bundle_limit(args)
    selected_limit = _dataset_selected_limit(args, bundle_limit=bundle_limit)
    progress(
        "Dataset pipeline: starting canonical Stage 1-11 pipeline."
        + (
            f" bundle_limit={bundle_limit} selected_limit={selected_limit}."
            if bundle_limit is not None or selected_limit is not None
            else ""
        )
    )

    run_config = config.model_copy(deep=True)
    run_config.data_dir = out_dir
    run_config.run_output_subdir = ".canonical"

    source = GraphifySource(graph_json_path=graph_json)
    run_meta = _new_run_metadata(run_config, source, mode=AnalysisMode.full_repo_scan)
    run_meta.graph_source_metadata.update(
        {
            "dataset_dir": str(dataset_dir),
            "repo_root": str(repo_root) if repo_root is not None else None,
            "graph_json": str(graph_json),
            "source_type": "dataset_normalized_graph",
        }
    )
    run_meta.dataset_path_resolution = resolution_summary
    internal_run_dir = _run_output_dir(run_config, run_meta.run_id)

    result = _run_pipeline(
        source,
        run_config,
        run_meta,
        repo_root=repo_root,
        bundle_limit=bundle_limit,
        selected_limit=selected_limit,
        min_score=args.min_score,
        progress=progress,
    )
    result.run_metadata.dataset_path_resolution = resolution_summary
    _attach_run_caveats(result.findings, result.run_metadata)

    _write_candidates_json(candidates_output, result=result, progress=progress)
    _write_bundles_json(bundles_output, result=result, progress=progress)
    score_rows = _write_bundle_scores_json(scores_output, bundles=result.bundles, progress=progress)
    _mirror_run_artifacts(internal_run_dir, final_run_dir, progress=progress)
    _write_violations(final_run_dir, result)
    _write_bundle_trace_json(final_run_dir / "bundle_pipeline_trace.json", result=result)
    pipeline_summary = _write_run_summary(
        final_run_dir / "run_summary.json",
        result=result,
        dataset_path_resolution=resolution_summary,
    )
    progress("Dataset pipeline: complete.")

    print(
        json.dumps(
            {
                "dataset_dir": str(dataset_dir),
                "repo_root": str(repo_root) if repo_root is not None else None,
                "source_roots": [str(p) for p in source_roots],
                "path_aliases": path_aliases,
                "normalized_nodes": len(extraction.get("nodes", [])),
                "normalized_edges": len(extraction.get("edges", [])),
                "resolved_via": result.change_manifest.resolved_via if result.change_manifest is not None else "empty",
                "candidates": len(result.candidates),
                "bundles": len(result.bundles),
                "scores": len(score_rows),
                "intermediates": {
                    "graph_json": str(graph_output),
                    "candidates_json": str(candidates_output),
                    "bundles_json": str(bundles_output),
                    "scores_json": str(scores_output),
                    "resolution_json": str(resolution_output),
                    "extraction_json": str(extraction_output) if extraction_output is not None else None,
                },
                "pipeline": pipeline_summary,
                "dataset_path_resolution": resolution_summary,
                "final_output_dir": str(final_run_dir),
            },
            indent=2,
        )
    )

    if getattr(args, "strict", False):
        return _strict_exit_code(
            reasoner_health=pipeline_summary["reasoner_run_health"],
            resolution_summary=resolution_summary,
        )
    return 0


# ---------------------------------------------------------------------------
# Pipeline orchestration (thin wrapper; real work is in analysis modules)
# ---------------------------------------------------------------------------

def _run_pipeline(
    source: GraphSource,
    config: IntelligenceConfig,
    run_meta: RunMetadata,
    *,
    diff_path: str | None = None,
    repo_root: Path | None = None,
    detector_policy: dict[str, Any] | None = None,
    bundle_limit: int | None = None,
    selected_limit: int | None = None,
    min_score: float | None = None,
    progress: Callable[[str], None] | None = None,
) -> RunResult:
    if progress is not None:
        progress("Loading graph source into memory.")
    graph = source.get_graph()
    if progress is not None:
        progress(f"Graph loaded with {graph.number_of_nodes()} nodes and {graph.number_of_edges()} edges.")

    try:
        from depos.enrichment.semantic_edges import enrich_graph
    except ImportError:
        enrich_graph = None

    if enrich_graph is not None:
        resolved_repo_root = repo_root if repo_root is not None else _source_repo_root(source)
        if progress is not None:
            progress("Module 1: running enrichment and cross-universe stitching.")
        graph, coverage = enrich_graph(graph, config=config, repo_root=resolved_repo_root)
        run_meta.stitcher_coverage = coverage
        run_meta.low_stitcher_coverage = coverage.low_coverage
        if progress is not None:
            progress(
                "Module 1: coverage "
                f"{coverage.linked_routes}/{coverage.total_fastapi_routes} routes linked; "
                f"low_coverage={str(coverage.low_coverage).lower()} errors={len(coverage.errors)}."
            )
    else:
        resolved_repo_root = repo_root if repo_root is not None else _source_repo_root(source)
        if progress is not None:
            progress("Module 1: enrichment module unavailable; continuing without enrichment.")

    try:
        from depos.analysis.pipeline import run_modules_2_through_7  # type: ignore
    except ImportError:
        return RunResult(findings=[], detector_stats=[], ingest_reports=[], run_metadata=run_meta)

    return run_modules_2_through_7(
        graph,
        config=config,
        run_meta=run_meta,
        diff_path=diff_path,
        repo_root=resolved_repo_root,
        detector_policy=detector_policy,
        bundle_limit=bundle_limit,
        selected_limit=selected_limit,
        min_score=min_score,
        progress=progress,
    )


def run_detectors_list(args) -> int:
    load_builtin()
    rows = [
        {
            "name": spec.name,
            "version": spec.version,
            "universe": spec.universe.value,
            "requires_reasoner": spec.requires_reasoner,
            "severity_default": spec.severity_default,
        }
        for spec in sorted(list_detectors(), key=lambda row: row.name)
    ]
    if getattr(args, "json", False):
        print(json.dumps({"detectors": rows}, indent=2))
        return 0
    for row in rows:
        print(
            f"{row['name']}  v{row['version']}  "
            f"{row['universe']}  "
            f"reasoner={str(row['requires_reasoner']).lower()}  "
            f"severity={row['severity_default']}"
        )
    return 0


def run_detectors_explain(args) -> int:
    load_builtin()
    spec = get_detector(args.name)
    payload = spec.model_dump(mode="json")
    payload["example_witness"] = spec.tree[0].then.witness_template if spec.tree else []
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2))
        return 0
    print(json.dumps(payload, indent=2))
    return 0


def run_detectors_replay(args) -> int:
    """Re-issue queued reasoner attempts from a prior run.

    Reads ``<data_dir>/<run_output_subdir>/<run_id>/reasoner_queue.jsonl``
    (defaults: ``DEPOS_DATA`` / ``intelligence``; dataset-pipeline uses
    ``--output-dir`` / ``.canonical``), replays each row (optionally filtered by
    mode), and reports how many calls now succeeded.
    """
    from depos.analysis.reasoning_engine import replay_one

    config = _replay_intelligence_config(load_config_from_env(), args)
    if getattr(args, "provider", None):
        config.llm.provider = args.provider

    run_id = str(args.run_id).strip()
    if not run_id:
        raise SystemExit("--run-id is required")
    run_dir = config.data_dir / config.run_output_subdir / run_id
    queue_path = run_dir / "reasoner_queue.jsonl"
    if not queue_path.exists():
        raise SystemExit(f"reasoner queue not found: {queue_path}")

    mode_filter = getattr(args, "mode", None)
    max_rows = getattr(args, "max", None)

    rows: list[dict[str, Any]] = []
    with queue_path.open("r", encoding="utf-8") as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if mode_filter and str(row.get("mode")) != mode_filter:
                continue
            rows.append(row)

    if max_rows is not None:
        rows = rows[: max(0, int(max_rows))]

    progress = _make_progress_reporter()
    progress(
        f"Replay: re-issuing {len(rows)} queued reasoner attempt(s) from {queue_path} "
        f"(provider={config.llm.provider})."
    )

    attempted = 0
    succeeded = 0
    failed = 0
    for index, row in enumerate(rows, start=1):
        attempted += 1
        results = list(replay_one(row, config=config, run_id=run_id))
        if results:
            succeeded += 1
            progress(
                f"Replay {index}/{len(rows)}: candidate={row.get('candidate_id')} "
                f"mode={row.get('mode')} → success."
            )
        else:
            failed += 1
            progress(
                f"Replay {index}/{len(rows)}: candidate={row.get('candidate_id')} "
                f"mode={row.get('mode')} → still failing (re-queued)."
            )

    summary = {
        "run_id": run_id,
        "queue_path": str(queue_path),
        "filter_mode": mode_filter,
        "attempted": attempted,
        "succeeded": succeeded,
        "failed": failed,
    }
    print(json.dumps(summary, indent=2))
    return 0
