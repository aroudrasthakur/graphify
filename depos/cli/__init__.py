"""depos-intel / depos console script entrypoint.

``main()`` is the historical ``depos-intel`` entry target. ``main_depos()`` is
the umbrella ``depos`` alias with the same subcommands plus v1-oriented epilog.

Dispatches to subcommands:

- ``run`` / ``analyze`` — intelligence analyses (repo, diff, dataset-pipeline, …)
- ``gate`` — CI policy on ``violations.json`` / ``gate_result.json``
- ``detectors`` — registry inspect
- ``intent-context`` — intent IR and graph compare
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional, Sequence


def _v1_epilog(prog: str) -> str:
    if prog != "depos":
        return ""
    return """
V1 quick start (config: flags > env > run-profile preset):
  depos analyze repo --path . --run-profile local
  depos analyze diff --graph-json graph.json --run-profile local
  depos gate --violations <run-dir>/violations.json

Run-profiles: local (stub reasoner, gray-zone off when env unset), full (env defaults), llm (gray-zone on when unset).
Pyinstrument: use --pyinstrument-html PATH (not --profile) for CPU profiling HTML.
Optional viewer: run depos-api and apps/web per README.
"""


def _build_parser(*, prog: str = "depos-intel") -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=prog,
        description="depOS intelligence CLI — local-first analysis, gate, and intent context.",
        epilog=_v1_epilog(prog),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="command", required=True)

    def _add_cache_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--no-cache",
            action="store_true",
            help="Disable the depOS fragment cache for this run.",
        )
        parser.add_argument(
            "--cache-dir",
            default=None,
            help="Override the depOS fragment cache root (default: <DEPOS_DATA>/cache).",
        )
        parser.add_argument(
            "--cache-clear",
            action="store_true",
            help="Clear the depOS fragment cache before running.",
        )

    def _add_scale_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--shard-by",
            choices=("none", "package_manifest"),
            default="none",
            help="Limit Module 2 detection to a subgraph: package_manifest = nodes under manifest dirs "
            "(bundles still read the full graph).",
        )

    def _add_perf_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--no-parallel",
            action="store_true",
            help="Serial-only: Wave B enrichers, semantic taint, and bundle build use one worker.",
        )
        parser.add_argument(
            "--taint-n-jobs",
            type=int,
            default=None,
            metavar="N",
            help="Override DEPOS_PERF_TAINT_N_JOBS (per-scope taint thread pool).",
        )
        parser.add_argument(
            "--cfg-dfg-n-jobs",
            type=int,
            default=None,
            metavar="N",
            help="Override DEPOS_PERF_CFG_DFG_N_JOBS (per-scope CFG/DFG fragment compute pool).",
        )
        parser.add_argument(
            "--bundle-n-jobs",
            type=int,
            default=None,
            metavar="N",
            help="Override DEPOS_PERF_BUNDLE_N_JOBS (parallel context bundles).",
        )
        parser.add_argument(
            "--no-expensive-metrics",
            action="store_true",
            help="Skip betweenness, articulation points, and cross-language cycle mining.",
        )
        parser.add_argument(
            "--metrics-backend",
            choices=("networkx", "rustworkx"),
            default=None,
            help="Expensive centrality backend (default: networkx or DEPOS_PERF_METRICS_BACKEND).",
        )

    analyze = sub.add_parser("analyze", help="Run or inspect intelligence analyses.")
    a_sub = analyze.add_subparsers(dest="analyze_command", required=True)

    detectors = sub.add_parser("detectors", help="Inspect the detector registry.")
    d_sub = detectors.add_subparsers(dest="detectors_command", required=True)

    intent_ctx = sub.add_parser(
        "intent-context",
        help="Intent IR (build) and graphical intent ↔ graph compare (graph-compare).",
    )
    ic_sub = intent_ctx.add_subparsers(dest="intent_command", required=True)
    ic_build = ic_sub.add_parser(
        "build",
        help="Write intent_manifest.json, intent_chunks.jsonl, intent_units.json, summaries.",
    )
    ic_build.add_argument("--repo-root", default=".", help="Repository checkout root.")
    ic_build.add_argument("--output-dir", required=True, help="Directory for intent artifacts.")
    ic_build.add_argument(
        "--intent-llm",
        choices=("auto", "rules", "llm"),
        default=None,
        help="Override DEPOS_INTEL_INTENT_LLM (auto uses OPENAI_API_KEY when set).",
    )
    ic_compare = ic_sub.add_parser(
        "graph-compare",
        help="Compare intent IR to the code graph (writes intent_graph_report.json and .md).",
    )
    ic_compare.add_argument("--repo-root", default=".", help="Repository checkout root.")
    ic_compare.add_argument(
        "--intent-dir",
        default="intent-out",
        type=Path,
        help="Directory containing intent_manifest.json from intent-context build.",
    )
    ic_compare.add_argument(
        "--graph-json",
        type=Path,
        default=None,
        help="Optional node-link JSON graph snapshot; otherwise build via graphify extract snapshot.",
    )
    ic_compare.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Where to write reports (defaults to --intent-dir).",
    )
    ic_compare.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 when any P0 intent unit remains unresolved against the graph (tier-weighted).",
    )
    ic_compare.add_argument(
        "--require-same-commit",
        action="store_true",
        help="Exit 1 when intent_manifest.repo_sha does not match git HEAD.",
    )
    sub.add_parser(
        "serve",
        help="Print how to start the local depOS API (depos-api); does not bind a port.",
    )
    gate = sub.add_parser(
        "gate",
        help="CI gate: exit non-zero when any finding is CONFIRMED with high or critical severity.",
    )
    gate.add_argument(
        "--violations",
        required=True,
        type=Path,
        help="Path to violations.json produced by a depOS run.",
    )
    gate.add_argument(
        "--allowlist",
        default=Path(".depOS/allowlist.json"),
        type=Path,
        help="Path to the depOS allowlist JSON file. Defaults to .depOS/allowlist.json.",
    )
    gate.add_argument(
        "--allow-finding-id",
        action="append",
        default=[],
        metavar="ID",
        help="Deprecated alias for temporarily excluding a finding ID from the gate (repeatable).",
    )
    gate.add_argument(
        "--auto-suppress",
        type=Path,
        default=None,
        help="Optional JSON file of finding_id strings (or {\"finding_ids\": [...]}) merged into the allowlist.",
    )

    detector_stats_cmd = sub.add_parser(
        "detector-stats",
        help="Print detector_stats from violations.json (rolling precision / verification counts).",
    )
    detector_stats_cmd.add_argument(
        "--violations",
        required=True,
        type=Path,
        help="Path to violations.json from a depOS run.",
    )

    migrate_allow = sub.add_parser(
        "migrate-allowlist",
        help="Rewrite allowlist finding_id values using a legacy->new JSON mapping.",
    )
    migrate_allow.add_argument(
        "--allowlist",
        required=True,
        type=Path,
        help="Path to .depOS/allowlist.json (array of {finding_id, expires?}).",
    )
    migrate_allow.add_argument(
        "--mapping",
        required=True,
        type=Path,
        help="JSON object mapping old finding_id to new finding_id.",
    )
    migrate_allow.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output path (default: overwrite --allowlist).",
    )

    repo = a_sub.add_parser("repo", help="Full-repo scan (no diff required).")
    repo.add_argument("--path", required=True)
    repo.add_argument(
        "--run-profile",
        "--profile-preset",
        choices=("local", "full", "llm"),
        default="full",
        dest="run_profile",
        metavar="PROFILE",
        help="V1 preset: local=stub reasoner + gray-zone off when env unset; full=env only; llm=gray-zone defaults. "
        "Alias: --profile-preset.",
    )
    repo.add_argument("--output")
    repo.add_argument("--mode", default="A,B,C")
    repo.add_argument("--provider", default=None)
    repo.add_argument("--export-training", action="store_true")
    repo.add_argument("--max-seeds", type=int, default=None)
    repo.add_argument("--detectors", action="append", default=[])
    repo.add_argument("--no-reasoner", action="store_true")
    repo.add_argument("--print-detector-stats", action="store_true")
    repo.add_argument(
        "--n-jobs",
        type=int,
        default=1,
        metavar="N",
        help="Number of parallel threads for Wave B enrichers (default: 1 = serial).",
    )
    _add_perf_args(repo)
    _add_scale_args(repo)
    _add_cache_args(repo)
    repo.add_argument(
        "--pyinstrument-html",
        metavar="PATH",
        default=None,
        dest="pyinstrument_html",
        help="Write a pyinstrument HTML profile to PATH (requires pip install graphifyy[perf]).",
    )

    diff = a_sub.add_parser("diff", help="Diff-aware scan using a change manifest.")
    diff.add_argument(
        "--run-profile",
        "--profile-preset",
        choices=("local", "full", "llm"),
        default="full",
        dest="run_profile",
        metavar="PROFILE",
        help="V1 preset: local=stub reasoner + gray-zone off when env unset; full=env only; llm=gray-zone defaults. "
        "Alias: --profile-preset.",
    )
    diff.add_argument("--cpg-path")
    diff.add_argument("--graph-json")
    diff.add_argument("--diff-path")
    diff.add_argument("--output")
    diff.add_argument("--mode", default="A,B,C")
    diff.add_argument("--provider", default=None)
    diff.add_argument("--export-training", action="store_true")
    diff.add_argument("--detectors", action="append", default=[])
    diff.add_argument("--no-reasoner", action="store_true")
    diff.add_argument("--print-detector-stats", action="store_true")
    diff.add_argument(
        "--n-jobs",
        type=int,
        default=1,
        metavar="N",
        help="Number of parallel threads for Wave B enrichers (default: 1 = serial).",
    )
    _add_perf_args(diff)
    _add_scale_args(diff)
    _add_cache_args(diff)
    diff.add_argument(
        "--pyinstrument-html",
        metavar="PATH",
        default=None,
        dest="pyinstrument_html",
        help="Write a pyinstrument HTML profile to PATH (requires pip install graphifyy[perf]).",
    )

    replay = a_sub.add_parser("replay", help="Replay a reasoner queue.")
    replay.add_argument("--queue", required=True)
    replay.add_argument("--output")
    replay.add_argument("--provider", default=None)
    replay.add_argument(
        "--data-dir",
        default=None,
        help="Intelligence data root for cached prompts (default: DEPOS_DATA or DEPOS_INTEL_DATA_DIR).",
    )
    replay.add_argument(
        "--run-subdir",
        default=None,
        help='Run artifact subdirectory under data-dir, e.g. ".canonical" for dataset-pipeline (default: intelligence).',
    )

    score_bundles = a_sub.add_parser(
        "score-bundles",
        help="Report-only sidecar: write stub bundle score rows from canonical bundles.json.",
    )
    score_bundles.add_argument("--bundles-json", required=True)
    score_bundles.add_argument("--output")
    score_bundles.add_argument("--model-name", default="", help="Unused; reserved for a future ranker.")
    score_bundles.add_argument("--cache-dir")
    score_bundles.add_argument("--device")
    score_bundles.add_argument("--local-files-only", action="store_true")

    bundle_pipeline = a_sub.add_parser(
        "bundle-pipeline",
        help="Deprecated shim. Use dataset-pipeline, repo, or diff for canonical analysis.",
    )
    bundle_pipeline.add_argument("--bundles-json", required=True)
    bundle_pipeline.add_argument("--scores-json")
    bundle_pipeline.add_argument("--graph-json")
    bundle_pipeline.add_argument("--output-dir")
    bundle_pipeline.add_argument("--top-n", type=int, default=20)
    bundle_pipeline.add_argument("--min-score", type=float, default=None)
    bundle_pipeline.add_argument("--provider", default=None)
    bundle_pipeline.add_argument("--model-name", default="", help="Unused; reserved for a future ranker.")
    bundle_pipeline.add_argument("--cache-dir")
    bundle_pipeline.add_argument("--device")
    bundle_pipeline.add_argument("--local-files-only", action="store_true")
    bundle_pipeline.add_argument(
        "--source-root",
        action="append",
        default=[],
        help="Additional directory to search for source files when reading snippets. May be passed multiple times.",
    )
    bundle_pipeline.add_argument(
        "--path-alias",
        action="append",
        default=[],
        help="Rewrite source-file paths before reading. Format: --path-alias from=to (e.g., src/=apps/api/src/).",
    )
    bundle_pipeline.add_argument(
        "--min-evidence",
        choices=["full", "embedded", "label_only"],
        default=None,
        help="Skip bundles whose dominant snippet quality falls below this threshold.",
    )
    bundle_pipeline.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero when reasoner_run_health is degraded/failed or when path resolution is poor.",
    )

    normalize_dataset = a_sub.add_parser("normalize-dataset", help="Normalize raw dataset AST JSON into a richer node-link graph.")
    normalize_dataset.add_argument("--dataset-dir", required=True)
    normalize_dataset.add_argument("--output", required=True)
    normalize_dataset.add_argument("--repo-root", default=".")
    normalize_dataset.add_argument("--extraction-output")

    prepare_dataset = a_sub.add_parser(
        "prepare-dataset",
        help="Clone or read a repo and export pipeline-compatible raw AST JSON into dataset/<repo_name>/.",
    )
    prepare_dataset_source = prepare_dataset.add_mutually_exclusive_group(required=True)
    prepare_dataset_source.add_argument(
        "--repo-url",
        help="Public git repository URL to clone before exporting AST dataset files.",
    )
    prepare_dataset_source.add_argument(
        "--repo-root",
        help="Existing local repository checkout to export instead of cloning.",
    )
    prepare_dataset.add_argument(
        "--dataset-root",
        default="dataset",
        help="Root directory under which dataset/<repo_name>/ will be created.",
    )
    prepare_dataset.add_argument(
        "--checkout-root",
        default=str(Path("worked") / "repos"),
        help="Where cloned repositories should be stored when --repo-url is used.",
    )
    prepare_dataset.add_argument(
        "--repo-name",
        default=None,
        help="Optional override for the dataset/<repo_name>/ directory name.",
    )

    dataset_pipeline = a_sub.add_parser(
        "dataset-pipeline",
        help="Run raw dataset AST files through normalize -> canonical Stage 1-11 pipeline.",
    )
    dataset_pipeline.add_argument("--dataset-dir", required=True)
    dataset_pipeline.add_argument("--output-dir", required=True)
    dataset_pipeline.add_argument("--repo-root", default=".")
    dataset_pipeline.add_argument("--provider", default=None)
    dataset_pipeline.add_argument("--top-n", type=int, default=20)
    dataset_pipeline.add_argument("--max-bundles", type=int, default=None)
    dataset_pipeline.add_argument("--min-score", type=float, default=None)
    dataset_pipeline.add_argument("--write-extraction", action="store_true")
    dataset_pipeline.add_argument(
        "--pyinstrument-html",
        metavar="PATH",
        default=None,
        dest="pyinstrument_html",
        help="Write a pyinstrument HTML profile to PATH (requires pip install graphifyy[perf]).",
    )
    _add_perf_args(dataset_pipeline)
    _add_scale_args(dataset_pipeline)
    dataset_pipeline.add_argument("--model-name", default="", help="Unused; reserved for a future ranker.")
    _add_cache_args(dataset_pipeline)
    dataset_pipeline.add_argument("--device")
    dataset_pipeline.add_argument("--local-files-only", action="store_true")
    dataset_pipeline.add_argument(
        "--source-root",
        action="append",
        default=[],
        help="Additional directory to search for source files referenced by AST nodes. May be passed multiple times.",
    )
    dataset_pipeline.add_argument(
        "--path-alias",
        action="append",
        default=[],
        help="Rewrite source-file paths before reading. Format: --path-alias from=to (e.g., src/=apps/api/src/).",
    )
    dataset_pipeline.add_argument(
        "--min-evidence",
        choices=["full", "embedded", "label_only"],
        default=None,
        help="Skip bundles whose dominant snippet quality falls below this threshold.",
    )
    dataset_pipeline.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero when reasoner_run_health is degraded/failed or when path resolution is poor.",
    )
    dataset_pipeline.add_argument(
        "--n-jobs",
        type=int,
        default=1,
        metavar="N",
        help="Number of parallel threads for Wave B enrichers (default: 1 = serial).",
    )

    coverage = a_sub.add_parser("coverage", help="Print StitcherCoverageReport only.")
    coverage.add_argument("--path")
    coverage.add_argument("--graph-json")
    coverage.add_argument(
        "--n-jobs",
        type=int,
        default=1,
        metavar="N",
        help="Number of parallel threads for Wave B enrichers (default: 1 = serial).",
    )
    coverage.add_argument(
        "--no-parallel",
        action="store_true",
        help="Same as --n-jobs 1 for Wave B enrichers.",
    )

    list_cmd = d_sub.add_parser("list", help="List built-in detectors.")
    list_cmd.add_argument("--json", action="store_true")

    explain_cmd = d_sub.add_parser("explain", help="Explain one detector.")
    explain_cmd.add_argument("name")
    explain_cmd.add_argument("--json", action="store_true")

    replay_cmd = d_sub.add_parser(
        "replay",
        help="Re-issue queued reasoner attempts from a prior run without re-running upstream stages.",
    )
    replay_cmd.add_argument("--run-id", required=True)
    replay_cmd.add_argument("--mode", choices=["A", "B", "C"], default=None)
    replay_cmd.add_argument("--max", type=int, default=None)
    replay_cmd.add_argument("--provider", default=None)
    replay_cmd.add_argument(
        "--data-dir",
        default=None,
        help="Intelligence data root containing the run folder (default: DEPOS_DATA or DEPOS_INTEL_DATA_DIR).",
    )
    replay_cmd.add_argument(
        "--run-subdir",
        default=None,
        help='Subdirectory under data-dir for run_id, e.g. ".canonical" for dataset-pipeline output.',
    )

    return p


def main_depos(argv: Optional[Sequence[str]] = None) -> int:
    """Console entrypoint for the ``depos`` script (umbrella product name)."""
    return _main(argv, prog="depos")


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Console entrypoint for ``depos-intel`` (historical script name)."""
    return _main(argv, prog="depos-intel")


def _main(argv: Optional[Sequence[str]] = None, *, prog: str = "depos-intel") -> int:
    parser = _build_parser(prog=prog)
    args = parser.parse_args(argv)

    # Lazy imports so a bare ``depos-intel --help`` works without the
    # [depos] / [supabase] extras installed.
    if args.command == "intent-context":
        from depos.cli.intent_context_cmd import run_intent_context_cli

        return run_intent_context_cli(args)
    if args.command == "serve":
        print(
            "Local API: run `depos-api` (or `python -m uvicorn depos.api_server:app --host 0.0.0.0 --port 8080`).\n"
            "Web dashboard: `cd apps/web && npm run dev` with repo-root `.env` (see README).",
            file=sys.stderr,
        )
        return 0
    if args.command == "analyze":
        if args.analyze_command == "coverage":
            from depos.cli.analyze import run_coverage

            return run_coverage(args)
        if args.analyze_command == "repo":
            from depos.cli.analyze import run_repo

            return run_repo(args)
        if args.analyze_command == "diff":
            from depos.cli.analyze import run_diff

            return run_diff(args)
        if args.analyze_command == "replay":
            from depos.cli.analyze import run_replay

            return run_replay(args)
        if args.analyze_command == "score-bundles":
            from depos.cli.analyze import run_score_bundles

            return run_score_bundles(args)
        if args.analyze_command == "bundle-pipeline":
            from depos.cli.analyze import run_bundle_pipeline

            return run_bundle_pipeline(args)
        if args.analyze_command == "normalize-dataset":
            from depos.cli.analyze import run_normalize_dataset

            return run_normalize_dataset(args)
        if args.analyze_command == "prepare-dataset":
            from depos.cli.analyze import run_prepare_dataset

            return run_prepare_dataset(args)
        if args.analyze_command == "dataset-pipeline":
            from depos.cli.analyze import run_dataset_pipeline

            return run_dataset_pipeline(args)
        parser.error(f"unknown analyze subcommand: {args.analyze_command}")
        return 2
    if args.command == "gate":
        from depos.cli.gate import run_gate

        return run_gate(args)
    if args.command == "detector-stats":
        import json

        from depos.output.gate import load_violations_path

        vpath = Path(args.violations)
        if not vpath.is_file():
            print(f"violations file not found: {vpath}", file=sys.stderr)
            return 2
        doc = load_violations_path(vpath)
        stats = doc.get("detector_stats") or []
        print(json.dumps(stats, indent=2, default=str))
        return 0
    if args.command == "migrate-allowlist":
        import json

        mpath = Path(args.mapping)
        apath = Path(args.allowlist)
        raw_map = json.loads(mpath.read_text(encoding="utf-8"))
        if not isinstance(raw_map, dict):
            print("mapping must be a JSON object", file=sys.stderr)
            return 2
        entries = json.loads(apath.read_text(encoding="utf-8"))
        if not isinstance(entries, list):
            print("allowlist must be a JSON array", file=sys.stderr)
            return 2
        out: list[dict] = []
        for e in entries:
            if not isinstance(e, dict):
                continue
            fid = str(e.get("finding_id") or "")
            new_id = str(raw_map.get(fid, fid))
            out.append({**e, "finding_id": new_id})
        outp = args.output or apath
        outp.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
        return 0
    if args.command == "detectors":
        if args.detectors_command == "list":
            from depos.cli.analyze import run_detectors_list

            return run_detectors_list(args)
        if args.detectors_command == "explain":
            from depos.cli.analyze import run_detectors_explain

            return run_detectors_explain(args)
        if args.detectors_command == "replay":
            from depos.cli.analyze import run_detectors_replay

            return run_detectors_replay(args)
        parser.error(f"unknown detectors subcommand: {args.detectors_command}")
        return 2
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
