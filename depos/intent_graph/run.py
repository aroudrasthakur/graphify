"""Run GIC: load artifacts, index graph, aggregate metrics, emit report."""
from __future__ import annotations

from collections import Counter
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import networkx as nx

from depos.intent_context.schemas import IntentTraceHints
from depos.intent_graph.graph_index import GraphPathIndex, normalize_key_any, orphan_candidates
from depos.intent_graph.loader import (
    load_chunks,
    load_coverage_tags,
    load_manifest,
    load_trace_hints,
    load_units,
)
from depos.intent_graph.resolve_units import resolve_unit
from depos.intent_graph.schemas import (
    GicCompositeMetrics,
    GicGraphLayerMetrics,
    GicIntentLayerMetrics,
    GicOrphanHint,
    GicReport,
)
from depos.snapshot import build_graph_for_root, load_graph_json

from pydantic import ValidationError

from depos.intent_graph.trace_join import paths_and_refs_from_trace_hints


def _fail_report(repo_root: Path, intent_dir: Path, msg: str) -> GicReport:
    return GicReport(
        repo_root=str(repo_root.resolve()),
        intent_dir=str(intent_dir.resolve()),
        warnings=[msg],
        graph_source="none",
        raw={"fatal": msg},
    )


def _git_head(repo_root: Path) -> str:
    try:
        r = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except (OSError, subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return "unknown"


def _intent_layer_metrics(
    units: list[Any],
    *,
    chunks: dict[str, tuple[str, int, int]],
    trace_hints: IntentTraceHints | None,
) -> GicIntentLayerMetrics:
    by_ex: dict[str, int] = {}
    tier_mix: dict[str, int] = {}
    empty_hint = 0
    p0_hinted = 0
    p0_total = 0

    for u in units:
        by_ex[u.extractor] = by_ex.get(u.extractor, 0) + 1
        tier = getattr(u, "effective_tier", "P2") or "P2"
        tier_mix[tier] = tier_mix.get(tier, 0) + 1
        if tier == "P0":
            p0_total += 1
            th_paths, _ = paths_and_refs_from_trace_hints(u, trace_hints, chunks)
            if (
                getattr(u, "scope_hints", None)
                or getattr(u, "oft_spec_item_id", None)
                or th_paths
            ):
                p0_hinted += 1
        hints = getattr(u, "scope_hints", []) or []
        oft = getattr(u, "oft_covers", None) or getattr(u, "oft_spec_item_id", None)
        if not hints and not oft:
            empty_hint += 1

    n = len(units) or 1
    cov = (p0_hinted / p0_total) if p0_total else 0.0

    return GicIntentLayerMetrics(
        intent_units_total=len(units),
        intent_units_by_extractor=by_ex,
        intent_tier_mix=tier_mix,
        intent_trace_hints_file_present=trace_hints is not None,
        intent_unresolved_rate=empty_hint / n,
        trace_hint_coverage_p0=cov,
    )


def build_report(
    repo_root: Path,
    intent_dir: Path,
    G: nx.Graph | nx.DiGraph,
    *,
    graph_source: str,
    manifest: Any,
    units: list[Any],
    chunks: dict[str, tuple[str, int, int]],
    coverage_tags: Any,
    trace_hints: IntentTraceHints | None,
    strict_commit: bool = False,
) -> GicReport:
    rr = repo_root.resolve()

    warnings: list[str] = []

    if os.environ.get("DEPOS_GIC_LLM", "").strip().lower() in {"1", "true", "yes", "on"}:
        warnings.append(
            "DEPOS_GIC_LLM is set; optional LLM assist is not wired in this version (ignored).",
        )

    manifest_sha = getattr(manifest, "repo_sha", None) or "unknown"
    head_sha = _git_head(rr)
    alignment: Any = "unknown"
    if head_sha != "unknown" and manifest_sha not in {"", "unknown"}:
        alignment = "match" if manifest_sha.startswith(head_sha) or head_sha.startswith(manifest_sha[:7]) else "mismatch"
        if alignment == "mismatch":
            warnings.append(
                "intent_manifest.repo_sha differs from current git HEAD; compare reports at matching commits.",
            )

    intent_layer = _intent_layer_metrics(units, chunks=chunks, trace_hints=trace_hints)
    cov_tags = coverage_tags if isinstance(coverage_tags, list) else list(coverage_tags or [])

    idx = GraphPathIndex(G, rr)

    results = [
        resolve_unit(u, chunks=chunks, coverage_tags=cov_tags, trace_hints=trace_hints, idx=idx, repo_root=rr)
        for u in units
    ]

    reason_counts: dict[str, int] = {}
    p0_tot = tier_res = tier_par = tier_unres = p1_res = 0.0
    p0_unweighted = 0.0

    denom_w = 0.0
    num_w = 0.0
    unit_paths_ref: set[str] = set()
    path_align_hits = 0

    for u, ur in zip(units, results):
        w = float(getattr(u, "effective_weight", 0.0) or 0.0)
        denom_w += max(w, 0.001)
        if ur.status in {"supported", "partial"}:
            num_w += w
        tier = getattr(u, "effective_tier", "P2") or "P2"
        if tier == "P0":
            p0_tot += 1
            if ur.status in {"supported", "partial"}:
                tier_res += 1
            if ur.status == "partial":
                tier_par += 1
            if ur.status == "unresolved":
                tier_unres += 1
                p0_unweighted += w
                if getattr(ur, "unresolved_reason", None):
                    rk = ur.unresolved_reason
                    reason_counts[rk] = reason_counts.get(rk, 0) + 1
        if tier == "P1" and ur.status in {"supported", "partial"}:
            p1_res += 1
        hint0 = ""
        if getattr(u, "scope_hints", None):
            hint0 = (u.scope_hints[0].strip()) if u.scope_hints else ""
        if hint0 and idx.has_file(hint0):
            path_align_hits += 1
        elif hint0:
            sfx = normalize_key_any(hint0, rr)
            for nf in idx.files_set():
                if sfx.endswith(Path(nf).name):
                    path_align_hits += 1
                    break
        for ev in getattr(u, "evidence", []) or []:
            tup = chunks.get(ev.chunk_id)
            if tup and idx.has_file(tup[0]):
                unit_paths_ref.add(normalize_key_any(tup[0], rr))
        for ref in getattr(ur, "evidence", []) or []:
            if ref.source_file:
                unit_paths_ref.add(normalize_key_any(ref.source_file, rr))

    g_align = num_w / denom_w if denom_w else 1.0

    for u in units:
        for h in getattr(u, "scope_hints", []) or []:
            if h.strip():
                unit_paths_ref.add(normalize_key_any(h.strip(), rr))

    orphans_raw = orphan_candidates(G, referenced_paths=unit_paths_ref, repo_root=rr, top_n=12)
    orphan_hints = [
        GicOrphanHint(node_id=nid, source_file=np, in_degree=idg, label=lbl)
        for nid, np, idg, lbl in orphans_raw
    ]

    p1_total_units = sum(1 for u in units if getattr(u, "effective_tier", "") == "P1")
    graph_layer = GicGraphLayerMetrics(
        gic_resolved_rate_p0=tier_res / p0_tot if p0_tot else 0.0,
        gic_resolved_rate_p1=p1_res / p1_total_units if p1_total_units else 0.0,
        gic_partial_rate_p0=tier_par / p0_tot if p0_tot else 0.0,
        gic_unresolved_rate_p0=tier_unres / p0_tot if p0_tot else 0.0,
        gic_path_alignment=path_align_hits / len(units) if units else 0.0,
        unresolved_reason_counts=reason_counts,
        gic_seam_reach=None,
        graph_orphan_feature_count=len(orphan_hints),
    )

    comp = GicCompositeMetrics(
        gic_alignment_score=min(1.0, max(0.0, g_align)),
        strict_p0_unresolved_max=0,
        p0_unresolved_weighted=p0_unweighted,
    )

    gaps = sorted(
        [r for r in results if r.status == "unresolved"],
        key=lambda x: -x.effective_weight,
    )[:10]

    if strict_commit and alignment == "mismatch":
        warnings.append("strict commit check: FAILED (use matching intent build at graph commit)")

    tag_trace = bool(cov_tags) or (
        trace_hints is not None and bool(trace_hints.nodes or getattr(trace_hints, "coverage_tags", []) or ())
    )

    raw: dict[str, Any] = {
        "schema_note": (
            "GIC evaluates deterministic structural linkage (paths, graph nodes/lines); "
            "semantic correctness is always out-of-scope."
        ),
        "graph": {
            "node_count": G.number_of_nodes(),
            "edge_count": G.number_of_edges(),
            "directed": G.is_directed(),
        },
        "intent_bundle": {
            "chunk_maps": len(chunks),
            "coverage_tag_rows_loaded": len(cov_tags),
            "intent_trace_hints_loaded": trace_hints is not None,
            "trace_hint_nodes": len(trace_hints.nodes) if trace_hints else 0,
            "trace_hint_edges": len(trace_hints.edges) if trace_hints else 0,
        },
        "check_classes": {
            "deterministic_structural_scope_and_graph": True,
            "tag_and_trace_hints_oft_coverage": tag_trace,
            "optional_openai_gic_assist": False,
        },
    }

    return GicReport(
        repo_root=str(rr),
        intent_dir=str(intent_dir.resolve()),
        graph_source=graph_source,
        commit_alignment=alignment,
        intent_repo_sha=manifest_sha,
        current_head_sha=head_sha,
        warnings=warnings,
        intent_layer=intent_layer,
        graph_layer=graph_layer,
        composite=comp,
        units=results,
        top_gaps=gaps,
        orphan_hints=orphan_hints,
        llm_assist_disambiguation_count=0,
        raw=raw,
    )


def render_markdown(rep: GicReport) -> str:
    sc = Counter(u.status for u in rep.units)
    lines = [
        "# Graphical Intent Context report",
        "",
        "**What this proves:** doc and policy claims (intent IR) mapped to **repository structure** "
        "(AST graph). It does **not** replace tests, types, or runtime validation.",
        "",
        "## Executive summary",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| gic_alignment_score (tier-weighted resolved / all) | **{rep.composite.gic_alignment_score:.4f}** |",
        f"| P0 unresolved (sum of effective_weight) | {rep.composite.p0_unresolved_weighted:.4f} |",
        f"| commit_alignment (manifest vs HEAD) | `{rep.commit_alignment}` |",
        "",
        "### What was evaluated",
        "",
        "- **Deterministic / structural** — `scope_hints`, evidence chunks, `intent_trace_hints` node→chunk paths, graph `source_file` / `source_location` (always on).",
        "- **Tag / trace** — `intent_coverage_tags.jsonl` and trace-hint embedded coverage tags (when present).",
        "- **Semantic assist** — disabled in this build (`DEPOS_GIC_LLM` ignored for pass/fail; CI-safe).",
        "",
        "## Intent IR (layer A)",
        "",
        f"- `intent_trace_hints.json` present / loaded: **{rep.intent_layer.intent_trace_hints_file_present}**",
        f"- units_total: {rep.intent_layer.intent_units_total}",
        f"- tier_mix: {rep.intent_layer.intent_tier_mix}",
        f"- trace_hint_coverage_p0 (% of P0 with path signal: scope, OFT id, or trace-hint path): **{rep.intent_layer.trace_hint_coverage_p0:.2%}**",
        f"- intent_unresolved_rate (no scope and no OFT id on unit): {rep.intent_layer.intent_unresolved_rate:.2%}",
        "",
        "## Graph context (layer B)",
        "",
        f"| P0 resolved rate | {rep.graph_layer.gic_resolved_rate_p0:.2%} |",
        f"| P1 resolved rate | {rep.graph_layer.gic_resolved_rate_p1:.2%} |",
        f"| P0 partial rate | {rep.graph_layer.gic_partial_rate_p0:.2%} |",
        f"| P0 unresolved rate | {rep.graph_layer.gic_unresolved_rate_p0:.2%} |",
        f"| primary scope_hint path alignment (approx.) | {rep.graph_layer.gic_path_alignment:.2%} |",
        "",
        f"- **Orphan signal (high fan-in, unreferenced by hints):** top {len(rep.orphan_hints)} rows in JSON (`orphan_hints`).",
        "",
    ]

    if rep.graph_layer.unresolved_reason_counts:
        lines += ["### P0 unresolved reasons (count)", "", "| reason | count |", "| --- | --- |"]
        for k, v in sorted(rep.graph_layer.unresolved_reason_counts.items(), key=lambda kv: -kv[1]):
            lines.append(f"| `{k}` | {v} |")
        lines.append("")

    lines += [
        "## Resolution by status",
        "",
        "| status | units |",
        "| --- | --- |",
    ]
    for k, v in sorted(sc.items()):
        lines.append(f"| `{k}` | {v} |")
    lines.append("")

    if rep.warnings:
        lines += ["## Warnings", ""]
        for w in rep.warnings:
            lines.append(f"- {w}")
        lines.append("")

    if rep.top_gaps:
        lines += ["## Top gaps (unresolved P0/P1+, by weight)", ""]
        for g in rep.top_gaps:
            body = g.natural_language.strip().replace("\n", " ")
            if len(body) > 140:
                body = body[:140] + "…"
            lines.append(
                f"- **`{g.unit_id}`** ({g.effective_tier}, w={g.effective_weight:.3f}): _{body}_ — `{g.unresolved_reason}`"
            )
        lines.append("")

    if rep.orphan_hints:
        lines += ["## Orphan hints (sample)", "", "| node | file | in-degree | label |", "| --- | --- | --- | --- |"]
        for o in rep.orphan_hints[:8]:
            lines.append(f"| `{o.node_id}` | `{o.source_file}` | {o.in_degree} | {o.label[:40]} |")
        lines.append("")

    lines += [
        "## CI policy",
        "",
        "- Default: **exit 0** after writing reports.",
        "- `--strict`: exit **1** if any **P0** unit remains `unresolved` (tier-weighted sum > `strict_p0_unresolved_max`).",
        "- `--require-same-commit`: exit **1** if `intent_manifest.repo_sha` does not match `git rev-parse HEAD`.",
        "",
    ]

    return "\n".join(lines)


def run_graphical_intent_compare(
    repo_root: Path,
    intent_dir: Path,
    graph_json: Path | None,
    *,
    output_dir: Path | None = None,
    strict: bool = False,
    require_same_commit: bool = False,
) -> tuple[GicReport, int]:
    rr = repo_root.resolve()
    intent_dir = intent_dir.resolve()
    out_root = output_dir.resolve() if output_dir else intent_dir

    try:
        manifest = load_manifest(intent_dir)
        units = load_units(intent_dir)
        chunks = load_chunks(intent_dir)
        cov = load_coverage_tags(intent_dir)
        th = load_trace_hints(intent_dir)
    except (json.JSONDecodeError, UnicodeDecodeError, OSError, ValidationError, ValueError) as e:
        print(f"error: intent IR under {intent_dir}: {e}", file=sys.stderr)
        return _fail_report(rr, intent_dir, str(e)), 2

    graph_source = "built_snapshot"
    try:
        if graph_json:
            graph_source = str(graph_json.resolve())
            G = load_graph_json(graph_json.resolve())
        else:
            _, G = build_graph_for_root(rr, directed=True)
    except (OSError, ValueError, KeyError) as e:
        print(f"error: loading graph: {e}", file=sys.stderr)
        return _fail_report(rr, intent_dir, f"graph load failed: {e}"), 2

    rep = build_report(
        rr,
        intent_dir,
        G,
        graph_source=graph_source,
        manifest=manifest,
        units=units,
        chunks=chunks,
        coverage_tags=cov,
        trace_hints=th,
        strict_commit=require_same_commit,
    )

    if require_same_commit and rep.commit_alignment == "mismatch":
        rep.warnings.insert(0, "Exiting strict: repo SHA mismatch between intent_manifest and HEAD.")
        json_path = out_root / "intent_graph_report.json"
        md_path = out_root / "intent_graph_report.md"
        out_root.mkdir(parents=True, exist_ok=True)
        json_path.write_text(rep.model_dump_json(indent=2), encoding="utf-8")
        md_path.write_text(render_markdown(rep), encoding="utf-8")
        return rep, 1

    code = 0
    if strict:
        unresolved_p0_weight = sum(
            float(u.effective_weight)
            for u, row in zip(units, rep.units)
            if getattr(u, "effective_tier", "") == "P0" and row.status == "unresolved"
        )
        if unresolved_p0_weight > rep.composite.strict_p0_unresolved_max:
            code = 1

    out_root.mkdir(parents=True, exist_ok=True)
    json_path = out_root / "intent_graph_report.json"
    md_path = out_root / "intent_graph_report.md"
    json_path.write_text(rep.model_dump_json(indent=2), encoding="utf-8")
    md_path.write_text(render_markdown(rep), encoding="utf-8")
    return rep, code


def write_reports(rep: GicReport, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "intent_graph_report.json").write_text(rep.model_dump_json(indent=2), encoding="utf-8")
    (output_dir / "intent_graph_report.md").write_text(render_markdown(rep), encoding="utf-8")