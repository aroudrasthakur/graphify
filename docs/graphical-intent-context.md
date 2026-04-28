# Graphical Intent Context (GIC) — Reference

**Graphical Intent Context (GIC)** compares the **intent intermediate representation (IR)** produced by [`intent-context build`](intent-context.md) against the **structural code graph** from graphify (live **`graphify extract` → `build_from_json`** or an optional pinned **NetworkX node-link JSON** snapshot). It emits **tier-weighted alignment metrics**, **per-unit resolution statuses**, **evidence references** (paths, optional graph node ids), **orphan signals** (high fan-in implementation nodes never referenced by intent hints), and **warnings** such as **`intent_manifest.repo_sha`** vs current **`git`** HEAD mismatch.

This layer answers: **Do written goals and trace links land on paths and AST nodes that exist in this checkout?** It does **not** prove functional correctness, UX acceptance, security, or runtime behavior—that remains with **tests**, detectors, humans, and other tooling.

**Report schema:** **`gic_schema_version`** **2** (see [`depos/intent_graph/schemas.py`](../depos/intent_graph/schemas.py)).

---

## Contents

1. [Problems GIC solves (and does not solve)](#problems-gic-solves-and-does-not-solve)  
2. [Inputs and prerequisites](#inputs-and-prerequisites)  
3. [Resolution algorithm](#resolution-algorithm)  
4. [Graph indexing and line semantics](#graph-indexing-and-line-semantics)  
5. [intent_trace_hints joining](#intent_trace_hints-joining)  
6. [Metrics layers (A / B / composite)](#metrics-layers-a--b--composite)  
7. [Report schema (`GicReport`)](#report-schema-gicreport)  
8. [`raw` telemetry payload](#raw-telemetry-payload)  
9. [Markdown human report](#markdown-human-report)  
10. [CLI](#cli)  
11. [Exit codes and strict semantics](#exit-codes-and-strict-semantics)  
12. [Policies for CI](#policies-for-ci-and-release-trains)  
13. [Environment: DEPOS_GIC_LLM](#environment-deps_gic_llm)  
14. [Operational notes](#operational-notes)  
15. [Troubleshooting](#troubleshooting)  
16. [Implementation map](#implementation-map)

---

## Problems GIC solves (and does not solve)

### In scope

- **Wrong or stale paths** in **`scope_hints`** vs graph **`source_file`** paths.
- **Claims with no filesystem anchor** (`unresolved`) where no candidate path matches the graph.
- **Line-level coherence** between evidence/tags and graph **`source_location`** `L{n}` (**`supported`** when hints align within tolerance).
- **OFT-linked units** with empty **`scope_hints`**: **`intent_trace_hints.json`** maps **spec id → chunk → path**, so intent build output still yields graph candidates (see [`trace_join.py`](../depos/intent_graph/trace_join.py)).
- **Orphan hotspots**: graph nodes with high **fan-in / degree** that no intent hint references (**`orphan_hints`** sample).

### Explicitly out of scope

- **Semantics** of whether code behaves as product intends.
- **Complete graph coverage** of every symbol—graphify extraction scope limits apply.
- **Semantic LLM adjudication as a gate:** optional assist is reserved; **`DEPOS_GIC_LLM`** surfaces a warning only today.

---

## Inputs and prerequisites

**Minimum:** `--intent-dir` containing:

| File | Required | Purpose |
|------|-----------|---------|
| **`intent_manifest.json`** | **Yes** | Repo SHA alignment, tier counts, diagnostics. |
| **`intent_units.json`** | Recommended (may be empty `[]`) | **`IntentUnit`** rows to resolve. Empty graph → trivial scores. |

**Highly recommended for meaningful joins:**

| File | Purpose |
|------|---------|
| **`intent_chunks.jsonl`** | Resolves **`evidence[].chunk_id`** → **`source_relpath`** and line spans. |
| **`intent_coverage_tags.jsonl`** | OFT tag locations in source; links **covered_spec_id** ↔ file/line. |
| **`intent_trace_hints.json`** | **Spec id → `source_chunk_id`** and embedded **`coverage_tags`** dict list. |

**Graph input (one of):**

- **Implicit:** omit **`--graph-json`** — GIC calls [`build_graph_for_root`](../depos/snapshot.py) (graphify **`detect` → `extract` → `build_from_json`**) on **`--repo-root`**. This can be expensive on large repos.
- **Explicit:** **`--graph-json path/to/node-link.json`** — deterministic, reproducible CI if the snapshot is archived with the same **`repo_sha`**.

---

## Resolution algorithm

Implementation: [`depos/intent_graph/resolve_units.py`](../depos/intent_graph/resolve_units.py) **`resolve_unit`**.

**Candidate path collection (order, then de-duplicated):**

1. **`unit.scope_hints`** — every non-empty string appended.
2. **`unit.evidence[]` + `chunks` map** — each **`chunk_id`** resolves to **`source_relpath`**.
3. **`intent_coverage_tags`** — for units with **`oft_spec_item_id`**, if **`tg.covered_spec_id`** is a substring of normalized OFT id → append **`tg.source_relpath`**.
4. **`paths_and_refs_from_trace_hints`** — from **`intent_trace_hints.json`**: matching **`TraceHintNode.id`** to **`unit.oft_spec_item_id`** yields chunk paths; embedded **`coverage_tags`** dicts add paths when **`covered_spec_id`** matches flexibly (substring match as in step 3).

**OFT metadata evidence:** if **`oft_covers`** or **`oft_spec_item_id`** present, a **`GicEvidenceRef`** of kind **`oft_covers`** is always attached before resolution outcome.

**Trace metadata:** **`hint_refs`** (**`kind: trace_hint`**) list trace-hint-derived evidence.

**Empty candidates:**

- If **`oft_covers`** / **`oft_spec_item_id`** exists but no paths → **`status: partial`** (OFT trace without graph anchor).
- Else → **`status: unresolved`**, **`unresolved_reason: empty_scope_hints`**.

**For each candidate path** (after **`_suffix_match_path`** — see [Graph indexing](#graph-indexing-and-line-semantics)):

- If graph has **no** **`source_file`** match → skip (try other candidates).
- Else **match file**; if no nodes for file → **`unresolved`, `no_graph_nodes_for_file`** after all candidates exhausted.
- **`line_hint`** from evidence **`start_line`** on same relpath OR coverage tag line on same file.
- **`best_node_for_line`**: pick AST node with **`source_location`** **`L{n}`** maximizing **`n ≤ line_hint`** (nearest container); if no line hint, coarse file-level node.
- **`supported`:** if **`line_hint`** and **`res_ln`** exist and **`|res_ln - line_hint| ≤ 5`**.
- Otherwise **`partial`** (file + nodes, no line agreement).

**Aggregator / status priority:** if any path yields **`supported`** status wins for that unit? Actually per loop: **`best_supported`** is OR across iterations; final status **`supported`** if any path hit line agreement, else **`partial`** if any file+nodes matched.

Conflicting paths: first successful path does not cancel later better line match — **`best_supported`** tracks any.

---

## Graph indexing and line semantics

[`depos/intent_graph/graph_index.py`](../depos/intent_graph/graph_index.py)

- **`normalize_key_any` / `normalize_repo_path`:** map absolute and relative **`source_file`** attributes to **repo-relative POSIX** keys for comparison with intent paths.
- **`GraphPathIndex`:** for each graph node with **`source_file`**, parse **`source_location`** with regex **`^L(\d+)$`**.
- **`best_node_for_line(file, line)`:** nodes sorted; pick **largest line ≤ hint**; if no hint, first node.
- **`orphan_candidates(G, referenced_paths):** high **in-degree** (directed) or **degree** (undirected / **MultiGraph**) nodes whose normalized path is **not** in **`referenced_paths`** (paths collected from scope hints, resolved evidence **`source_file`s, chunk paths).
- **Suffix / leaf match:** **`_suffix_match_path`** — if exact **`has_file`** fails, first graph file whose **basename** matches candidate **leaf** (deterministic first match).

---

## `intent_trace_hints` joining

[`depos/intent_graph/trace_join.py`](../depos/intent_graph/trace_join.py)

- **`normalize_oft_id`** strips backticks/spaces.
- **Nodes:** for each **`TraceHintNode`** whose **`id`** equals unit’s **`oft_spec_item_id`**, if **`source_chunk_id`** exists in **`chunks`**, append that relpath + evidence.
- **Embedded `coverage_tags`:** dicts with **`file`**, **`line`**, **`covered_spec_id`** — flexible id matching, append path and optional line for evidence.

---

## Metrics layers (A / B / composite)

Computed in [`depos/intent_graph/run.py`](../depos/intent_graph/run.py) **`build_report`**.

### Layer A — Intent (`GicIntentLayerMetrics`)

| Field | Definition |
|-------|-------------|
| **`intent_units_total`** | `len(units)` |
| **`intent_units_by_extractor`** | Count by **`extractor`** |
| **`intent_tier_mix`** | Count by **`effective_tier`** |
| **`intent_trace_hints_file_present`** | **`True`** iff **`load_trace_hints`** returned a parsed object (file missing → **`False`**) |
| **`intent_unresolved_rate`** | Fraction of units with **no** **`scope_hints`** and **no** OFT **`oft_covers`/id** |
| **`trace_hint_coverage_p0`** | Fraction of **P0** units with at least one of: non-empty scope, **`oft_spec_item_id`**, or **trace-hint-derived path** from **`paths_and_refs_from_trace_hints`** |

### Layer B — Graph (`GicGraphLayerMetrics`)

| Field | Definition |
|-------|-------------|
| **`gic_resolved_rate_p0`** | Among P0 units, fraction with **`supported`** or **`partial`** |
| **`gic_resolved_rate_p1`** | Same for P1 |
| **`gic_partial_rate_p0`** | Fraction of P0 with **`partial`** |
| **`gic_unresolved_rate_p0`** | Fraction of P0 **`unresolved`** |
| **`gic_path_alignment`** | Per unit: primary **`scope_hints[0]`** matches a graph file (**`has_file`** or basename suffix match) — hit rate over all units |
| **`unresolved_reason_counts`** | Histogram of **`unresolved_reason`** for **P0** unresolved units only |
| **`gic_seam_reach`** | Reserved **`null`** — cross-service path length not implemented in v1 |
| **`graph_orphan_feature_count`** | Length of **`orphan_hints`** list (capped sample, not total graph orphans) |

### Composite (`GicCompositeMetrics`)

- **`gic_alignment_score`** = **Σ `effective_weight`** (units with **`supported`** or **`partial`**) **/** **Σ `effective_weight`** (all units, with a small floor per unit for division stability in implementation).
- **`strict_p0_unresolved_max`** — default **0** (schema hook for future thresholds).
- **`p0_unresolved_weighted`** — **Σ `effective_weight`** for P0 units **`unresolved`** (used for dashboards; strict check uses live sum vs threshold).

---

## Report schema (`GicReport`)

[`GicReport`](../depos/intent_graph/schemas.py) top-level:

| Field | Type | Notes |
|-------|------|--------|
| **`gic_schema_version`** | int | **2** |
| **`generated_at`** | ISO-8601 UTC | |
| **`repo_root`** | string | Absolute path used |
| **`intent_dir`** | string | Intent artifact directory |
| **`graph_source`** | string | **`built_snapshot`** or path to JSON file |
| **`commit_alignment`** | `match` \| `mismatch` \| `unknown` | Compares **`intent_manifest.repo_sha`** to **`git rev-parse HEAD`** (prefix-matching rules when both known) |
| **`intent_repo_sha`**, **`current_head_sha`** | strings | |
| **`warnings`** | string[] | Includes manifest/HEAD mismatch, **`DEPOS_GIC_LLM`**, strict-commit notes |
| **`intent_layer`** | **GicIntentLayerMetrics** | |
| **`graph_layer`** | **GicGraphLayerMetrics** | |
| **`composite`** | **GicCompositeMetrics** | |
| **`units`** | **GicUnitResult[]** | Parallel index order to **`intent_units.json`** inputs |
| **`top_gaps`** | **GicUnitResult[]** | Up to 10 **`unresolved`**, sorted by **`effective_weight`** descending |
| **`orphan_hints`** | **GicOrphanHint[]** | Sample top high-degree unreferenced nodes |
| **`llm_assist_disambiguation_count`** | int | Reserved — **0** unless future assist moves rows |
| **`raw`** | object | Telemetry — see below |

### `GicUnitResult`

| Field | Meaning |
|-------|---------|
| **`unit_id`**, **`natural_language`**, **`effective_tier`**, **`effective_weight`**, **`extractor`** | Copies / derived from intent |
| **`status`** | **`supported`** \| **`partial`** \| **`unresolved`** \| **`conflict`** (reserved) |
| **`unresolved_reason`** | **`none`** or enum: **`no_matching_file`**, **`no_graph_nodes_for_file`**, **`empty_scope_hints`**, **`path_outside_repo`**, **`insufficient_graph_signal`**, **`sha_mismatch_degraded`** |
| **`structural_confidence`** | 0..1 coarse score |
| **`evidence`** | **GicEvidenceRef[]** — **`kind`**: **`scope_hint_path`**, **`oft_covers`**, **`trace_hint`**, etc. |

### `GicEvidenceRef`

**`kind`**, **`detail`**, optional **`node_id`**, **`source_file`**, **`line`**.

### `GicOrphanHint`

**`node_id`**, **`source_file`**, **`in_degree`**, **`label`**.

---

## `raw` telemetry payload

Populated in **`build_report`** — intended for dashboards and audit exports:

- **`schema_note`** — one-line scope statement.
- **`graph`**: **`node_count`**, **`edge_count`**, **`directed`**.
- **`intent_bundle`**: **`chunk_maps`**, **`coverage_tag_rows_loaded`**, **`intent_trace_hints_loaded`**, **`trace_hint_nodes`**, **`trace_hint_edges`**.
- **`check_classes`**: **`deterministic_structural_scope_and_graph`** (always true), **`tag_and_trace_hints_oft_coverage`** (true when tags or trace-hint data present), **`optional_openai_gic_assist`** (false until implemented).

---

## Markdown human report

[`render_markdown`](../depos/intent_graph/run.py) emits:

- Plain-language purpose boundary.
- **Executive summary** table (scores, HEAD alignment).
- **What was evaluated** (three check classes).
- Intent layer (**layer A**) bullet metrics.
- Graph layer (**layer B**) table (P0/P1 rates, alignment).
- Optional **P0 unresolved reason histogram**.
- **Resolution by status** table (counts).
- **Warnings**.
- **Top gaps** — unresolved rows with abbreviated natural language + reason codes.
- **Orphan hints** sample table (**up to ~8 rows**).
- **CI policy** recap (default exit **0**, **`--strict`**, **`--require-same-commit`**).

Pair **`intent_graph_report.md`** with **`intent_graph_report.json`** for automation.

---

## CLI

Registered in [`depos/cli/__init__.py`](../depos/cli/__init__.py); handler [`depos/cli/intent_context_cmd.py`](../depos/cli/intent_context_cmd.py).

```bash
depos-intel intent-context graph-compare --repo-root . --intent-dir ./intent-out \
  [--graph-json ./snapshots/repo-graph.json] \
  [--output-dir ./gic-out] \
  [--strict] \
  [--require-same-commit]
```

| Flag | Meaning |
|------|---------|
| **`--repo-root`** | Repository root for graph extraction and path normalization (default `.`). |
| **`--intent-dir`** | Directory holding **`intent_manifest.json`** etc. Default **`./intent-out`**. |
| **`--graph-json`** | Optional node-link snapshot. Omit to run embedded graphify pipeline (CPU-costly on large repos). |
| **`--output-dir`** | Write **`intent_graph_report.{json,md}`** here; default **intent-dir**. |
| **`--strict`** | Exit **1** if weighted sum of **P0 unresolved** **`effective_weight`** > **`composite.strict_p0_unresolved_max`** (default **0**). See [Exit codes](#exit-codes-and-strict-semantics). |
| **`--require-same-commit`** | Exit **1** on **`commit_alignment == mismatch`** after writing reports. |

**Pre-check:** CLI returns **2** immediately if **`intent_manifest.json`** is missing under **`intent_dir`** (message on stderr).

---

## Exit codes and strict semantics

| Code | Meaning |
|------|---------|
| **0** | Reports written; policy modes satisfied. |
| **1** | Policy failure: **`--strict`** P0 gap OR **`--require-same-commit`** SHA mismatch. |
| **2** | Invalid input: malformed intent IR JSON / validation failure when loading manifest, units, chunks, coverage, or trace hints; or graph load failure (implementation wraps several exception types). Failures print **`error: ...`** to **stderr** and still emit a minimal **`GicReport`** with warnings for some paths. |

**Strict P0 rule (current):**

```text
sum(effective_weight for each unit where tier == P0 and status == unresolved) > strict_p0_unresolved_max  →  exit 1
```

Default **`strict_p0_unresolved_max = 0`**.

---

## Policies for CI (and release trains)

| Policy | Command pattern |
|--------|-----------------|
| **Informational only** | Default (no flags) — always **exit 0** if IR loads and graph builds. |
| **P0 structural gate** | **`--strict`** after intent + graph baselines are healthy. |
| **Reproducible graph** | Commit **`--graph-json`** from the same **`repo_sha`** as **`intent_manifest.repo_sha`**. |
| **Commit lock** | **`--require-same-commit`** for release branches when manifest must match checkout. |

---

## Environment: DEPOS_GIC_LLM

| Value | Behavior |
|-------|----------|
| unset / **`0`** / false | No assist; deterministic only. |
| **`1`** / true / **`on`** | Emits report **warning** that optional LLM assist is **not wired** (future); **never** gates pass/fail today. |

Documented sample in [.env.example](../.env.example).

---

## Operational notes

- **Cost:** Live graph extraction scales with codebase size and **`detect`**’s code file glob. Pin **`--graph-json`** for repeatable CI timings.
- **HEAD vs manifest:** Mismatch warns but does **not** fail unless **`--require-same-commit`**. Align **`intent-context build`** and **`graph-compare`** on same workspace state for interpretable deltas.
- **MultiGraph / directed graphs:** **`orphan_candidates`** uses **`in_degree`** on **`DiGraph`** and **`degree`** on undirected / **MultiGraph** from NetworkX serializers.

---

## Troubleshooting

| Symptom | Likely cause | Mitigation |
|---------|---------------|------------|
| All units **`unresolved`**, **`no_matching_file`** | Paths in **`scope_hints`** do not normalize to graph **`source_file`** strings | Normalize to repo-relative paths; fix typos; use trace hints |
| Mostly **`partial`**, rarely **`supported`** | No line overlaps within **±5** lines vs graph nodes | Provide **`evidence.start_line`** or coverage tags with lines |
| **`no_graph_nodes_for_file`** | File exists as path hint but extractor produced no AST nodes (binary, ignored, unsupported) | Ensure file in graphify **`detect`** set |
| High **orphans** | Hot modules never mentioned in **`scope_hints`** / evidence | Extend docs or shrink scope claims |
| **`commit_alignment mismatch`** | **`intent_manifest`** built at different revision | Re-run **`intent-context build`** or use **`--require-same-commit`** intentionally |

---

## Implementation map

| Component | Path |
|-----------|------|
| Schemas | [`depos/intent_graph/schemas.py`](../depos/intent_graph/schemas.py) |
| Load IR | [`depos/intent_graph/loader.py`](../depos/intent_graph/loader.py) |
| Graph index | [`depos/intent_graph/graph_index.py`](../depos/intent_graph/graph_index.py) |
| Resolve units | [`depos/intent_graph/resolve_units.py`](../depos/intent_graph/resolve_units.py) |
| Trace hints join | [`depos/intent_graph/trace_join.py`](../depos/intent_graph/trace_join.py) |
| Build report + Markdown | [`depos/intent_graph/run.py`](../depos/intent_graph/run.py) |
| Graph snapshot helpers | [`depos/snapshot.py`](../depos/snapshot.py) |
| Public export | [`depos/intent_graph/__init__.py`](../depos/intent_graph/__init__.py) |

Upstream intent IR specification: **[intent-context.md](intent-context.md)**.

---

## Pipeline order

```text
intent-context build → intent-context graph-compare → intent_graph_report.json + intent_graph_report.md
```
