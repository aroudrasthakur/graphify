# Intent Context Layer — Reference

The **Intent Context Layer** discovers intent-bearing documentation in a repository (Markdown, READMEs, ADRs, policy docs under `.github`), **normalizes** text, splits it into provenance-rich **chunks**, runs deterministic **tier policy** merges, extracts **intent units** with multiple backends (`rules_v0`, `oft_markdown_v0`, optional `llm_v0`), optionally scans source for **OpenFastTrace-style coverage tags**, and writes a **versioned intermediate representation (IR)** to disk.

Intent IR is consumed by downstream tools—notably **[Graphical Intent Context (GIC)](graphical-intent-context.md)**, which maps units to the AST graph—but the intent layer itself **never** mutates the code graph or tree-sitter output. Each **IntentUnit** is a **claim with evidence** (chunk ids, paths, tiers), not ground truth about runtime behavior.

**Schema anchor:** [`intent_manifest.json`](#artifact-intent_manifestjson) field **`intent_schema_version`** — **currently 2**. New fields SHOULD be additive; readers MUST ignore unknown keys they do not care about.

**Gating semantics:** **`effective_tier`** and **`effective_weight`** are the authoritative policy knobs. Raw **`confidence`** from extractors is **not** sufficient alone for CI or merge gates (see [Tiers and gating](#tiers-and-gating)).

---

## Contents

1. [Tiers and gating](#tiers-and-gating)  
2. [End-to-end pipeline](#end-to-end-pipeline)  
3. [CLI](#cli)  
4. [Discovery, globs, and denylists](#discovery-globs-and-denylists)  
5. [Chunking and normalization](#chunking-and-normalization)  
6. [Intent policy (`.depos/intent.yaml`)](#intent-policy-file-depsintentyaml)  
7. [Extractors](#extractors)  
8. [Git doc signals](#git-doc-signals)  
9. [Coverage tag scanning](#coverage-tag-scanning)  
10. [intent_trace_hints.json](#intent_trace_hintsjson)  
11. [Emitted artifacts](#emitted-artifacts)  
12. [Pydantic types (field catalogs)](#pydantic-types-field-catalogs)  
13. [Environment variables](#environment-variables)  
14. [`IntentContextConfig`](#intentcontextconfig-deposanalysisconfigpy)  
15. [Handoff for GIC and alignment](#handoff-for-gic-and-alignment-work)  
16. [Operational guidance](#operational-guidance)  
17. [Non-goals and limitations](#non-goals-and-limitations)  
18. [Source map](#source-layout)

---

## Tiers and gating

| Tier | Role | Typical downstream behavior |
|------|------|------------------------------|
| **P0** | Binding intent jurisdiction (architecture, regulated ADRs when policy dictates) | May block merges when a **consumer** (e.g. GIC `--strict`) says so—not by default in intent build |
| **P1** | Normative but not universally blocking | PR comments, checklists |
| **P2** | Ambient / informative | Diagnostics only |

**Rank order:** P0 strictest → P2 loosest. Integer ranks: **P0 = 0, P1 = 1, P2 = 2**.

**Merge rule (deterministic):**

1. From [`.depos/intent.yaml`](#intent-policy-file-depsintentyaml): `tier_policy = first_matching(tier_rules, relpath)` or **`default_tier`**.
2. **`effective_tier`** = minimum rank among: policy tier; **binding_glob** floor (≥ P1); YAML frontmatter **`normative: true`** (≥ P1); **OFT** `` `type~name~revision` `` in chunk text (≥ P1 for that chunk). Stronger tiers are not weakened by weaker bumps.

**effective_weight:** For each **`IntentUnit`**, `effective_weight = clip(confidence × tier_multiplier(effective_tier), 0..1)` with multipliers **P0: 1.0**, **P1: 0.85**, **P2: 0.45**. Chunks expose **`effective_weight`** as tier multiplier alone (no extractor confidence at chunk level).

Tier provenance is **auditable** via **`tier_lineage`** on manifests, chunks, and units where populated.

---

## End-to-end pipeline

High-level steps implemented in [`depos/intent_context/build.py`](../depos/intent_context/build.py) — `run_intent_context_build`:

1. Resolve **`repo_root`** / **`output_dir`**; optionally override LLM mode from CLI.
2. **Discover** Markdown-like files (`discover.py`) respecting include/exclude and denylisted directories.
3. Load **intent policy** (`.depos/intent.yaml`) → caps, defaults, **`policy_parse_warnings`**.
4. For each discovered file: read bytes, **normalize Markdown** (`normalize_markdown`), **chunk** (`chunk_normalized_text`), compute file-level **tier bundle** (`compute_file_tier_bundle`), optionally **git signals** (`git_doc_signals`), emit **`IntentManifestFile`** + **`IntentChunkRecord`** rows.
5. Run **extractors** on accumulated chunks:
   - **`extract_rules_v0`** — heuristic / pattern units.
   - **`extract_oft_markdown_v0`** — OpenFastTrace-shaped blocks and backtick IDs.
   - Optionally **`extract_units_llm_batched`** when LLM addon is on (`llm_v0`).
6. **`enrich_units_from_chunks`** aligns unit tiers/evidence where needed.
7. **Tag scan**: if **`enable_tag_scan`**, **`scan_coverage_tags`** walks code globs, writes **`intent_coverage_tags.jsonl`**.
8. **`build_trace_hints_from_oft_units`** + coverage records builds **`intent_trace_hints.json`** (OFT nodes, covers/depends edges, coverage tag payloads).
9. Optional **LLM summaries** (`summarize_files`, `summarize_repo`) when addon enabled.
10. Aggregate **`IntentManifest`**, concatenate units (order: **rules → oft → llm** in `intent_units.json`), write **all artifact files**.
11. Return **0** on success.

**Combined unit order on disk (`intent_units.json`):** all **`rules_v0`** units first, then **`oft_markdown_v0`**, then **`llm_v0`** — merge behavior is consumer-defined; document any consumer-side dedup.

---

## CLI

```bash
depos-intel intent-context build --repo-root . --output-dir ./intent-out
```

| Argument | Meaning |
|---------|---------|
| `--repo-root` | Repository checkout root (default `.`) |
| `--output-dir` | **Required** — directory where all intent JSON/JSONL files are written (created if missing). |
| `--intent-llm` | Overrides `DEPOS_INTEL_INTENT_LLM`: **`auto`** \| **`rules`** \| **`llm`**. |

Compare intent to graph (**separate command**, forwards to [GIC](graphical-intent-context.md)):

```bash
depos-intel intent-context graph-compare --repo-root . --intent-dir ./intent-out
# Pin graph: --graph-json ./snapshots/graph.json  |  Gate: --strict  |  SHA: --require-same-commit
```

| Mode (`--intent-llm` / `DEPOS_INTEL_INTENT_LLM`) | Behavior |
|-------------------------------------------------|----------|
| **`auto`** (default) | If `OPENAI_API_KEY` present → runs **`llm_v0`** plus file/repo summaries **in addition** to **`rules_v0`**; else rules-only path. |
| **`rules`** | No network calls; **`rules_v0`** (+ OFT) only; stubs for summaries. CI-friendly. |
| **`llm`** | **`llm_v0`** **required**; exits **non-zero** without API key (`return 2` from [`build.py`](../depos/intent_context/build.py)). |

---

## Discovery, globs, and denylists

Default Markdown discovery globs (**`DEFAULT_INTENT_GLOBS`** in [`depos/intent_context/discover.py`](../depos/intent_context/discover.py)):

- `**/*.md`, `**/*.rst`, `**/README*`, `**/CONTRIBUTING*`, `**/ADR*.md`, `.github/**/*.md`

These merge with **`include_globs`** from `.depos/intent.yaml` (see [Intent policy file](#intent-policy-file-depsintentyaml)). Paths are classified as **`intent`** vs **`mixed`** (`classify_path`) for downstream drift heuristics.

**Directory denylist (skipped during walk):** `node_modules`, `.git`, `dist`, `build`, `graphify-out`, `.next`, `__pycache__`, `.venv`, `venv`, `target`, `.turbo`, …

**Binary-ish suffixes** (skipped when matching): `.png`, `.jpg`, `.pdf`, `.zip`, `.so`, `.dylib`, `.wasm`, …

---

## Chunking and normalization

- **Normalization** strips/adjusts fences per **`fenced_code_policy`** (`strip` vs `annotate` — see [Environment](#environment-variables)).
- **Chunking** respects **`chunk_max_chars`**, **`chunk_overlap_chars`**, **`max_bytes_per_file`**, **`max_chunks_per_run`**, and repo-wide **`max_input_bytes_per_repo`** from [`IntentContextConfig`](#intentcontextconfig-deposanalysisconfigpy).
- Each chunk gets stable **`chunk_id`**, **`source_relpath`**, line range, heading stack, **`path_classification`**, and tier fields after policy merge.

---

## Intent policy file (.depos/intent.yaml)

Optional file at repo root. Example (fuller than minimal):

```yaml
intent_schema_policy: 1

include_globs:
  - "design/**/*.md"
exclude_globs:
  - "**/vendor/**"

default_tier: P2
tier_rules:
  - glob: "docs/architecture/**/*.md"
    tier: P0
  - glob: "docs/adr/**/*.md"
    tier: P1

binding_globs:
  - "policies/**/*.md"
```

Invalid tier strings → warnings; bad rows skipped with entries in **`intent_manifest.policy_parse_warnings`**.

---

## Extractors

| Name | Module | Role |
|------|--------|------|
| **`rules_v0`** | [`rules_v0.py`](../depos/intent_context/rules_v0.py) | Deterministic heuristics over chunk text; no network. |
| **`oft_markdown_v0`** | [`oft_markdown_v0.py`](../depos/intent_context/oft_markdown_v0.py) | Parses OFT-style spec structure in Markdown; fills **`oft_*`** fields and feeds **trace hints**. |
| **`llm_v0`** | [`llm_v0.py`](../depos/intent_context/llm_v0.py) | Optional OpenAI extraction + batched unit generation; governed by token/repo caps. |

**OFT scan guards:** HTML `<!-- oft:off -->` … `<!-- oft:on -->` and RST `.. oft:off` / `.. oft:on` strip regions before chunking so examples do not become false spec items.

---

## Git doc signals

When **`enable_doc_git_signals`** is true, each **`IntentManifestFile`** gets a **`DocSignalsRecord`**: last-commit metadata from git when available. If git is missing or fails, **`git_available`** is false and **`degraded_warning`** may be set—freshness is informational only.

---

## Coverage tag scanning

When **`enable_tag_scan`** is true, [`tag_scan.py`](../depos/intent_context/tag_scan.py) walks **`tag_scan_globs`** (defaults include `**/*.py`, `**/*.go`, `**/*.rs`, `**/*.ts`, …) with per-file byte caps, and records:

- **Long form:** `[impl->type~name~rev]` (with optional `>>needs`)
- **Short form:** `[[name:rev]]`

Output: one JSON object per line in **`intent_coverage_tags.jsonl`** (`CoverageTagRecord`).

---

## intent_trace_hints.json

Not a full OpenFastTrace `aspec` export. Structure (`IntentTraceHints`):

| Field | Content |
|-------|---------|
| **`nodes`** | OFT spec identifiers from Markdown units (`TraceHintNode`: `id`, optional `source_chunk_id`, `kind`). |
| **`edges`** | Parsed **`covers`** / **`depends`** between spec IDs (`TraceHintEdge`). |
| **`coverage_tags`** | Denormalized list of `{file, line, covered_spec_id, …}` mirrors for downstream join (GIC consumes these plus [`intent_coverage_tags.jsonl`](#artifact-intent_coverage_tagsjsonl)). |

Emitted from **`build_trace_hints_from_oft_units`** in [`tag_scan.py`](../depos/intent_context/tag_scan.py).

---

## Emitted artifacts

All paths are relative to **`--output-dir`**.

### Artifact: `intent_manifest.json`

Top-level **`IntentManifest`** — key fields:

| Field | Meaning |
|-------|---------|
| **`intent_schema_version`** | **`2`** — consumer contract anchor. |
| **`repo_sha`** | `git -C repo rev-parse HEAD` or **`unknown`**. |
| **`built_at`** | ISO-8601 UTC timestamp. |
| **`files`** | List of **`IntentManifestFile`** (relpath, sha256, bytes, tiers, **doc_signals**, warnings, lineage). |
| **`parse_warnings`** | Global parse/discovery warnings. |
| **`policy_parse_warnings`** | YAML policy issues. |
| **`counts_by_tier`** | Count of manifest **files** per **P0/P1/P2** after effective tier. |
| **`p0_paths`** | Capped list (200) of P0 file relpaths for quick navigation. |
| **`llm_enabled`**, **`llm_model`**, **`llm_calls`**, **`llm_tokens_in`**, **`llm_tokens_out`** | LLM addon telemetry. |
| **`truncation_warnings`**, **`truncation`**-style messages | Subset of warnings about caps. |
| **`chunks_written`** | Number of chunk records in **`intent_chunks.jsonl`**. |
| **`units_rules`**, **`units_llm`**, **`units_oft`** | Counts of units per extractor family. |
| **`oft_artifact_type_counts`**, **`oft_unique_spec_ids`**, **`oft_revision_warnings`** | OFT inventory & revision consistency warnings. |
| **`coverage_tags_found`** | Count of scanned coverage tag records. |

### Artifact: `intent_chunks.jsonl`

One JSON object per line — **`IntentChunkRecord`** per chunk:

- **`chunk_id`**, **`source_relpath`**, **`start_line`**, **`end_line`**
- **`heading_stack`**, **`text`** (normalized body)
- **`path_classification`**: **`intent`** \| **`mixed`**
- **`effective_tier`**, **`normative_surface`**, **`tier_lineage`**, **`effective_weight`**

### Artifact: `intent_units.json`

Single JSON **array** of **`IntentUnit`** objects (see [IntentUnit catalog](#intentunit)). Order: **rules → oft → llm** as produced by the build.

### Artifact: `intent_coverage_tags.jsonl`

One **`CoverageTagRecord`** per line: **`source_relpath`**, **`line`**, **`tag_shape`**, **`covering_artifact`**, **`covered_spec_id`**, **`raw_excerpt`**.

### Artifact: `intent_trace_hints.json`

Single JSON object — **`IntentTraceHints`**: **`nodes`**, **`edges`**, **`coverage_tags`**.

### Artifact: `intent_file_summaries.jsonl`

If LLM enabled and summaries produced: one **`IntentFileSummary`** per line. Otherwise a **single** stub line: `{"skipped_reason": "llm_disabled_or_no_output"}`.

### Artifact: `intent_repo_summary.json`

If LLM produced repo rollup: **`IntentRepoSummary`**. Otherwise `{"skipped_reason": "llm_disabled_or_no_output"}`.

---

## Pydantic types (field catalogs)

### IntentUnit

| Field | Type | Notes |
|-------|------|--------|
| **`unit_id`** | string | Required stable id. |
| **`kind`** | invariant, ownership, security_policy, api_contract_narrative, data_model, unknown | |
| **`natural_language`** | string | Human-readable claim. |
| **`scope_hints`** | list[string] | Path-like strings linking to implementation (critical for downstream GIC). |
| **`evidence`** | list[**IntentEvidence**] | **`chunk_id`**, optional **`start_line`**, **`end_line`**, char ranges. |
| **`extractor`** | rules_v0 \| llm_v0 \| oft_markdown_v0 | |
| **`confidence`** | 0..1 | Per-extractor heuristic or model score — use with tier. |
| **`effective_tier`** | P0 \| P1 \| P2 | |
| **`normative_surface`** | bool | |
| **`tier_lineage`** | **TierLineageEntry**[] | |
| **`effective_weight`** | 0..1 | Policy weight for gates. |
| **`oft_*`** | optional / lists | **`oft_spec_item_id`**, **`oft_covers`**, **`oft_needs`**, **`oft_depends`**, **`oft_revision`**, excerpts, … |

### IntentEvidence

**`chunk_id`** (required), **`start_line`**, **`end_line`**, **`char_start`**, **`char_end`**.

### TierLineageEntry

**`source`**: policy_glob, default, frontmatter, binding_glob, oft_markdown_pattern, merged — **`tier_after`** is the resulting **`IntentTier`**.

### TraceHintNode / TraceHintEdge / IntentTraceHints

See [intent_trace_hints.json](#intent_trace_hintsjson).

---

## Environment variables

| Variable | Effect |
|---------|--------|
| `OPENAI_API_KEY` | Enables LLM path when **`llm_mode`** is **`auto`** or **`llm`**. |
| `OPENAI_MODEL` | Default chat model (unless **`DEPOS_INTEL_INTENT_MODEL`** set). |
| `DEPOS_INTEL_INTENT_LLM` | **`auto`** \| **`rules`** \| **`llm`** — loaded in [`load_config_from_env`](../depos/analysis/config.py). |
| `DEPOS_INTEL_INTENT_MODEL` | Overrides model for intent-only calls. |
| `DEPOS_INTEL_INTENT_MAX_TOKENS`, `..._MAX_REPO_BYTES`, `..._MAX_CHUNKS`, `..._MAX_FILE_BYTES`, `..._CHUNK_CHARS`, `..._CHUNK_OVERLAP` | Integer caps (see config loader). |
| `DEPOS_INTEL_INTENT_FENCED` | **`strip`** (default) or **`annotate`**. |
| `DEPOS_INTEL_INTENT_TAG_SCAN` | **`1`** / **`0`** — coverage tag scan. |
| `DEPOS_INTEL_INTENT_GIT_SIGNALS` | **`1`** / **`0`** — per-file git metadata. |
| `DEPOS_INTEL_INTENT_DEFAULT_TIER` | **`P0`** / **`P1`** / **`P2`** — overrides YAML **`default_tier`** without editing the file. |

---

## `IntentContextConfig` ([`depos/analysis/config.py`](../depos/analysis/config.py))

| Field | Default / notes |
|-------|-----------------|
| **`llm_mode`** | **`auto`** |
| **`max_tokens_per_call`** | 4096 |
| **`max_input_bytes_per_repo`** | 5_000_000 |
| **`max_chunks_per_run`** | 500 |
| **`max_bytes_per_file`** | 512_000 |
| **`chunk_max_chars`** | 8000 |
| **`chunk_overlap_chars`** | 400 |
| **`intent_openai_model`** | optional override vs reasoner |
| **`fenced_code_policy`** | strip \| annotate |
| **`enable_tag_scan`** | True |
| **`tag_scan_globs`** | Built-in glob list covering common code extensions |
| **`enable_doc_git_signals`** | True |
| **`default_intent_tier`** | Optional P0 \| P1 \| P2 |

---

## Handoff for GIC and alignment work

Treat IR as hypotheses. For downstream **graph alignment** (see [Graphical Intent Context](graphical-intent-context.md)):

1. **`intent_schema_version`** ≥ **2** and **`repo_sha`** should match the checkout used for graph extraction when reproducibility matters.
2. **`intent_units[].evidence[].chunk_id`** MUST exist in **`intent_chunks.jsonl`**.
3. Gate merges using **`effective_tier`** + **`effective_weight`**; use **`extractor`** + **`confidence`** only as tie-breakers within the same chunk/tier tier (prefer explicit OFT IDs over pure heuristics).
4. **`path_classification: mixed`** flags higher coupling between prose and implementation trees — expect more structural drift reviews.

---

## Operational guidance

- **CI (no secrets):** `DEPOS_INTEL_INTENT_LLM=rules`, run **`intent-context build`**, archive **`intent-out/`** as an artifact or commit when policy requires baselines.
- **Dev (richer units):** `auto` with `OPENAI_API_KEY` — expect non-deterministic **`llm_v0`** units; pin model for auditability.
- **Downstream graph compare:** run **`intent-context graph-compare`** with the **same `--repo-root`** and committed **`intent-out`** aligned to **`repo_sha`** (or accept manifest vs HEAD mismatch **warnings** in GIC unless **`--require-same-commit`**).

---

## Non-goals and limitations

- No NetworkX / graph mutation inside this layer.
- No SARIF or “confirmed vulnerability” language — outputs are **intent claims**, not vuln verdicts.
- No automatic verification of LLM output against runtime behavior — that belongs in tests/detectors.
- **`intent_doc_signals.jsonl`** is **not** emitted; canonical per-file git signals live on **`intent_manifest.files[].doc_signals`**.

---

## Source layout

| Area | Location |
|------|----------|
| Orchestration | [`depos/intent_context/build.py`](../depos/intent_context/build.py) |
| Discovery | [`depos/intent_context/discover.py`](../depos/intent_context/discover.py) |
| Policy | [`depos/intent_context/intent_policy.py`](../depos/intent_context/intent_policy.py), [`intent_yaml.py`](../depos/intent_context/intent_yaml.py) |
| Normative / tier merge | [`depos/intent_context/normative.py`](../depos/intent_context/normative.py) |
| Git signals | [`depos/intent_context/doc_signals.py`](../depos/intent_context/doc_signals.py) |
| Schemas | [`depos/intent_context/schemas.py`](../depos/intent_context/schemas.py) |
| Extractors | [`rules_v0.py`](../depos/intent_context/rules_v0.py), [`oft_markdown_v0.py`](../depos/intent_context/oft_markdown_v0.py), [`llm_v0.py`](../depos/intent_context/llm_v0.py) |
| Tag scan | [`depos/intent_context/tag_scan.py`](../depos/intent_context/tag_scan.py) |
| CLI entry | [`depos/cli/intent_context_cmd.py`](../depos/cli/intent_context_cmd.py) |

CLI registration: [`depos/cli/__init__.py`](../depos/cli/__init__.py) (`depos-intel intent-context`).


---

## OpenFastTrace interoperability

[OpenFastTrace](https://github.com/itsallcode/openfasttrace) defines stable IDs (**`type~name~revision`**), needs/covers/depends, and revision discipline. This stack **does not** embed the OFT Java engine; it **parses compatible Markdown and tag shapes** so teams can mix broad discovery with audit-oriented OFT units. See [Coverage tag scanning](#coverage-tag-scanning) and [intent_trace_hints.json](#intent_trace_hintsjson).

---

## Pipeline order (documentation diagram)

```text
checkout_at_SHA
  → intent-context build   (Intent Context Layer — this document)
  → graphify snapshot        (optional explicit step; graph-compare can invoke graphify internally)
  → intent-context graph-compare  (Graphical Intent Context — see graphical-intent-context.md)
```

For GIC specifics, **`intent-context graph-compare`** is documented in **[graphical-intent-context.md](graphical-intent-context.md)**.

