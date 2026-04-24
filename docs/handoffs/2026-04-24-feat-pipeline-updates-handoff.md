# Handoff: pipeline stack `5a08700` → `4cc7349` (24 Apr 2026)

Teammate-oriented summary of the commit chain on **`feat/pipeline-updates`** (HEAD `4cc7349` at time of writing), from the **Group C taint model migration** through the **architecture-risk / Kiro diagnostic work**, the **merge to `v4`**, and the latest **reasoner time-budget and product-output work**. Several commits use minimal messages (`refactor (needs review)`, `pipeline`, `kiro-changes`); this document records intent, scope, and why the changes exist.

| Order | Commit     | Subject |
| ----- | ---------- | ------- |
| 1 | `5a08700` | `fix(depos): migrate Group C detectors to typed taint_edges` |
| 2 | `ed97ce3` | `test(depos): assert TaintEdge on graph; drop taint_rows mirror check` |
| 3 | `4a47dfb` | `chore(depos): drop graph.graph taint_rows alias; assert absent in smoke test` |
| 4 | `5b52e94` | `refactor (needs review)` — master pipeline / detector platform expansion |
| 5 | `19054bc` | `refactor (needs review)` — taint follow-up + NOTICE |
| 6 | `cabc5d5` | `refactor (needs review)` — large `dataset/depos` AST export refresh |
| 7 | `57833b7` | `pipeline` — consolidation tests + vendored pytest tree + env/docs |
| 8 | `56cd47b` | `kiro-changes` — diagnostic bugfix specs, focused code + regression tests |
| 9 | `2f26a8e` | `architecture-risk-pipeline-plan` — Cursor plan + `dataset/depos-2/graphify` |
| 10 | `9b01c5f` | Merge PR #1 `crf/kiro-spec` → `v4` |
| 11 | `4cc7349` | `time-complexity improvements` — reasoner policy, staged verifier, product outputs |

---

## Theme A — Typed taint edges and removing `taint_rows` (`5a08700`–`4a47dfb`)

### `5a08700` — migrate Group C detectors to typed `taint_edges`

**Intent:** Move **Group C** (taint / data-flow–oriented) detectors onto a **structured taint representation** (`taint_edges`) instead of ad hoc or loosely typed flows, so downstream stages can rely on a single, typed contract.

**What changed**

- **`depos/analysis/detectors/builtin/group_c_taint_dfg_detectors.py`** — substantial addition (~235 lines): implements or rewires Group C logic to emit/consume **typed taint edge data** consistent with the evolving graph model.
- **`tests/fixtures/jsx_spec_sync_manifest.json`** — fixture updates so tests and manifests stay aligned with detector / graph expectations after the migration.

**Reasoning:** Group C candidates are the highest-risk path for **LLM hallucination** when “taint” is claimed but no real chain exists. A typed `taint_edges` field makes **evidence gating** and tests possible: the pipeline can distinguish “has structural taint support” from “empty placeholder.”

---

### `ed97ce3` — tests: assert `TaintEdge` on graph; drop `taint_rows` mirror check

**Intent:** Lock in the **new graph invariant**: taint structure lives as **`TaintEdge`** (and related graph fields), not as a parallel **`taint_rows`** mirror that could drift.

**What changed**

- **`tests/intelligence/test_phase1_semantic_layers.py`** — extends coverage so semantic layer / graph construction asserts **`TaintEdge`** presence where expected.
- **`tests/intelligence/test_taint_edge_producers.py`** — new tests ensuring producers emit the right edge shapes; **removes** reliance on a **`taint_rows`** mirror check.

**Reasoning:** Dual representations (`taint_rows` + graph edges) create **silent desync** bugs: tests pass on one mirror while production consumes the other. Dropping the mirror check forces the **canonical graph** to be the source of truth.

---

### `4a47dfb` — drop `graph.graph` `taint_rows` alias; smoke asserts absence

**Intent:** Remove the **compatibility alias** that kept `taint_rows` hanging off `graph.graph`, completing the migration to **`TaintEdge`**-only semantics for taint.

**What changed**

- **`depos/analysis/taint.py`** — large update (~283 lines): implements the taint analysis path without maintaining a **`taint_rows`** alias on the nested graph object; aligns helpers with typed edges.
- **`tests/fixtures/jsx_spec_sync_manifest.json`** — small sync tweak.
- **`tests/intelligence/test_taint_edge_producers.py`** — additional assertions (e.g. that smoke paths do not resurrect the alias).

**Reasoning:** Aliases extend migration pain indefinitely: new code continues to read the wrong field. Removing the alias **fails fast** if anything still expects `taint_rows`, which is preferable to silent wrong results.

---

## Theme B — “Master implementation” refactor (`5b52e94`, `19054bc`, `cabc5d5`)

These three commits are labeled **`refactor (needs review)`** in git history; treat them as a **single architectural push** plus **dataset churn**.

### `5b52e94` — detector platform, CFG/DFG, pipeline, CLI, output canonicalization

**Intent:** Broad depOS analysis upgrade: **control-flow** and **data-flow** layers for JS/TS and Python, **detector grouping** (Group A/B/C modules), **run context** plumbing, **scoring**, **seams**, and **canonical output** helpers — while **removing** the old **`graphcodebert`** integration.

**Highlights (non-exhaustive)**

- **New / expanded:** `depos/analysis/cfg/` (`jsts.py`, `python_cfg.py`, …), `depos/analysis/dfg/` (`jsts_dfg.py`, `python_dfg.py`), `depos/analysis/graph_metrics.py`, `depos/analysis/run_context.py`, `depos/analysis/run_context_bootstrap.py`, `depos/analysis/scoring.py`, `depos/analysis/seams.py`, `depos/analysis/semantic_jsts.py`, `depos/analysis/semantic_python.py`, `depos/analysis/verifier_rules.py`, `depos/output/canonical.py`, `depos/output/gate.py`, `depos/cli/gate.py`, `depos/enrichment/env_resolver.py`, `depos/analysis/citations.py`, `depos-pipeline.jsx`, planning artifact `.cursor/plans/depos_master_implementation_4ed5e277.plan.md`.
- **Detectors:** new **`group_a_graph_detectors.py`**, **`group_b_cfg_detectors.py`**, updates to **`group_c_taint_dfg_detectors.py`**, wholesale **`detectors/__init__.py`** and **`detectors/builtin/common.py`** expansion; many individual detectors touched to adopt shared helpers / signatures.
- **Core pipeline:** `depos/analysis/pipeline.py`, `reasoning_engine.py`, `verifier.py`, `schemas.py`, `config.py`, `context_bundle.py`, `candidate_identifier.py`, `bundle_prompter.py`, `gray_zone_evaluator.py`, `depos/cli/analyze.py`, `depos/cli/__init__.py`.
- **Removal:** `depos/analysis/graphcodebert.py` deleted (~264 lines) — embedding-based path retired in favor of explicit graph/CFG/DFG/seam semantics.

**Reasoning:** The product direction (see `docs/detector-platform.md` and architecture docs) calls for **deterministic, explainable** signals (graph structure, CFG, DFG, seams) rather than opaque embedding similarity. Grouping detectors clarifies **which reasoning mode** applies (graph vs CFG vs taint) and supports **policy** and **gating** later in the stack.

**Review focus for teammates:** size and blast radius — run full **`pytest tests/ -q`**, spot-check **golden / roundtrip** tests, and confirm **no downstream tool** still imported `graphcodebert`.

---

### `19054bc` — taint follow-up + NOTICE trim

**Intent:** Incremental correction on top of `5b52e94` for **`taint.py`** (another ~80 lines net) and a small **`depos/NOTICE`** edit (lines removed).

**Reasoning:** Typical “phase 1.1” fix after a large refactor: align taint helpers with the new detector/pipeline assumptions without re-opening the whole refactor diff.

---

### `cabc5d5` — massive `dataset/depos` graphify JSON refresh + `.env.example`

**Intent:** Regenerate or resync **AST export JSON** under **`dataset/depos/`** (apps/web and depos Python modules) and adjust **`.env.example`** for the new pipeline / tooling expectations.

**Reasoning:** depOS uses vendored **graphify**-style dataset artifacts for **regression and intelligence tests**. After refactors, file hashes and node counts move; refreshing the dataset avoids **stale fixture** failures. The diff is **noise-heavy** for humans — when reviewing, prefer **sampling** a few JSON files and trusting **manifest / test** gates.

---

## Theme C — `57833b7` “pipeline” (consolidation + vendored pytest)

**Intent:** Further **pipeline consolidation** (bundle prompter, candidate identifier, context bundle, detectors/common, graph metrics, gray zone, pipeline, reasoning engine, run context, schemas, seams, taint, verifier, verifier rules, CLI, output writers, docs) and **expanded tests** across intelligence and output.

**Notable repo hygiene:** This commit also adds a full **`.pytest-deps/`** tree (vendored pytest, colorama, iniconfig, packaging, executables) and **`.matplotlib/fontlist-v390.json`**. That is **unusual for a typical Python repo** (normally pytest is a normal dependency). Teammates should decide whether to **keep** (offline/air-gapped CI) or **replace** with standard `pip`/lockfile deps and **gitignore** vendored copies.

**Reasoning:** The substantive pipeline edits align with **canonical output**, **run context**, and **verification** tightening from Theme B; the vendored deps may have been a **local Windows** convenience — validate CI and developer setup expectations before relying on it long term.

---

## Theme D — Kiro diagnostic fixes (`56cd47b`)

**Intent:** Encode and implement the **“depOS Pipeline Diagnostic Fixes”** program: five failure modes (stitcher route matching, ranker label corruption, Ollama timeouts, prompt truncation, graph-anomaly noise, Group C taint gating). Specs and tests live under **`.kiro/specs/depos-pipeline-diagnostic-fixes/`**.

**What changed (high level)**

- **Specs / design / tasks:** `bugfix.md`, `design.md`, `tasks.md`, task summaries, counterexamples, preservation test notes — formal requirements and rollout order.
- **Code:** `depos/analysis/bundle_prompter.py` (prompt budget enforcement), `config.py`, `detectors/__init__.py`, `detectors/builtin/graph_anomaly.py` (low stitcher coverage suppression), `pipeline.py`, `schemas.py` (e.g. `RankingMetadata`), `depos/enrichment/http_probes.py`, `semantic_edges.py` (route linking), `url_normalize.py`.
- **Tests:** large suite of `test_bugfix_*` modules (graph anomaly noise, Group C gating, Ollama timeout / truncation, preservation properties, ranker labels, stitcher route matching), plus focused tests for bundle prompter, HTTP method handling, URL normalize, run result shape, zero-findings regression updates.

**Reasoning:** Diagnostic runs showed **systematic** failures — zero route links, wrong detector labels on disk, local LLM timeouts, oversize prompts, noisy graph-anomaly placeholders, and **ungated** Group C LLM calls. The Kiro package makes fixes **sequential, test-backed, and regression-safe** (see “Preservation” sections in `bugfix.md` / `design.md`).

---

## Theme E — Architecture-risk plan + second dataset tree (`2f26a8e`)

**Intent:** Check in **`.cursor/plans/architecture-risk_pipeline_e968b014.plan.md`** — a phased plan for **product-facing outputs** (`ProductFinding`, `CIDecision`, `PreselectionInfo`, advisory **staged verifier**, graph reliability signals, `write_product_outputs`, legacy-safe serialization). The commit also adds **`dataset/depos-2/graphify/`** — another large graphify JSON export set (parallel to `dataset/depos/`).

**Reasoning:** The plan is the **blueprint** for later work that landed in `4cc7349` (see Theme F). The dataset mirrors the repo state after the diagnostic / refactor wave for **fixture fidelity**.

---

## Theme F — Merge to `v4` (`9b01c5f`)

**Intent:** Integrate the **`crf/kiro-spec`** branch via **GitHub PR #1**, bringing the Kiro diagnostic stack and dataset/plan artifacts onto **`v4`**.

**Reasoning:** Consolidates long-running pipeline work onto the main integration branch before the final performance/product-output slice.

---

## Theme G — `4cc7349` “time-complexity improvements” (reasoner budget, telemetry, product outputs)

Despite the commit message, this is not only Big-O work: it ships **operational controls** for expensive LLM reasoning, **observability**, **advisory verification**, and **product JSON artifacts**.

### Reasoner policy, preselection, and traceability

- **`depos/analysis/pipeline.py`** — adds **`reasoner_policy_summary`** tracking (disabled detectors, per-detector min evidence / max candidates, skip counts, sends-by-detector), integrates **`PreselectionInfo`** on `run_metadata` (counts and limits across eligibility / bundling / selection), enriches **`BundleTraceEntry`** with detector-aware skip reasons for policy / semantic gating, and emits **Ollama bulk-run warnings** when local runs risk **timeout amplification** (suggesting env vars documented in the new runbook).
- **`depos/analysis/config.py`**, **`depos/analysis/schemas.py`** — config and schema support for the above (policy objects, summaries, preselection).

**Reasoning:** “Time complexity” in practice often means **fewer LLM calls** and **fewer retries**, not tighter inner loops. Per-detector caps and evidence floors **prune** the reasoner queue without changing detector correctness for candidates that never needed the LLM.

### Staged verifier + source snippet cache

- **`depos/analysis/verifier.py`** — introduces **`verify_staged`** and **`SourceSnippetCache`** (used from pipeline): **advisory** staged verification with **bounded** per-run snippet reads — see plan phase “staged-advisory” (no gate mutation, no finding rejection from this path alone).

**Reasoning:** Full verification on every candidate can be I/O heavy; staging + caching **bounds work** while still producing **audit-friendly** stage results for product packaging.

### Product outputs module and docs

- **`depos/analysis/product_outputs.py`** (new) — **`write_product_outputs`** builds **`findings.json`**, **`impact_paths.json`**, **`triage_backlog.json`**, **`mcp_context.json`**, **`product_summary.json`** after canonical **`RunResult`** assembly; gated by **`DEPOS_PRODUCT_OUTPUTS_ENABLED`** (default on).
- **`docs/runbooks/reasoner-performance.md`** (new) — how to read **`reasoner_attempts.jsonl`** and **`reasoner_attempt_summary`**, diagnose retry amplification, calibrate **Ollama** timeouts, and use **evidence / detector policy** env vars (`DEPOS_INTEL_MIN_EVIDENCE_SCORE`, `DEPOS_REASONER_*`, `DEPOS_REASONER_DISABLED_DETECTORS`, etc.).
- **`docs/architecture.md`**, **`docs/dataset-pipeline.md`**, **`docs/product.md`** — product and pipeline documentation updated to describe the new outputs and behavior.
- **`.cursor/plans/architecture-risk_pipeline_e968b014.plan.md`** — plan frontmatter updated to **completed** phases (inventory through docs/tests).

### CLI and tests

- **`depos/cli/analyze.py`** — wires **product output directory** resolution and writing into analyze flows where appropriate.
- **New tests:** `tests/analysis/test_product_outputs.py`, `tests/analysis/test_staged_verifier.py`, `tests/intelligence/test_reasoner_attempt_telemetry.py`, `tests/pipeline/test_reasoner_policy.py`; updates to **`test_dataset_pipeline_cli.py`**, **`test_golden_roundtrip.py`**, **`tests/fixtures/jsx_spec_sync_manifest.json`**.

### Dataset noise

- As with earlier commits, **`dataset/depos-2/graphify/*.json`** files move heavily in this commit — treat as **regenerated AST exports**, not hand-edited sources.

**Reasoning:** This commit closes the **architecture-risk plan**: depOS gains **downstream-safe** product artifacts and **operator-grade** reasoner tuning hooks without feeding product assembly back into ranking or gray-zone logic (`product_outputs.py` docstring explicitly forbids feedback loops).

---

## Quick teammate checklist

1. **Run** `pytest tests/ -q` on your platform after pulling this stack; pay attention to **golden** and **dataset pipeline** tests.
2. **Decide** whether **`.pytest-deps/`** and vendored matplotlib font cache should remain in git — if not, remove and rely on **`requirements`** / **`uv`** / **CI** images.
3. **Tune** local Ollama using **`docs/runbooks/reasoner-performance.md`** — especially if you see **retry amplification** or timeouts clustered under configured limits.
4. **Consume** product JSON via **`DEPOS_PRODUCT_OUTPUTS_ENABLED`** and inspect **`product_summary.json`** + **`findings.json`** next to canonical outputs.
5. **When debugging Group C / taint**, use **graph `TaintEdge`** paths only — **`taint_rows`** is intentionally gone.

---

## Related references

- **Diagnostic requirements:** [`.kiro/specs/depos-pipeline-diagnostic-fixes/bugfix.md`](../../.kiro/specs/depos-pipeline-diagnostic-fixes/bugfix.md)
- **Diagnostic design:** [`.kiro/specs/depos-pipeline-diagnostic-fixes/design.md`](../../.kiro/specs/depos-pipeline-diagnostic-fixes/design.md)
- **Architecture-risk rollout plan:** [`.cursor/plans/architecture-risk_pipeline_e968b014.plan.md`](../../.cursor/plans/architecture-risk_pipeline_e968b014.plan.md)
- **Reasoner performance runbook:** [`docs/runbooks/reasoner-performance.md`](../runbooks/reasoner-performance.md)
- **Zero-findings diagnosis:** [`docs/runbooks/reasoner-zero-findings.md`](../runbooks/reasoner-zero-findings.md)
