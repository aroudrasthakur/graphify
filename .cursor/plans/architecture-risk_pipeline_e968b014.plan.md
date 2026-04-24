---
name: architecture-risk pipeline
overview: Refine the depOS intelligence pipeline with additive product-facing outputs (ProductFinding models), advisory staged verifier, graph reliability as a product signal, product CIDecision, centralized write_product_outputs, and legacy-safe serialization. Shipped in small gated phases; each phase preserves existing artifacts and passes targeted tests before proceeding. Full pytest tests/ -q at final gate. Completed after approval.
todos:
  - id: phase0-inventory
    content: Phase 0 - Codebase inspection and output contract inventory (schemas, Finding type, writers, output dirs, RunResult wiring, model_dump risk, golden tests). Document in plan appendix; no feature code.
    status: completed
  - id: phase1-product-schemas
    content: Phase 1 - Add ProductFinding, ProductEvidence, ProductImpactPath, ProductImpactPathNode, ProductImpactPathEdge, ProductAffectedSurface, ProductMCPContext, ProductRunSummary, shared enums, PreselectionInfo, CIDecision; minimal VerifierAuditEntry advisory fields only. No large Finding expansion unless legacy-safe and tested.
    status: completed
  - id: phase1-legacy-serialization
    content: Phase 1 - Legacy serialization protection for _write_violations and any model_dump paths; regression tests for violations.json shape; gate.py unchanged.
    status: completed
  - id: phase1-output-helpers
    content: Phase 1 - resolve_product_output_dir + write_product_outputs (DEPOS_PRODUCT_OUTPUTS_ENABLED); single call per analyze mode; schema_version 1.0 on all new artifacts.
    status: completed
  - id: phase1-pipeline-preselection
    content: Phase 1 - Attach PreselectionInfo in run_modules_2_through_7 after slicing (search for function); comment Module 5 post-selection. No change to ordering or top-N.
    status: completed
  - id: phase1-staged-advisory
    content: Phase 1 - verify_staged advisory only (stage_results + validity fields); bounded per-run SourceSnippetCache; no VerifierOutcome mutation; no gate change; no finding rejection.
    status: completed
  - id: phase2-graph-product
    content: Phase 2 - graph_reliability product signal; ProductFinding impact_confidence/caveats/request_review for coverage-sensitive; no core gray-zone movement; examples A/B in tests/docs.
    status: completed
  - id: phase2-ci-mcp
    content: Phase 2 - CIDecision from ProductFinding + policy snapshot; conservative defaults vs legacy gate; MCP caps, redaction, review_only.
    status: completed
  - id: phase3-docs-tests-final
    content: Phase 3 - Docs (product, architecture, dataset-pipeline); unit-first tests + minimal integration; final pytest tests/ -q.
    status: completed
isProject: false
---

## Line numbers in this plan

**Line numbers are approximate hints only.** Search by **function/class name** and **behavior** before editing. **Do not patch based only on line numbers.**

---

## Phase 0: Codebase inspection and output contract inventory

**Insert before Phase 1 implementation.** Deliverable: documented answers (appendix in this plan or `docs/` note).

Phase 0 must inspect and document:

- **Current schema definitions** and **serialization behavior** (`model_dump`, defaults, JSON mode).
- Whether **`Finding`** is a **Pydantic** model, **dataclass**, or other — and how it is serialized to `violations.json`.
- **Current writers** for: `violations.json`, `run_summary.json`, `candidates.json`, `bundles.json`, `bundle-scores.json`, `bundle_pipeline_trace.json` (functions in [depos/cli/analyze.py](depos/cli/analyze.py) and any helpers).
- **Current output directories** for: `analyze repo`, `analyze diff`, `analyze dataset-pipeline` (including `.canonical` mirror for dataset).
- Whether **repo/diff** write **`run_summary.json`** to disk or only **stdout** + canonical under `data_dir` / `run_output_subdir` / `run_id`.
- How **`RunResult.findings`**, **`violations.json`**, **`gray_zone_audit.jsonl`**, and **ranker** examples (`ranker_phase0_examples.jsonl`) are **connected** (data flow).
- Whether adding **optional fields** to **`Finding`** would change **legacy `model_dump()`** output (and thus golden tests).
- Which **golden** or **compatibility** tests would break on **schema growth** ([tests/output/test_golden_roundtrip.py](tests/output/test_golden_roundtrip.py), [tests/output/test_ci_gate.py](tests/output/test_ci_gate.py), dataset CLI tests, etc.).

**Phase 0 exit:** safest **canonical path** for repo/diff product files is identified before coding `resolve_product_output_dir`.

---

## Rollout

**Shipped in small gated phases.** Each phase must **preserve existing artifacts** and **pass targeted tests** before proceeding. **Do not** imply a single session or a single monolithic PR is required.

---

## Guiding constraints

- **Additive only** for compatibility artifacts: `violations.json`, `bundles.json`, `bundle-scores.json`, `run_summary.json`, `bundle_pipeline_trace.json`, `candidates.json`, training rows, etc.
- **Preselection unchanged:** `(-CandidateScore.composite, candidate_id)` sort, then `max_seeds`, then `min_score` / `max_bundles` / `top_n` slice in `run_modules_2_through_7`. **Module 5 ranker** runs after the per-candidate loop; it does **not** select initial top-N.
- **No global penalty** to `CandidateScore.composite` from graph reliability.
- **Product outputs** must not affect top-N, bundle creation, reasoner, **legacy** verifier outcome, Module 5 ranker, or gray-zone **evaluator** logic.

---

## Legacy serialization protection (dedicated section)

**Rules:**

- **`_write_violations`** must remain **backward-compatible** (use `exclude_none=True`, `exclude_unset=True`, or **explicit `include`** for `Finding` if new optional fields are ever added to the model).
- **[depos/output/gate.py](depos/output/gate.py)** remains **unchanged** in behavior.
- **Golden output tests** remain **unchanged** unless there is a **documented additive** contract change.
- **Product-only fields** must **not** leak into `violations.json\*\* unless the old contract explicitly permits extra keys.
- **Regression tests:** `violations.json` shape stability; **gate** behavior unchanged ([tests/output/test_ci_gate.py](tests/output/test_ci_gate.py), [tests/output/test_golden_roundtrip.py](tests/output/test_golden_roundtrip.py)).

---

## Product-facing models first (not large direct `Finding` expansion)

**Create product models first** in [depos/analysis/schemas.py](depos/analysis/schemas.py) (or `product_schemas.py` if needed for clarity):

- `ProductFinding`
- `ProductEvidence`
- `ProductImpactPath`
- `ProductImpactPathNode`
- `ProductImpactPathEdge`
- `ProductAffectedSurface`
- `ProductMCPContext`
- `ProductRunSummary`

Shared enums may include: `RiskCategory`, `Confidence`, `GraphReliability`, `RecommendedAction`, `FindingStatus` (product), `RunMode`.

**Existing `Finding`** remains **mostly unchanged.**

**Only add optional fields to `Finding` if:**

- the field is **required inside the core pipeline**, or
- legacy serializers already **exclude unset/default** safely, or
- **tests prove** `violations.json`, gate output, and golden roundtrip are **unchanged**, or
- legacy writers are updated to **explicitly exclude** product-only fields.

**Product outputs** are **assembled from:** `Finding`, `ContextBundle`, `VerifierAuditEntry`, `GrayZoneAuditRow`, `RunMetadata`, **`RunResult`**.

**Do not** make `ProductFinding` the canonical internal finding in this work.

---

## Centralized product output writing

**Single helper** (e.g. in [depos/analysis/product_outputs.py](depos/analysis/product_outputs.py) or [depos/cli/product_write.py](depos/cli/product_write.py)):

```text
write_product_outputs(out_dir, result: RunResult, mode: RunMode, config) -> dict[str, str]
```

**Responsibilities:**

- Build **`list[ProductFinding]`** (and aggregates for triage / MCP).
- Write **`findings.json`**, **`impact_paths.json`**, **`triage_backlog.json`**, **`mcp_context.json`**.
- Optionally **`product_summary.json`** if `run_summary` would balloon.
- Return **logical name → path** map; caller merges into **`RunMetadata.output_paths`** and/or **`product_summary`**.
- **`schema_version: "1.0"`** on every new artifact (see **Stable artifact schemas**).
- **Must not** modify candidate selection, reasoner, verifier, or ranking.

**Each** of `run_repo`, `run_diff`, `run_dataset_pipeline` calls **`write_product_outputs` once** (when `DEPOS_PRODUCT_OUTPUTS_ENABLED` is true), not four separate writer hooks scattered everywhere.

---

## Product output directory resolver

```text
resolve_product_output_dir(mode, result: RunResult, config, existing_out_dir=None) -> Path
```

**Behavior:**

- **`analyze repo`:** same **canonical intelligence run directory** used for existing repo analysis artifacts (confirm exact path in Phase 0 — typically `config.data_dir` / `run_output_subdir` / `run_id`).
- **`analyze diff`:** same as above for diff runs (usually same layout with different metadata).
- **`dataset-pipeline`:** **`<out_dir>/gemma4-run/`** (alongside `violations.json`), preserving **mirror** behavior for canonical tree.
- If repo/diff lack a stable pattern, Phase 0 picks the **safest single canonical location**; implement **one helper** used by all modes.
- Record all product output paths in **`RunMetadata.output_paths`** and/or **`product_summary`**.

**Do not** scatter path logic across `run_repo`, `run_diff`, and `run_dataset_pipeline`.

---

## Product output assembly order

1. Run the **existing canonical pipeline** unchanged through **`RunResult`**.
2. **Then** assemble **ProductFinding** and related structures from **`RunResult`** (+ bundles/audits already on the result).
3. **Product outputs must not affect:** top-N selection, bundle creation, reasoner calls, **legacy** verifier calls, Module 5 ranker, or gray-zone evaluation.
4. **Exception:** **`verify_staged`** may attach **advisory** fields to **`VerifierAuditEntry`** additively; it **must not** change **`VerifierOutcome`**.

---

## Staged verifier (this phase: advisory only)

- **`verify_staged`** emits **`stage_results`** and **advisory** validity fields on **`VerifierAuditEntry`** (or a small sidecar structure if needed to avoid `Finding` growth).
- **`verify_staged` does not** alter legacy **`VerifierOutcome`**.
- **`verify_staged` does not** alter **[depos/output/gate.py](depos/output/gate.py)** behavior.
- **`verify_staged` does not** reject findings in the core pipeline.
- **Product assembly** may use advisory fields to set **`ProductFinding`** confidence and **`recommended_action`**.
- **Migration** of advisory fields to **authoritative** verifier outcomes is a **later explicit change**.

**V1 source validation:** use a **bounded per-run `SourceSnippetCache`**, keyed by **absolute path**, **line range**, **`mtime_ns`**, and **file size**. Expose **read counters** for tests. A **process-level** cache is allowed **only** if keyed by **absolute path + mtime/size** (or content hash) to avoid stale cross-run reads.

---

## Graph reliability (product-level; no default core gray-zone push)

- **Graph reliability** is a **product-level** signal on **`ProductFinding`** / **`RunMetadata`**, not a reason to **move** core findings between verified and gray-zone **unless** existing architecture already supports it cleanly.
- **Low reliability** affects **coverage-sensitive** product claims via **caveats**, **`impact_confidence`**, and **`recommended_action=request_review`** on **`ProductFinding`**.
- **Do not** move core **`Finding`** / pipeline outcomes into gray-zone by default for “low reliability + coverage-sensitive.”
- **Gray-zone evaluator** may be **extended later** to persist low-reliability **review** rows; **not** a Phase 1 requirement.
- **Local-code findings** (e.g. null deref, off-by-one) are **never** downgraded **solely** due to low stitcher coverage; **`CandidateScore.composite`** unchanged.

**Example A — local null dereference + low route coverage**

- `finding_confidence` can remain **high** (on `ProductFinding`).
- `impact_confidence` may be **unknown** or **low**.
- `graph_reliability` may be **low** or **partial**.
- **`CandidateScore.composite` unchanged**.

**Example B — API route contract change + failed route stitcher**

- `finding_confidence` may be **medium**.
- `impact_confidence` should be **low** or **partial**.
- `graph_reliability` should be **low** or **partial**.
- **`recommended_action`** should be **`request_review`**.

**Derivation** should use available **`StitcherCoverageReport`** (and related run metadata) per Phase 2 design; if **no** relevant signal, prefer **`unknown`** over arbitrary **`low`**.

---

## CI policy and `CIDecision`

**`CIDecision` is a new product-level decision.** It is **intentionally more conservative by default than the existing gate** (e.g. product default may block on **critical** only, while **legacy** [depos/output/gate.py](depos/output/gate.py) may still treat **high** and **critical** `CONFIRMED` as blocking). **[depos/output/gate.py](depos/output/gate.py) behavior remains unchanged.**

**Recommended default product policy:**

- `block_on_critical_verified = true`
- `block_on_high_verified = false`
- `block_on_gray_zone = false`
- `max_allowed_critical = 0`
- `max_allowed_high = null` (or “no cap” — represent as `None` in code)

**Rules:**

- **`CIDecision` consumes `ProductFinding`** (and product-level review classification), **not** raw legacy `Finding` where avoidable.
- Include **policy snapshot** on **`CIDecision`**.
- **Gray-zone** and **`request_review`** product findings **never block** by default.

---

## `RunMode` mapping

| Entry                                   | `mode`      |
| --------------------------------------- | ----------- |
| `analyze diff`                          | `pr`        |
| `analyze repo`                          | `full_repo` |
| `dataset-pipeline`                      | `dataset`   |
| CI API / post-CI path (when applicable) | `ci`        |
| fallback                                | `unknown`   |

---

## Stable artifact schemas

Every **new** artifact includes **`schema_version: "1.0"`**, **`run_id`**, **`mode`**, **`generated_at`** (ISO-8601 string), then payload-specific keys.

**`findings.json`:** `schema_version`, `run_id`, `mode`, `generated_at`, `findings`

**`impact_paths.json`:** `schema_version`, `run_id`, `mode`, `generated_at`, `impact_paths`

**`triage_backlog.json`:** `schema_version`, `run_id`, `mode`, `generated_at`, `unreasoned_candidates`, `gray_zone_findings`, `suppressed_candidates`, `low_evidence_candidates`

**`mcp_context.json`:** `schema_version`, `run_id`, `mode`, `generated_at`, `contexts` (array of per-context objects, each with `finding_id` or equivalent stable id)

**`product_summary.json`** (if emitted): `schema_version`, `run_id`, `mode`, `generated_at`, `summary`

---

## MCP safety and redaction

- **No** speculative fix instructions for **low-confidence** findings.
- If **`review_only=true`**: **`suggested_fix_strategy`** is **empty** or **review-focused** only.
- Include **`uncertainties`** whenever **`graph_reliability`** is low or **`impact_confidence`** is low.
- **Cap** evidence snippets by **count** and **character length**.
- **Do not** include secrets, tokens, passwords, or **env var values**; **names** are allowed.
- **Redact** obvious secrets in **product** snippets (conservative patterns). **MCP** uses **redacted** snippets.
- **Do not** change **legacy** `violations.json` redaction unless it already does the same.

---

## Feature flag

- **`DEPOS_PRODUCT_OUTPUTS_ENABLED=true`** by default for CLI analyze modes **after** implementation.
- **`true`:** write new product artifacts.
- **`false`:** skip product writes; **legacy** behavior only.
- Tests may **force** `true`.

---

## Phased implementation (summary)

- **Phase 0:** inventory only.
- **Phase 1:** product models, `write_product_outputs` + `resolve_product_output_dir`, legacy-safe violations, preselection metadata, **advisory** `verify_staged` + per-run cache, feature flag, targeted tests.
- **Phase 2:** graph reliability → `ProductFinding`, `CIDecision` from `ProductFinding`, MCP/redaction, unit tests.
- **Phase 3:** docs, minimal integration tests, final **`pytest tests/ -q`**.

---

## Data flow (target)

```mermaid
flowchart LR
  graph[Enriched graph] --> det[Detectors composite]
  det --> pre[Preselect topN]
  pre --> b[ContextBundle]
  b --> r[Reasoner]
  r --> v[verify_all legacy]
  v --> vs[verify_staged advisory]
  vs --> m5[Module5 ranker]
  m5 --> gz[Gray zone]
  gz --> rr[RunResult]
  rr --> po[write_product_outputs]
  rr --> leg[Legacy violations]
```

---

## Test plan (unit-first)

**Unit tests:** `product_outputs` builders, `graph_reliability`, `ci_decision`, `verify_staged` with **synthetic** bundles, **SourceSnippetCache**, **redaction** helpers, **recommended_action** mapping.

**Integration tests (minimal):** one **dataset-pipeline** artifact emission; one **light** repo or diff test **if** fixtures exist.

**Compatibility:** **`violations.json` legacy-safe**; **`depos/output/gate.py`** behavior unchanged.

**Per phase:** targeted `pytest` paths.

**Final:** **`pytest tests/ -q`**.

---

## Final acceptance gate

1. **Phase 0** inventory is completed and reflected in the plan (or linked doc).
2. **Existing compatibility artifacts** are preserved.
3. **Product output generation** is centralized through **`write_product_outputs`**.
4. **Product output paths** are resolved through **`resolve_product_output_dir`**.
5. **New artifacts** use **`schema_version: "1.0"`** and **stable** top-level shapes (including **`generated_at`** on each file).
6. **Product outputs** are emitted for **repo**, **diff**, and **dataset-pipeline** when **`DEPOS_PRODUCT_OUTPUTS_ENABLED=true`**.
7. **Existing** `violations.json` and **[depos/output/gate.py](depos/output/gate.py)** behavior remain **backward-compatible**.
8. **Top-N** preselection is **unchanged** and **documented** (`PreselectionInfo` on `RunMetadata` or equivalent).
9. **Module 5** ranker is **documented** as post-selection phase-0 / training / annotation.
10. **Staged verifier** is **advisory/additive** and does **not** mutate **legacy `VerifierOutcome`**.
11. **Graph reliability** is **separate** from **`CandidateScore.composite`**.
12. **Low stitcher coverage** affects **coverage-sensitive product claims**, not local-issue scores.
13. **Gray-zone** and **low-reliability** **product** findings map to **`request_review`** and do **not** block **default product CI**.
14. **MCP** context is **scoped**, **capped**, **redacted**, and **`review_only`** for uncertain findings.
15. **Tests** are **unit-first** with **minimal** heavy integration.
16. **Docs** updated: `docs/product.md`, `docs/architecture.md`, `docs/dataset-pipeline.md`.
17. **Targeted tests** pass **per phase**.
18. **`pytest tests/ -q`** passes at the **final** gate.

---

## Revised plan summary (for approval)

- **Phase 0** documents schemas, writers, directories, `RunResult` → artifacts wiring, and **`model_dump` / golden** risk before coding.
- **Product** layer uses **`ProductFinding`** and related models first; **`Finding`** stays lean unless pipeline-proven and **legacy-safe**.
- **Legacy serialization** is explicit: **`_write_violations`** and tests protect shape; **gate** unchanged.
- **One** **`write_product_outputs`** and **one** **`resolve_product_output_dir`**; feature flag **`DEPOS_PRODUCT_OUTPUTS_ENABLED`**; **`generated_at` + `schema_version 1.0`** on all new files.
- **Run pipeline → `RunResult` → then product assembly**; no product side-effects on top-N, reasoner, legacy verifier, ranker, or gray-zone **evaluation**.
- **`verify_staged`** is **advisory** only; **per-run** source cache with **mtime/size** keys.
- **Graph reliability** is **product** only; **no** default core gray-zone **movement**; examples **A/B** documented.
- **`CIDecision`** from **`ProductFinding`**; **more conservative** defaults than **legacy** gate; **gate.py** file unchanged.
- **MCP** safety and **redaction** for product only.
- **Tests:** unit-first; **final** full pytest.
- **Phased** rollout, **not** a single session.

## Completion notes

Status: complete.

### Phase 0 inventory

- `Finding`, `RunMetadata`, and `RunResult` are Pydantic models in
  `depos/analysis/schemas.py`.
- `violations.json` is written by `_write_violations` in
  `depos/cli/analyze.py`; it now uses an explicit legacy `Finding` include set
  and excludes product `output_paths` from `run_metadata`.
- Existing writers remain in `depos/cli/analyze.py`: `_write_candidates_json`,
  `_write_bundles_json`, `_write_bundle_scores_json`,
  `_write_bundle_trace_json`, and `_write_run_summary`.
- Repo and diff runs use the canonical intelligence run directory from
  `config.data_dir / config.run_output_subdir / run_id`.
- Dataset pipeline product outputs use `<out_dir>/gemma4-run/`, alongside
  `violations.json`, while the internal `.canonical` mirror behavior remains
  unchanged.
- `RunResult` is the handoff point for product assembly. Findings, bundles,
  verifier audits, gray-zone rows, candidate data, and bundle trace are all
  available after the canonical pipeline completes.
- Module 5 remains post-selection annotation/training; it does not select the
  initial top-N candidates.
- Optional product fields were not added to legacy `Finding`; product data
  lives in `ProductFinding` and related models.

### Implemented surfaces

- Product schemas: `ProductFinding`, `ProductEvidence`,
  `ProductImpactPath`, `ProductAffectedSurface`, `ProductMCPContext`,
  `ProductRunSummary`, `PreselectionInfo`, `CIDecision`, and shared enums.
- Product writer: `depos/analysis/product_outputs.py` centralizes
  `resolve_product_output_dir`, `write_product_outputs`, product CI decisions,
  graph reliability mapping, MCP capping, and redaction.
- CLI wiring: repo, diff, and dataset-pipeline each call product writing once
  when `DEPOS_PRODUCT_OUTPUTS_ENABLED` is enabled.
- Staged verifier: `verify_staged` and bounded per-run `SourceSnippetCache`
  attach advisory audit fields without mutating legacy `VerifierOutcome`.
- Docs updated: `docs/product.md`, `docs/architecture.md`, and
  `docs/dataset-pipeline.md`.

### Verification

- Targeted suite:
  `uv run --with pytest pytest tests/analysis/test_product_outputs.py tests/analysis/test_staged_verifier.py tests/pipeline/test_run_result_shape.py tests/output/test_golden_roundtrip.py tests/output/test_ci_gate.py tests/intelligence/test_dataset_pipeline_cli.py -q`
  passed with `28 passed`.
- Final gate:
  `uv run --with pytest pytest tests/ -q` passed with
  `627 passed, 5 skipped, 2 warnings`.
