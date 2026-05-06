# depOS - 11-stage pipeline (current state)

This document is the canonical current-state reference for the depOS analysis
pipeline as implemented in the repo today. It is intended to sit alongside
[`depos-pipeline.md`](depos-pipeline.md), which remains the target-state spec.

Use the inline markers below exactly:

- `[TARGET]` - what the target spec says but is not implemented yet
- `[ACTUAL]` - what the repo actually does, with file + line
- `[PARTIAL]` - implemented, but not fully or not exactly as specced

## Stages

### Stage 1 - AST Ingest

[PARTIAL] Tree-sitter extraction is real, but `graphify.extract.extract()` iterates files sequentially and returns one merged extraction dict after cross-file import and call resolution, not persisted per-file AST node sets (`graphify/extract.py:3071`, `graphify/extract.py:3144`, `graphify/extract.py:3171`, `graphify/extract.py:3202`).

[TARGET] Seam candidate tagging at ingest is not implemented.

[ACTUAL] HTTP route / HTTP call tagging happens later in Module 1 probes `annotate_fastapi_routes()` / `annotate_ts_http_calls()`, and queue stitching happens later in `emit_celery_payload_edges()` (`depos/enrichment/http_probes.py:227`, `depos/enrichment/http_probes.py:253`, `depos/enrichment/celery_payload.py:156`).

Output: [ACTUAL] one aggregated extraction JSON with `nodes` and `edges`, then `build_graph_for_root()` feeds that into graph construction (`depos/snapshot.py:18`, `depos/snapshot.py:23`, `depos/snapshot.py:30`).

### Stage 2 - Graph Construction

[ACTUAL] The active repo path is `detect -> extract -> build_from_json(directed=True)` via `GraphifySource`; this is the current production graph source (`depos/snapshot.py:18-32`, `depos/graph_source.py:30-31`, `depos/graph_source.py:47-60`).

[TARGET] `CPGSource` is not implemented; it is reserved for Phase 2 and `get_graph()` raises `NotImplementedError` (`depos/graph_source.py:72-89`).

[PARTIAL] Base graph construction preserves extracted relations such as `imports_from`, `inherits`, and inferred `calls`; it does not itself synthesize a fixed uppercase CPG edge vocabulary (`graphify/extract.py:134`, `graphify/extract.py:758`, `graphify/extract.py:3202-3205`, `graphify/build.py:62-82`).

[PARTIAL] Cross-universe edges are added later in Module 1 enrichment (`HTTP_CALLS_ROUTE`, `TASK_ENQUEUES`, `PRODUCES_PAYLOAD`, `CONSUMES_PAYLOAD`, etc.), and CFG/DFG/taint are added even later by `build_run_context()`, not during `build_from_json()` (`depos/enrichment/semantic_edges.py:229-301`, `depos/enrichment/celery_payload.py:184-219`, `depos/analysis/run_context_bootstrap.py:19-36`).

[ACTUAL] `build_seam_edge_index()` canonicalizes `edge_id` and materializes seam records with `source_language`, `target_language`, `pattern`, `contract_defined`, `contract_verified`, and computed risk on both the seam index and the graph-edge payload (`depos/analysis/seams.py:19-62`, `depos/analysis/seams.py:96-121`, `depos/analysis/schemas.py:220-250`).

Output: [ACTUAL] one mutable `nx.DiGraph`, later enriched in place (`graphify/build.py:40-86`, `depos/enrichment/semantic_edges.py:196-311`).

### Stage 3 - GraphMetrics Computation

[ACTUAL] `compute_graph_metrics()` is called once when `apply_semantic_layer()` builds `RunContext`; it computes PageRank, betweenness, fan-in/out, SCC count/id, cross-language cycles, articulation points, and per-node SCC size (`depos/analysis/run_context_bootstrap.py:21-34`, `depos/analysis/graph_metrics.py:9-60`).

[ACTUAL] `RunContext` carries `manifest`, `graph_metrics`, `seam_edge_index`, and `cfg_available` / `dfg_available` / `taint_edges_available` (`depos/analysis/run_context.py:38-48`).

[PARTIAL] This happens at analysis start, not inside snapshot/graph construction (`depos/analysis/pipeline.py:158-171`).

Output: [ACTUAL] `RunContext` with precomputed metrics and seam index (`depos/analysis/run_context.py:61-75`).

### Stage 4 - Change Manifest Resolution

[PARTIAL] Resolution order is CPG diff > git diff > manual > empty; CPG diff is only consumed if `graph.graph["cpg_diff"]` is already present (`depos/analysis/candidate_identifier.py:86-103`).

[TARGET] Git diff hunk extraction is not implemented; current git resolution uses `git diff --name-only HEAD` (`depos/analysis/candidate_identifier.py:105-147`).

[ACTUAL] `_attach_graph_nodes()` matches `entry.path` against node `source_file` values and appends `node_ids` (`depos/analysis/candidate_identifier.py:150-171`).

[ACTUAL] Full-repo mode falls back to `ChangeManifest(entries=[], resolved_via="empty")`, and `change_proximity` uses PageRank as the no-diff proxy when `resolved_via in {"git", "empty"}` and there are no diff anchors (`depos/analysis/candidate_identifier.py:190-192`, `depos/analysis/detectors/builtin/common.py:212-243`).

Output: [ACTUAL] `ChangeManifest` with matched `node_ids` when available (`depos/analysis/candidate_identifier.py:174-193`).

### Stage 5 - Candidate Identification

[ACTUAL] `identify_candidates()` is the public entry point; it requires a prebuilt `RunContext`, re-resolves the same manifest, and calls the detector registry (`depos/analysis/candidate_identifier.py:615-660`).

[PARTIAL] The four seed sources exist, but as detector registrations (`diff-anchor`, `interface-surface`, `graph-anomaly`, `lexical-keyword-seed`) rather than a separate pre-detector phase (`depos/analysis/detectors/builtin/diff_anchor.py:9-19`, `depos/analysis/detectors/builtin/interface_surface.py:9-19`, `depos/analysis/detectors/builtin/graph_anomaly.py:9-19`, `depos/analysis/detectors/builtin/lexical_keyword_seed.py:9-19`).

[ACTUAL] Group B/C gating is enforced by `semantic_requirement` through `iter_eligible_scopes()` (`depos/analysis/detectors/policy.py:31-58`, `depos/analysis/detectors/__init__.py:187-193`).

[PARTIAL] Group B/C inventory is real, but current builtins are mostly `*-approx` heuristic detectors (`null-dereference-approx`, `sql-injection-approx`, etc.), not the exact proof obligations in the target spec (`depos/analysis/detectors/builtin/group_b_cfg_detectors.py:68-117`, `depos/analysis/detectors/builtin/group_c_taint_dfg_detectors.py:251-271`).

[PARTIAL] `CandidateScore` has the seven dimensions in schema, and context enrichment fills `structural_centrality`, `blast_radius_norm`, and `taint_chain_present`; `evidence_quality` stays `0.0` at candidate-identification time (`depos/analysis/schemas.py:184-200`, `depos/analysis/detectors/__init__.py:95-116`).

[ACTUAL] `Candidate.seam_edges` is typed as `list[SeamEdge]` with resolved endpoints, and `language_path` is now a first-class field; `language_pair` remains as a deprecated compatibility field (`depos/analysis/schemas.py:285-295`, `depos/analysis/detectors/builtin/common.py:64-174`, `depos/analysis/detectors/builtin/common.py:243-346`).

[PARTIAL] `DetectorPayload` is typed but still includes `raw: dict[str, Any]` (`depos/analysis/schemas.py:203-217`).

[ACTUAL] Dedup key is `(scope_id, seam_ids, diff_anchors)` and budget cap is `config.candidates.max_seeds`; `dropped_from_budget` is written back to manifest entries (`depos/analysis/detectors/__init__.py:148-165`, `depos/analysis/detectors/__init__.py:237-238`, `depos/analysis/candidate_identifier.py:655-658`).

Output: [ACTUAL] prioritized `list[Candidate]` sorted by `-score.composite` (`depos/analysis/detectors/__init__.py:163-165`, `depos/analysis/detectors/__init__.py:237-238`).

### Stage 6 - Context Bundle Construction

[ACTUAL] `build_bundle()` produces `ContextBundle` with the original bundle fields plus `scope_text`, `scope_language`, `caller_texts`, `callee_texts`, `seam_neighbor_texts`, `pagerank_percentile`, `scc_size`, `graph_distance_to_diff`, `cfg_summary`, `null_paths`, and bundle-only `node_facts` / `edge_facts` for downstream verification (`depos/analysis/schemas.py:376-420`, `depos/analysis/context_bundle.py:866-978`).

[TARGET] Fields such as `scope_text`, `scope_language`, `caller_texts`, `callee_texts`, `seam_neighbor_texts`, `pagerank_percentile`, `scc_size`, `graph_distance_to_diff`, `cfg_summary`, and `null_paths` are not current bundle fields (`depos/analysis/schemas.py:330-357`).

[ACTUAL] Bundle building carries forward fully materialized seam records, including contract flags and risk, and can still recover endpoints from canonical `edge_id` when needed (`depos/analysis/context_bundle.py:136-153`, `depos/analysis/context_bundle.py:800-851`).

[ACTUAL] The graph is closed after this stage; `verify()` / `verify_all()` and gray-zone `evaluate()` are bundle-only, `run_modules_2_through_7()` passes only candidate/bundle/audit data downstream, and `tests/test_graph_closure.py` enforces that post-bundle modules do not access graph adjacency APIs (`depos/analysis/pipeline.py:332-385`, `depos/analysis/verifier.py:929-966`, `depos/analysis/gray_zone_evaluator.py:304-409`, `tests/test_graph_closure.py:7-27`).

Output: [ACTUAL] one `ContextBundle` per candidate, and downstream stages consume bundle-only `RunResult` artifacts (`depos/analysis/pipeline.py:410-421`, `depos/analysis/schemas.py:809-820`).

### Stage 7 - Graph-Structural Ranking

[PARTIAL] `CandidateScore.composite` is a deterministic weighted sum keyed by analysis mode, and detector outputs are prioritized by `-score.composite` (`depos/analysis/scoring.py:20-105`, `depos/analysis/detectors/__init__.py:163-165`).

[ACTUAL] The pipeline also runs a separate deterministic Phase 0 ranker after verification for training data and `ranking_phase`, not for pre-LLM candidate scheduling (`depos/analysis/pipeline.py:283-301`, `depos/analysis/ranker.py:47-98`).

[ACTUAL] There is no separate post-bundle pre-LLM re-sort stage beyond the earlier candidate prioritization; dataset-backed runs now use that same canonical ordering with adapter-level bundle/selection limits instead of a second bundle-pipeline rank pass (`depos/analysis/pipeline.py:202-208`, `depos/cli/analyze.py:807-857`, `tests/intelligence/test_canonical_pipeline_consolidation.py:27-118`).

Output: [ACTUAL] deterministic ordering, but split across candidate prioritization and later ranker metadata (`depos/analysis/detectors/__init__.py:163-165`, `depos/analysis/pipeline.py:283-301`).

### Stage 8 - LLM Reasoning

[PARTIAL] Prompt rendering is bundle-structured via `render_bundle_prompt()` and includes semantic-layer flags, seams, taint edges, call chains, source-text fields, CFG summaries, null paths, RLS/migration state, and code snippets (`depos/analysis/bundle_prompter.py:19-64`).

[PARTIAL] The prompt now instructs the model to cite `[node:...]`, `[edge:...]`, or `[taint:...]` tokens and to recommend gray-zone when required semantic layers are unavailable, and `evidence_cites_bundle()` recognizes those explicit forms; the prompt still includes snippet text (`code_snippets[].text`), not only abstract graph evidence (`depos/analysis/bundle_prompter.py:26-64`, `depos/analysis/citations.py:34-83`).

[PARTIAL] Model configuration is provider-specific on `config.llm` (`gemma_model`, `openai_model`, `ollama_model`); `config.reasoner` is a deprecated alias to `config.llm` (`depos/analysis/config.py:46-63`, `depos/analysis/config.py:139-158`).

[PARTIAL] Reasoner parsing is strict JSON with repair/coercion, but `uncited` is not set at parse time; `verify()` computes it later via `evidence_cites_bundle()` (`depos/analysis/reasoning_engine.py:424-453`, `depos/analysis/reasoning_engine.py:534-580`, `depos/analysis/verifier.py:391-392`, `depos/analysis/verifier.py:507`).

Output: [ACTUAL] parsed Mode A/B/C outputs; `uncited` is added later on `Finding`, not on reasoner output (`depos/analysis/reasoning_engine.py:677-699`, `depos/analysis/verifier.py:487-509`).

### Stage 9 - Deterministic Verifier

[ACTUAL] Verifier behavior is a bundle-only rule engine: it computes `uncited`, applies `GLOBAL_AUTO_GRAYZONE` first, resolves a finding category from explicit detector / bug-type maps, then evaluates the matching `VerifierRule` against typed score and bundle evidence (`depos/analysis/verifier_rules.py:9-62`, `depos/analysis/verifier_rules.py:65-169`, `depos/analysis/verifier.py:633-924`, `depos/analysis/verifier.py:929-966`).

[ACTUAL] The per-category `VerifierRule` engine is implemented for `security`, `architecture`, and `correctness` (`depos/analysis/verifier_rules.py:19-52`, `tests/intelligence/test_verifier_rules.py:1-118`).

[ACTUAL] `GLOBAL_AUTO_GRAYZONE` is populated with uncited, alias-analysis, dynamic-dispatch, inter-procedural-CFG, heap-identity, and unmodeled-sanitizer conditions (`depos/analysis/verifier_rules.py:55-62`, `tests/intelligence/test_verifier_rules.py:1-118`).

[ACTUAL] The global auto-grayzone pre-pass runs before per-category rule evaluation (`depos/analysis/verifier.py:802-828`, `depos/analysis/verifier.py:855-924`).

[PARTIAL] Internal outcomes remain `confirmed | partially_confirmed | unconfirmed | invalid_reasoning | evaluator_surfaced`, but `VerifierOutcome.canonical` maps them to the target output vocabulary in the output layer (`depos/analysis/schemas.py:513-528`, `depos/output/canonical.py:16-25`).

Output: [ACTUAL] `VerifierAuditEntry` plus `Finding` (`depos/analysis/schemas.py:464-556`, `depos/analysis/verifier.py:465-514`).

### Stage 10 - Gray-Zone Evaluator

[PARTIAL] Gray-zone evaluation is a three-role panel (`A`, `B`, `C`) with provider calls and heuristic fallback, not a single second-pass evaluator prompt (`depos/analysis/gray_zone_evaluator.py:144-258`, `depos/analysis/gray_zone_evaluator.py:323-406`).

[ACTUAL] Entries are admitted for `partially_confirmed_1_check`, `unconfirmed_high_confidence`, `all_inferred_edges`, `rls_context_mismatch`, or `low_stitcher_coverage` (`depos/analysis/gray_zone_evaluator.py:59-80`).

[ACTUAL] It can only surface `evaluator_surfaced`, `hold_for_review`, or `discard`; surfaced findings are marked `VerifierOutcome.evaluator_surfaced`, never `confirmed` (`depos/analysis/gray_zone_evaluator.py:285-320`, `depos/analysis/gray_zone_evaluator.py:401-406`).

[ACTUAL] `GrayZoneAuditRow` carries `failed_rule`, `missing_evidence`, `confidence_range`, and `recommended_action`, and `evaluate()` populates them from verifier audit state plus panel-vote agreement (`depos/analysis/schemas.py:575-608`, `depos/analysis/gray_zone_evaluator.py:304-398`).

Output: [ACTUAL] `gray_zone_audit.jsonl` rows plus optional `evaluator_surfaced` trust-level updates on findings (`depos/analysis/gray_zone_evaluator.py:409-421`).

### Stage 11 - Structured Output

[PARTIAL] `violations.json` is still the primary artifact written by the CLI; it contains `run_id`, `run_metadata`, `ingest_reports`, `detector_stats`, and raw `findings`, while dataset-backed runs now also mirror canonical audit files and derived `candidates.json` / `bundles.json` / `bundle-scores.json` / `bundle_pipeline_trace.json` from the same `RunResult` (`depos/cli/analyze.py:251-260`, `depos/cli/analyze.py:807-857`).

[PARTIAL] Canonical enrichment exists, and it now maps internal verifier outcomes through `VerifierOutcome.canonical`, but it still emits a lighter document than the full target-spec JSON contract (`depos/output/canonical.py:16-110`).

[PARTIAL] SARIF 2.1.0 and PR-comment renderers use canonical statuses, fingerprints, optional primary locations, gray-zone `failed_rule` / `missing_evidence` detail (plus a collapsible PR-comment section), and shared secret redaction for SARIF message text (`depos/output/sarif.py`, `depos/output/redaction.py`, `depos/output/pr_comment.py:21-67`).

[ACTUAL] CI gate fails on canonical `CONFIRMED` high/critical findings, loads `.depOS/allowlist.json` with expiry enforcement, and keeps `--allow-finding-id` only as a deprecated alias (`depos/output/gate.py:19-36`, `depos/cli/gate.py:11-26`, `depos/cli/__init__.py:29-45`). **v1:** each CLI run also writes `gate_result.json` (single precedence table) and `run_manifest.json` (artifact checksums); see `depos/output/gate_result.py` and `depos/output/run_manifest.py`.

Output: [ACTUAL] `repo`, `diff`, and `dataset-pipeline` all route through the same `_run_pipeline()` -> `run_modules_2_through_7()` execution path; `bundle-pipeline` is a deprecated shim, and JSON/SARIF/PR renderers all read from the same `violations.json` document shape (`depos/cli/analyze.py:807-857`, `depos/cli/analyze.py:909-955`, `depos/cli/__init__.py:82-94`, `tests/intelligence/test_canonical_pipeline_consolidation.py:27-118`, `depos/output/json.py:16-21`).

## The Invariants That Hold Across Every Stage

1. [ACTUAL] GraphMetrics are computed once via `build_run_context()` / `apply_semantic_layer()`, and `identify_candidates()` rejects manifest/run-context mismatches instead of rebuilding mid-pipeline (`depos/analysis/run_context.py:61-75`, `depos/analysis/run_context_bootstrap.py:26-34`, `depos/analysis/candidate_identifier.py:626-641`).
2. [PARTIAL] Every `Candidate` has a `CandidateScore` object with all fields present in schema, but `evidence_quality` stays `0.0` at candidate-identification time (`depos/analysis/schemas.py:184-200`, `depos/analysis/detectors/__init__.py:95-116`).
3. [ACTUAL] `Candidate.seam_edges` is `list[SeamEdge]`, and seed builders resolve seam records from the canonical seam index or graph-edge fallback instead of emitting blank endpoints (`depos/analysis/schemas.py:285-295`, `depos/analysis/detectors/builtin/common.py:64-174`).
4. [TARGET] "No `dict[str, Any]` in detector payloads" is not true yet; `DetectorPayload.raw` remains a `dict[str, Any]` (`depos/analysis/schemas.py:203-217`).
5. [ACTUAL] `GraphContextBundle` is now self-contained for downstream stages: verifier and gray-zone evaluation are bundle-only, and `tests/test_graph_closure.py` enforces that post-Stage-6 modules do not access graph adjacency APIs (`depos/analysis/pipeline.py:332-385`, `depos/analysis/verifier.py:929-966`, `depos/analysis/gray_zone_evaluator.py:304-409`, `tests/test_graph_closure.py:7-27`).
6. [ACTUAL] Group B/C detectors do not run on scopes without their required semantic layer (`depos/analysis/detectors/policy.py:31-58`, `depos/analysis/detectors/__init__.py:187-212`). Skipped detectors emit `DetectorRunStats` rows with `skip_reason=semantic_layer_unavailable` on empty/unavailable scopes.
7. [ACTUAL] `GLOBAL_AUTO_GRAYZONE` is applied before per-category verifier rules (`depos/analysis/verifier.py:802-828`, `depos/analysis/verifier.py:855-924`, `depos/analysis/verifier_rules.py:19-62`).
8. [ACTUAL] Gray-zone rows carry `failed_rule`, `missing_evidence`, `confidence_range`, and `recommended_action` populated by the evaluator (`depos/analysis/schemas.py:575-608`, `depos/analysis/gray_zone_evaluator.py:304-398`).
9. [ACTUAL] The LLM prompt is bundle-structured, uncited findings trigger the global auto-grayzone pre-pass, and the output layer maps non-confirmed verifier outcomes to canonical `GRAY-ZONE` statuses (`depos/analysis/bundle_prompter.py:26-64`, `depos/analysis/verifier.py:633-828`, `depos/output/canonical.py:16-25`).
10. [ACTUAL] Canonical seam `edge_id` is consistent across the seam index, candidates, and bundles (`depos/analysis/seams.py:96-121`, `depos/analysis/context_bundle.py:136-153`, `depos/analysis/context_bundle.py:800-851`, `depos/analysis/detectors/builtin/common.py:64-174`).
