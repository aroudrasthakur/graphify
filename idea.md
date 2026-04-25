# depOS — Product Idea Brief

## The Core Idea

depOS is an **architecture-intelligence platform** built on top of a static code graph. Its central premise is that when engineers ask "what breaks if I change this file?", no existing tool can answer it precisely — linters check style, test runners check behavior, and static analyzers check patterns, but none of them model the *structural dependency network* of a real repo and reason over it.

depOS fills that gap. It takes a snapshot of your repository as a directed multigraph, enriches it with cross-language relationships, CI signals, and runtime facts, runs a detector suite over the graph, optionally passes high-uncertainty findings to an LLM reasoner, and surfaces a ranked list of structural defects and blast-radius estimates.

The output is not just a diagram. It is a machine-queryable risk model — a persistent artifact that can gate CI, feed AI coding assistants with precise context, and power a live dashboard for engineering leaders.

---

## The Problem Space

Modern software has three structural properties that make change-risk hard to reason about:

1. **Multi-language seams.** A Python FastAPI route calls a TypeScript Next.js frontend through an HTTP contract. A Node.js worker reads from a Postgres schema that Python migrations own. These seams are not tracked by any single language's tooling. When the contract drifts, both sides fail silently until production.

2. **Blast radius is opaque.** `auth/session.ts` has 12 direct importers. Those importers have 47 transitive consumers. Changing a single field in that file potentially touches 59 modules. No developer knows this number without running the full suite — and by then it's already merged.

3. **CI signals are disconnected from structure.** A test fails in CI. Which graph nodes does that test touch? Which other nodes share those paths? The answer lives in the intersection of graph topology and test coverage, but no tool holds both at once.

depOS solves all three by owning the graph layer: a cross-language, cross-universe dependency graph that persists across commits and accumulates signals from static analysis, CI runs, and LLM reasoning.

---

## The Product

### What it ingests

The pipeline begins with **graphify** (vendored, MIT-licensed static graph extractor). graphify walks a repository and emits a node-link JSON graph where:

- **Nodes** are named entities: TypeScript modules, Python functions, React components, Next.js routes, Postgres tables, OpenAPI operations, environment variables, config keys, GitHub Actions workflows, and infrastructure resources.
- **Edges** are typed relationships: `IMPORT`, `CALLS`, `DEPENDS_ON`, `HTTP_CALL`, `QUEUE_PUBLISH`, `SCHEMA_REF`, `ENV_REF`, `RLS_POLICY`, `MIGRATION_ALTERS`, and more.

This base graph is extended by depOS into **seven universes**:

| Universe | What it captures |
|---|---|
| `code` | AST-level function/module relationships |
| `deps` | Package manager dependency graph (npm, pip, cargo, etc.) |
| `env` | Environment variable references and their resolution chain |
| `prompt` | LLM prompt templates and their upstream data sources |
| `schema` | Postgres schema + migration history |
| `nextjs` | Next.js App Router route tree + middleware chain |
| `infra` | GitHub Actions workflows, Docker services, deployment config |

Cross-universe edges — called **seams** — are the most valuable part of the graph. A seam is a boundary where data flows between universes: a Python route consuming a Postgres row that a TypeScript client then renders. Seams carry metadata: `source_language`, `target_language`, `pattern` (REST/RPC/queue/schema), `contract_defined`, `contract_verified`. These are exactly the points where drift and defects concentrate.

### What it detects

The **candidate identifier** (Layer 2) seeds analysis from three origins:

- `diff_anchor` — nodes touched by a git diff or CPG diff
- `interface_surface` — all nodes adjacent to seam edges (cross-language boundaries)
- `graph_anomaly` — structural issues independent of any diff: orphaned nodes, missing guards, lockfile drift

Against these seeds, **40+ detectors** fire, organized into three groups by semantic complexity:

**Group A — Pure graph / dependency:**
`env_var_referenced_but_undefined`, `peer_dep_unsatisfied`, `lockfile_drift`, `diff_anchor`, `graph_anomaly`, `interface_surface`, `missing_rls_policy_for_public_table`, `unresolved_import`, `circular_dependency_in_critical_path`, `removed_api_endpoint_still_consumed`, and more.

**Group B — Control-flow aware (CFG required):**
`error_swallowed_in_async_handler`, `route_without_session_check`, `transaction_not_committed`, `missing_error_boundary_on_data_fetch`, `promise_not_awaited_in_sequential_path`, `retry_without_backoff`, and more.

**Group C — Taint / data-flow (DFG + interprocedural):**
`rpc_invoked_without_rls`, `response_field_consumed_but_not_produced`, `redirect_target_not_safelisted`, `user_input_reaches_raw_query`, `migration_missing_rollback`, `seam_contract_drift`, and more.

Each detector emits a **Candidate**: a scored, evidence-rich object with a `scope_id` (the graph node at issue), a `seed_type`, a list of `seam_edges_crossed`, `diff_anchors`, an `analysis_mode`, and a composite score across six dimensions:

```
structural_centrality     — how many paths pass through this node
seam_exposure             — how many cross-language seams touch this scope
change_proximity          — how recently / directly changed
detector_confidence       — detector's own confidence signal
evidence_quality          — richness of supporting evidence
taint_chain_present       — whether a source→sink taint path was traced
blast_radius_norm         — normalized count of affected nodes
```

### How it reasons

High-uncertainty candidates go to the **reasoner** (Layer 3). The reasoner is a fully modular LLM layer with a provider registry:

- **Stub** (test harness)
- **OpenAI** (GPT-4-family, chat API with system/user role split)
- **Gemma** (Google REST endpoint)
- **Ollama** (local inference, raw-completion)
- **Anthropic** (Claude, Messages API with `system` parameter)

Any provider can be registered at runtime. Per-mode overrides let Mode A (lightweight pattern bugs) use a fast/cheap model while Mode C (taint/data-flow) uses a stronger one.

Three **prompt modes** correspond to three reasoning depths:

- **Mode A** — pattern-level: "does this code pattern match the expected contract?"
- **Mode B** — control-flow: "does the CFG reach a guard before the sink?"
- **Mode C** — taint/data-flow: "does user-controlled data reach this execution sink without sanitization?"

Prompts are split into a `system` section (instructions + response contract) and a `user` section (citation block + evidence JSON). Chat-API providers receive separate roles; completion providers receive the concatenated `full` string. The system prompt is configurable per-deployment, enabling XML-tagged instructions for Claude or shorter directives for local models.

All three modes run in parallel via `ThreadPoolExecutor`, collapsing 90–360s sequential latency to the cost of the slowest single call.

Reasoner output is validated against a strict JSON schema. Failed parses go through a JSON repair stage. Persistent transport failures enqueue to a replay file at `<DEPOS_DATA>/intelligence/<run_id>/reasoner_queue.jsonl`.

### How it verifies

The **verifier** (Layer 4) is deterministic. It applies local oracles — code pattern checks, negation checks (does the fix already exist?), cross-universe consistency checks, RLS verdict (is a row-level policy covering this exposure?), and migration state facts (has the referenced schema change been applied or rolled back?). It outputs a `VerifierOutcome` with `trust_level`: `confirmed`, `partially_confirmed`, or `evaluator_surfaced`.

### What it produces

Seven output artifacts per intelligence run:

| Artifact | Contents |
|---|---|
| `findings.json` | Stable `ProductFinding` records for UI triage |
| `impact_paths.json` | Graph-backed affected paths per finding |
| `triage_backlog.json` | Review queues: unreasoned, gray-zone, suppressed, low-evidence |
| `mcp_context.json` | Token-capped context bundle for Claude Code / AI tools |
| `product_summary.json` | Aggregate risk counts + CI gate decision |
| `violations.json` | Legacy CI gate output (semgrep-compatible) |
| `reasoner_queue.jsonl` | Replay queue for failed LLM calls |

---

## The Data Model

### Supabase schema

```
organizations          id, slug, name, created_at
graph_snapshots        id, org_id, repo_slug, git_sha, status, storage_path
intelligence_runs      id, org_id, repo_slug, base_ref, head_ref, status, provider, created_at
intelligence_findings  id, run_id, org_id, bug_type, description, affected_components,
                       witness_path, missing_guard, recommended_fix, reasoner_confidence,
                       trust_level, verifier_outcome, verifier_checks_passed,
                       rls_verdict, migration_state_facts, caveats
ci_signals             id, snapshot_id, org_id, status, sarif_payload, created_at
```

Row-Level Security is enforced on every table: users only see rows for organizations they are members of. All cross-org federation requires an explicit org-controlled allowlist.

### Finding structure

A `ProductFinding` is the stable public-facing record. Its key fields:

- `bug_type` — detector category slug (e.g., `rpc_invoked_without_rls`, `error_swallowed_in_async_handler`)
- `description` — human-readable summary of the defect
- `affected_components` — list of graph node IDs involved
- `witness_path` — for taint findings: the full source-to-sink path through the graph
- `missing_guard` — what's absent (e.g., "RLS policy", "session check", "error boundary")
- `recommended_fix` — concrete remediation suggestion
- `reasoner_confidence` — float 0–1 from the LLM pass (null if reasoner skipped)
- `trust_level` — `confirmed` / `partially_confirmed` / `evaluator_surfaced`
- `verifier_outcome` — deterministic verifier decision string
- `rls_verdict` — Supabase-specific: which policy (or lack thereof) is relevant
- `caveats` — structured exceptions: conditions under which the finding may not apply

---

## The Frontend

The web dashboard is a Next.js 14 App Router application with Supabase auth and full RLS enforcement on the client via the Supabase JS client.

### Routes

```
/                              Marketing landing page
/auth/sign-in                  Supabase Magic Link / OAuth
/auth/sign-up                  Org creation + user onboarding
/orgs/[slug]/snapshots         List and upload graph snapshots
/orgs/[slug]/analyze           Browse intelligence runs (branch, risk, file count, status)
/orgs/[slug]/federation        Cross-repo graph view (org allowlist)
/orgs/[slug]/drift             Branch comparison: main vs feature
/orgs/[slug]/intelligence      Run history with finding counts and CI gate decisions
```

### Console mock (product vision)

The ConsoleMock component in the marketing page shows the intended UX:

- Left sidebar: Snapshots · Analyze · Federation · Drift · Intelligence (with active-rail accent)
- Main table: Run rows with branch, risk score, file count, status badge
- Bottom drawer: Raw JSON output (the `findings.json` artifact) accessible per-run
- Risk is quantified as a score (0–1) and color-coded

The live dashboard maps exactly to this mock — it's not aspirational, it's the actual schema.

---

## The CI Integration

depOS integrates into GitHub Actions via OIDC trust (no long-lived secrets). The integration is a two-step flow:

1. **Post-build:** `POST /v1/ci/analyze` — sends org_slug, repo_slug, graph_snapshot_id, changed_files. Returns a `product_summary.json` with a `ci_gate` boolean.
2. **Post-test:** `POST /v1/ci/postci` — sends test results, SARIF output, coverage. Correlates CI signals with graph nodes; enriches existing findings with coverage facts.

The `ci_gate` decision blocks merge if any `confirmed` findings exist with severity above a configurable threshold.

---

## The Intelligence Export (MCP)

Every intelligence run produces an `mcp_context.json` — a token-capped (configurable, default ~60k tokens) structured context bundle designed for AI tools. It contains:

- Run metadata (repo, branch, git SHA)
- The top-N findings with full detail
- The relevant graph subgraph (nodes + edges around the findings)
- SARIF diagnostics fused into finding context
- CI signal summaries

Claude Code and other MCP-compatible tools can ingest this to act on findings with structural awareness — not just "there's a bug in line 42" but "this function is in the blast radius of 3 changed modules, crosses a seam into the schema universe, and lacks an RLS policy covering the user-controlled input path."

---

## Positioning

depOS sits in the **change-risk layer** — between source hosting and deployment. It complements, rather than replaces:

- **Source hosts** (GitHub, GitLab) — depOS reads git diffs but adds graph topology
- **Static analyzers** (ESLint, Pylint, Semgrep) — depOS ingests their SARIF output but models structural impact
- **CI systems** (GitHub Actions, CircleCI) — depOS reads test results but maps them to the graph
- **Service catalogs** (Backstage) — depOS provides the live dependency graph that catalogs lack
- **Observability** (Datadog, Sentry) — depOS models pre-production risk; observability handles post-production reality

The unique value proposition: **graph-native blast radius with LLM-verified structural defects, persisted per org and gated into CI.**

---

## Technical Stack

| Layer | Technology |
|---|---|
| Graph extraction | graphify (vendored, Python, MIT) |
| Analysis pipeline | Python 3.9+, NetworkX, Pydantic, AST/tree-sitter |
| API server | FastAPI + SQLAlchemy |
| Database + Auth | Supabase (Postgres, RLS, Storage, Magic Link) |
| LLM providers | Anthropic, OpenAI, Gemma, Ollama |
| Frontend | Next.js 14, React 18, TypeScript |
| UI | Tailwind CSS, Framer Motion, Radix UI, Lucide |
| CI integration | GitHub Actions OIDC |

---

## Current State (April 2026)

**Implemented:**
- Full 7-layer pipeline (ingest → enrich → candidate → bundle → reason → verify → rank)
- 40+ detectors across Groups A, B, and C
- 4-provider LLM reasoner with parallel mode execution (~3× speedup)
- Deterministic verifier with RLS verdict and migration state facts
- Supabase schema with RLS on all tables
- Next.js dashboard with org/snapshot/intelligence routes
- CI integration via POST endpoints
- MCP context export
- Marketing landing page with 3D scroll effects

**Near-term:**
- CPG (Composite Program Graph) as an alternate graph source
- GraphCodeBERT pre-ranking for candidate prioritization before LLM
- Autonomous code rewriting from confirmed findings
- Universal language coverage (Rust, Go, Java)
