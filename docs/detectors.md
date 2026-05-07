# depOS detectors

Detectors are the core of the depOS intelligence pipeline. Each detector is a Python module under `depos/analysis/detectors/builtin/` that emits `Candidate` objects — investigation targets that flow into the reasoner, verifier, and output stages.

## Execution pipeline

`run_all()` in [depos/analysis/detectors/__init__.py](../depos/analysis/detectors/__init__.py) is the single entry point:

1. Load all builtin detector modules via `load_builtin()` (dynamic `importlib` imports).
2. For each registered detector, check policy (enabled/disabled) and semantic gating.
3. Call `runner(graph, manifest, mode, config, ctx)` → `list[Candidate]`.
4. Enrich each candidate with `structural_centrality`, `blast_radius_norm`, and `taint_chain_present` from `RunContext.graph_metrics`.
5. Wrap candidates: normalize `detector_payload` with `detector_name`, `detector_version`, `pipeline_version`, `severity`, `oracle_hints`.
6. Deduplicate by `(scope_id, seam_ids, diff_anchors)`, keep highest composite score.
7. Return top `config.candidates.max_seeds` sorted by `-score.composite`.

**Pipeline version:** `"2.1.0"` (``PIPELINE_VERSION`` in `__init__.py`).

## Semantic gating

Detectors declare a `semantic_requirement` field on their `SPEC`. The policy layer gates them accordingly before calling `run()`:

| `semantic_requirement` | Gate condition | Checked via |
|---|---|---|
| `None` | Always eligible (Group A) | — |
| `"cfg"` | `RunContext.cfg_available[scope_id]` | `iter_eligible_scopes()` in `policy.py` |
| `"dfg"` | `RunContext.dfg_available[scope_id]` | `iter_eligible_scopes()` in `policy.py` |
| `"taint"` | `RunContext.taint_edges_available[scope_id]` | `iter_eligible_scopes()` in `policy.py` |

Scopes without the required layer are silently skipped — the detector never receives them.

## Policy

`DetectorPolicy` in [depos/analysis/detectors/policy.py](../depos/analysis/detectors/policy.py) controls what runs:

- `enabled` / `disabled` — sets of detector names. `disabled` always wins.
- If `enabled` is non-empty, only listed detectors run; otherwise all non-disabled detectors with `enabled_by_default=True` run.
- `severity_overrides` — per-detector severity map applied at wrap time.

`load_policy(raw)` coerces a `dict`, an existing `DetectorPolicy`, or `None` into a `DetectorPolicy` instance.

---

## Group A — graph-only detectors

**File:** [depos/analysis/detectors/builtin/group_a_graph_detectors.py](../depos/analysis/detectors/builtin/group_a_graph_detectors.py)

No semantic layer required. All detectors in this file operate directly on the `nx.DiGraph` and precomputed `RunContext.graph_metrics`.

| Detector | What it finds | Confidence | Key logic |
|---|---|---|---|
| `cross-lang-cycle` | Cycles that span a language boundary | 0.88 | Reads `rctx.graph_metrics.cross_lang_cycles`; emits up to 8 candidates |
| `seam-contract-drift` | Repeated seam patterns that suggest an implicit contract was broken | 0.72 | Pattern frequency analysis on `seam_edge_index` |
| `articulation-point-high-fanin` | High-betweenness nodes that are also high fan-in (removal breaks the graph) | 0.68 | `fan_in >= 6` and `betweenness >= 0.05` from graph metrics |
| `orphan-surface` | Next.js/OpenAPI routes not reachable from production entry nodes | 0.60 | BFS from `ENTRY_NODE_KINDS_PROD = {"next_route", "openapi_operation"}`; excludes test paths |
| `dead-code` | Functions/methods not reachable from production on the call subgraph | 0.52 | BFS on subgraph of `CALLS`, `IMPORTS`, `HTTP_CALLS_ROUTE` edges from prod entries; capped at 40 |
| `high-centrality-isolated` | High-PageRank nodes absent from the change manifest | 0.65 | PageRank from graph metrics intersected with manifest node IDs; requires reasoner |
| `env-var-exposed` | Env vars with no resolved name or dynamic access outside known-safe names | 0.70 | Iterates `env` universe nodes; flags `dynamic_access` or missing `name` |

**Helper functions in this file:**

- `_production_entry_nodes(graph)` — seeds for reachability: zero in-degree `next_route`/`openapi_operation` nodes and FastAPI route nodes, excluding test paths.
- `_reachable_from(graph, seeds)` — BFS via `nx.descendants`.
- `_call_subgraph(graph)` — filters graph to `CALLS`, `IMPORTS`, `HTTP_CALLS_ROUTE`, `TASK_ENQUEUES`, `TASK_CONSUMES` edges.

---

## Group B — CFG-gated detectors

**File:** [depos/analysis/detectors/builtin/group_b_cfg_detectors.py](../depos/analysis/detectors/builtin/group_b_cfg_detectors.py)

All have `semantic_requirement="cfg"`. They run regex patterns over source text for scopes where a control flow graph is available. Two detectors (`infinite-loop`, `null-dereference-approx`) reuse named pattern rules from the registry.

| Detector | Detection method | Pattern / Rule | Confidence |
|---|---|---|---|
| `infinite-loop` | Pattern rule via `PatternSourceCache` + `run_pattern_rule` | `INFINITE_LOOP` rule: `while\s*\(\s*true\s*\)` or `while True:` | 0.80 |
| `unreachable-branch` | Regex on source text | `RE_UNREACH`: `if(false)`, `if(0)`, `if False:` | 0.72 |
| `off-by-one-approx` | Regex on source text | `RE_OFFBY`: `<=.length`, `len()-1` | 0.65 |
| `null-dereference-approx` | Pattern rule | `TS_NON_NULL_ASSERTION` rule: TypeScript `!.` non-null operator | 0.75 |
| `unhandled-exception-path` | Regex on source text | `RE_EMPTY_CATCH`: empty `catch` blocks | 0.68 |
| `logic-inversion-approx` | Regex on source text | `RE_DBL_NEG`: double negation `if(!!` | 0.55 |

All candidates are tagged `scope_id=f"cfg:{detector_name}:{scope}"` and `requires_cfg=True`.

---

## Group C — DFG/taint-gated detectors

**File:** [depos/analysis/detectors/builtin/group_c_taint_dfg_detectors.py](../depos/analysis/detectors/builtin/group_c_taint_dfg_detectors.py)

Operate on `TaintEdge` records stored in `graph.graph["taint_edges"]` and on DFG edges in the graph. Each detector checks taint/DFG availability before running. Candidates are tagged `scope_id=f"sem:{detector_name}:{scope}"`.

**Regex patterns defined at module top:**

```python
RE_SQL     = re.compile(r"execute\(|raw\(|`select\s|INSERT\s+INTO", re.I)
RE_CMD     = re.compile(r"os\.system|subprocess|child_process|exec\(", re.I)
RE_SUDO    = re.compile(r"\bsudo\b|setuid|seteuid|chmod\s+4755", re.I)
RE_UAF     = re.compile(r"free\s*\(|delete\s+\w+[\s;]", re.M)
RE_OVERFLOW = re.compile(r"<<\s*\d+|0x[0-9a-f]+\s*\*\s*|Math\.imul", re.I)
RE_AW_RACE = re.compile(r"async\s+function|async\s*\(", re.M)
RE_AW_MUT  = re.compile(r"\+=|-=|\+\+|--|\.push\(", re.M)
```

| Detector | Mechanism | Matched against | Confidence |
|---|---|---|---|
| `sql-injection-approx` | Taint edges → `RE_SQL` on `sink_pattern + source_chain` | `execute(`, `raw(`, `INSERT INTO` | 0.90 |
| `command-injection-approx` | Taint edges → `RE_CMD` on sink | `os.system`, `subprocess`, `exec(` | 0.92 |
| `uninit-variable-approx` | DFG edges: use before def | DFG edge `kind` inspection | 0.72 |
| `auth-bypass-approx` | Middleware/auth source file + static source pattern | `if(true) return` in middleware | 0.80 |
| `privilege-escalation-approx` | Taint edges → `RE_SUDO` on sink | `sudo`, `setuid`, `chmod 4755` | 0.92 |
| `use-after-free-approx` | DFG edges + `RE_UAF` on source | `free(`, `delete ` | 0.78 |
| `integer-overflow-approx` | DFG edges + `RE_OVERFLOW` on source | `<<N`, `0xN *`, `Math.imul` | 0.68 |
| `race-condition-approx` | `AWAIT_SUSPENSION` DFG edges + `RE_AW_RACE` + `RE_AW_MUT` | async functions with shared mutations | 0.72 |

Candidates are tagged `scope_id=f"sem:{detector_name}:{scope}"` using each detector's registered name (for example `command-injection-approx`). Verifier and output layers resolve findings using that same detector id.

---

## Domain-specific detectors

Individual files under [depos/analysis/detectors/builtin/](../depos/analysis/detectors/builtin/). Each exports a `SPEC` and a `run()` function and is registered at import time.

### Seed detectors

Always enabled; emit candidates that seed the investigation before domain detectors run.

| Detector | File | What it emits |
|---|---|---|
| `diff-anchor` | `diff_anchor.py` | Candidates anchored to changed files in the git diff |
| `interface-surface` | `interface_surface.py` | Public API surface nodes (routes, exported functions) |
| `graph-anomaly` | `graph_anomaly.py` | Structural anomalies from graph metrics |
| `lexical-keyword-seed` | `lexical_keyword_seed.py` | Word-boundary hits on ``IntelligenceConfig.lexical_seed_keywords`` in labels, embedded text, and paths (budget: ``CandidateBudget.max_lexical_seeds``). Enable via ``enable_lexical_seeds`` (``enable_ai_driven_seeds`` is a deprecated alias). Optional ``enable_embedding_seeds`` extends with :mod:`depos.analysis.embedding_seed`. |

### Dependencies — `Universe.deps`

| Detector | File | Logic |
|---|---|---|
| `vulnerable-dep` | `vulnerable_dep.py` | Iterates `lockfile_resolution` nodes; flags any with `advisory_ids` or `vulnerable=True`; emits `oracle_hints` for advisory DB lookup |
| `lockfile-drift` | `lockfile_drift.py` | Detects divergence between declared and resolved versions |
| `dep-version-mismatch-across-workspaces` | `dep_version_mismatch_across_workspaces.py` | Cross-workspace version conflicts in monorepos |
| `phantom-dep` | `phantom_dep.py` | Imported packages not declared in any manifest (synthetic `package_dep` nodes with `declared=False`) |
| `unused-dep` | `unused_dep.py` | Declared packages with no import edges in the graph |
| `peer-dep-unsatisfied` | `peer_dep_unsatisfied.py` | Peer dependency ranges not satisfied by installed versions |
| `transitive-pin-conflict` | `transitive_pin_conflict.py` | Incompatible transitive version pins |

### Env and config — `Universe.env`

| Detector | File | Logic |
|---|---|---|
| `env-var-referenced-but-undefined` | `env_var_referenced_but_undefined.py` | Uses `ENV_VAR_REFERENCED_BUT_UNDEFINED` pattern rule from `pattern_registry.py`; skips test fixture scopes |
| `env-var-defined-but-unused` | — | Env vars declared but never referenced in code graph |
| `env-var-typed-drift` | — | Runtime type of env var contradicts declared type annotation |
| `cors-origin-omits-known-client-origin` | — | Known client origin not in CORS allowlist |
| `next-route-protected-in-middleware-but-not-layout` | — | Auth check in middleware not reflected in Next.js layout |
| `redirect-target-not-safelisted` | — | Redirect URL not in safelisted origins |

### Auth and authorization — `Universe.code`

| Detector | File | Logic |
|---|---|---|
| `route-without-session-check` | `route_without_session_check.py` | Iterates `next_route` nodes; flags routes without `NEXT_ROUTE_GUARDED_BY_MIDDLEWARE` edge or `session_checked` attribute; skips routes with `public=True` |
| `rpc-invoked-without-rls-or-service-role` | — | RPC call graph edge without RLS policy or service-role context |
| `password-reset-link-handler-redirects-to-external-origin` | — | Password reset handler redirects to an unverified external URL |
| `cookie-set-without-httponly-or-secure-in-prod` | — | `Set-Cookie` without `HttpOnly` or `Secure` flags in production paths |

### Schema and contract

| Detector | File | Logic |
|---|---|---|
| `request-body-missing-required-field` | — | OpenAPI required field absent from observed request body shape |
| `response-field-consumed-but-not-produced` | — | Field read by consumer not in producer's OpenAPI response schema |
| `enum-value-used-but-not-in-schema` | — | Enum value used in code not declared in the schema |
| `migration-adds-not-null-without-default` | — | DB migration adds a `NOT NULL` column with no default (breaks existing rows) |

### Prompt and template

| Detector | File | Logic |
|---|---|---|
| `prompt-missing-required-field` | — | Required template variable absent from prompt schema |
| `prompt-field-type-mismatch` | — | Variable type in code call does not match prompt schema declaration |
| `prompt-references-undefined-variable` | — | Template variable has no binding in the calling context |
| `prompt-drift-between-provider-versions` | — | Prompt schema changed incompatibly between provider versions |

### Build and infra

| Detector | File | Logic |
|---|---|---|
| `dockerfile-copies-path-not-in-build-context` | — | `COPY` instruction references a path outside the Docker build context |
| `gha-workflow-uses-secret-not-declared` | — | `secrets.*` reference in a workflow not declared in the `secrets:` block |
| `gha-matrix-node-version-diverges-from-engines` | — | Matrix `node-version` does not match `engines.node` in `package.json` |
| `compose-service-depends-on-service-with-different-network` | — | `depends_on` service is on a different Docker Compose network |

---

## Pattern system

The pattern system provides reusable, declarative detection rules on top of the raw detector API. It is not Semgrep-compatible and does not produce findings directly — pattern matches become normal `Candidate` objects inside the detector pipeline.

### `pattern_types.py` — [link](../depos/analysis/detectors/pattern_types.py)

Core data models (all Pydantic with `extra="allow"`):

- `PatternRule` — rule declaration: `id`, `detector_name`, `risk_category`, `severity`, `scope`, `semantic_requirement`, `message`, `formula` (dict).
- `PatternScope` — a node in the graph eligible for pattern evaluation: `scope_id`, `scope_type`, `file_path`, `node_id`, line range, `language`.
- `PatternMatch` — result: `rule_id`, `detector_name`, `scope`, `matched_text`, `metavars`, `node_ids`, `edge_ids`, `evidence` list, `confidence`.
- `PatternEvidence` — a single evidence item: `kind`, `message`, `node_id`, `edge_id`, `file_path`, line range, `data`.
- `PatternScopeType` — literal union of 12 scope types: `file`, `function`, `class`, `route`, `migration`, `prompt`, `env_var`, `config`, `node`, etc.

### `pattern_registry.py` — [link](../depos/analysis/detectors/pattern_registry.py)

Global `_RULES` dict. Three built-in rules registered at import time:

| Rule constant | `id` | Pattern | Semantic requirement | Used by |
|---|---|---|---|---|
| `INFINITE_LOOP` | `infinite-loop-source` | `while(true)` or `while True:` (case-insensitive) | `cfg` | `group_b_cfg_detectors.py` |
| `TS_NON_NULL_ASSERTION` | `null-dereference-approx` | TypeScript `!.` non-null assertion | `cfg` | `group_b_cfg_detectors.py` |
| `ENV_VAR_REFERENCED_BUT_UNDEFINED` | `env-var-referenced-but-undefined` | `all_of` formula on env var graph | None | `env_var_referenced_but_undefined.py` |

`register_pattern_rule(rule)` adds to `_RULES`; `get_pattern_rule(id)` retrieves.

### `pattern_matcher.py` — [link](../depos/analysis/detectors/pattern_matcher.py)

Evaluates pattern rules against the graph. Key pieces:

- `PatternSourceCache` — bounded LRU cache for reading source files; supports repo-root-relative and absolute paths.
- `collect_pattern_scopes(graph, rule)` — walks graph nodes and returns rule-eligible `PatternScope` objects filtered by `scope_type`.
- `evaluate_primitive(primitive_type, formula, scope, graph, cache)` — dispatcher for primitive evaluators:
  - `source_regex` — compiles regex, searches source text, returns matches with line ranges.
  - `node_kind` / `node_attr` — match node attributes.
  - `edge_exists` — check edges with `relation`, `direction`, and `kind` filters.
  - `label_regex` — regex over `label`, `name`, `call_name`, `import_name`, `route_pattern`.
  - `env_var` — match env var nodes by `name_regex` and `defined` flag.
- `run_pattern_rule(rule, graph, cache)` → `list[PatternMatch]`.
- `pattern_match_to_candidate(match, mode, config)` → `Candidate`.

### `pattern_formula.py` — [link](../depos/analysis/detectors/pattern_formula.py)

Scope-keyed boolean logic for combining primitives. Returns `dict[scope_id, PatternMatch]`.

| Operator | Behavior |
|---|---|
| `all_of` | AND — all children must match the same scope |
| `any_of` | OR — at least one child must match |
| `not` | Negation — scope must not match the inner formula |
| `requires_edge` | Graph edge must exist between matched nodes |
| `requires_node` | A node of the given kind must exist |

`merge_matches()` combines child matches for the same scope (unions `node_ids`/`edge_ids`, averages `confidence`).

### `dsl.py` — [link](../depos/analysis/detectors/dsl.py)

Safe expression evaluator for inline detector logic. Uses `ast.parse(expression, mode="eval")` with a `_SafetyVisitor` that:

- Allows: `BoolOp`, `UnaryOp`, `Compare`, `Call`, `Name`, `Constant`, `List`, `Tuple`, `Dict`.
- Blocks: comprehensions, slicing, `__import__`, dunder names, dunder attributes.
- Only permits calls to whitelisted helpers from `dsl_helpers.py` (`attr`, `regex`, `has_edge`, `count`, `version_satisfies`, `cross_universe`, `schema_validate`).

`evaluate(expression, **context)` executes with `globals={}` and `locals=HELPERS | context`.

---

## Adding a detector

1. Pick the universe (`Universe.code`, `.deps`, `.env`, etc.) and what semantic layer you need (`None`, `"cfg"`, `"dfg"`, `"taint"`).
2. Add ingest/resolver support if the required nodes or edges don't exist yet (`depos/ingest/`, `depos/enrichment/`).
3. Create `depos/analysis/detectors/builtin/<name>.py`.
4. Define `SPEC = simple_spec(name=..., universe=..., verifier_checks=[...], semantic_requirement=..., severity=...)`.
5. Define `run(graph, manifest, mode, config, ctx) -> list[Candidate]` and call `register(SPEC, run)` at module bottom.
6. Emit candidates via `make_candidate(scope_id=..., seed_type=..., detector_confidence=..., extra={...})` from `builtin/common.py`.
7. Add positive, negative, and verifier coverage under `tests/detectors/`.
8. Regenerate the registry snapshot: `python scripts/snapshot_detector_registry.py`.

The module is auto-imported by `load_builtin()` — no manual registry entry needed beyond the `register()` call.
