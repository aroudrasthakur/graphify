# depOS pattern detectors

depOS includes a small Semgrep-inspired pattern layer for deterministic
candidate generation. It is not a Semgrep-compatible rule engine and does not
produce final findings. Pattern matches become normal depOS `Candidate` objects
inside Module 2, then the existing scoring, bundle, reasoner, verifier, and
output pipeline handles the rest.

The implementation lives under `depos/analysis/detectors/`:

- `pattern_types.py` defines reviewable rule, scope, match, and evidence models.
- `pattern_matcher.py` runs source and graph primitives.
- `pattern_formula.py` composes primitives with scope-keyed boolean logic.
- `pattern_registry.py` stores built-in v1 rules.

Version 1 supports source/graph primitives such as `source_regex`,
`node_kind`, `node_attr`, `edge_exists`, `import_name`, `call_name`,
`route_path`, and `env_var`. Formula support is intentionally small:
`all_of`, `any_of`, `not`, `requires_edge`, and `requires_node`.

Rules evaluate over depOS scopes such as functions, routes, env vars, prompts,
and config nodes. A formula returns matches keyed by `scope_id`; this avoids
full Semgrep range algebra while preserving replayable evidence for candidates.

Future work can add metavariable-lite bindings across graph relations, AST-aware
source primitives, and user/team rule loading. Those should still emit normal
Candidates through the detector registry rather than creating a separate
finding pipeline.
