# depOS detector platform

The detector platform is the depOS Module 2 intelligence path. It turns candidate generation into a registry of many small detectors instead of one fixed generator.

## Layers

| Layer | Path | Role |
|---|---|---|
| 0 — ingest | `depos/ingest/` | Extends the graph with dep, env/config, prompt, OpenAPI, Next.js, and infra nodes |
| 1 — enrichment | `depos/enrichment/*_resolver.py` | Stitches universes back to code through semantic probes; records structured probe errors |
| 2 — detectors | `depos/analysis/detectors/` | Emits candidates with detector metadata and deterministic replay envelopes |
| 3 — reasoning | optional | Mechanical detectors skip LLM entirely; only `requires_reasoner=True` detectors use it |
| 4 — verifier | `depos/analysis/verifier.py` | Trust boundary: oracle, negation, cross-universe, and version checks |
| 5 — store | `depos/output/` | Findings, detector stats, ingest reports, observability rows |

## Detector contract

Each detector module exports:

```python
SPEC = simple_spec(name="...", universe=..., verifier_checks=[...], semantic_requirement=..., severity="...")
run(graph, manifest, mode, config, ctx) -> list[Candidate]
register(SPEC, run)  # called at module bottom
```

The `DetectorPayload` envelope written by `_wrap_candidate()` in `detectors/__init__.py` includes `detector_name`, `detector_version`, `pipeline_version`, `severity`, and `oracle_hints` — enough for the verifier and persistence layer to replay the exact decision path.

## Cross-universe node kinds

Defined in `depos/analysis/schemas.py`:

- **deps:** `package_manifest`, `package_dep`, `lockfile_resolution`
- **env:** `env_var`, `config_key`
- **prompt:** `prompt_template`
- **schema:** `openapi_operation`, `openapi_schema`
- **nextjs:** `next_route`, `next_middleware`
- **infra:** `infra_workflow`, `infra_service`, `dockerfile_stage`

## Operational notes

- **GraphCodeBERT** is an opt-in pre-ranker (`config.ranker.use_graphcodebert`); defaults to off.
- Node-link graph JSON is normalized through `graphify/nx_compat.py` so both legacy `links` and newer `edges` payloads keep working.
- The gray-zone evaluator can only surface `evaluator_surfaced`; it never upgrades to `confirmed`.

See [detectors.md](detectors.md) for the full per-detector reference, group descriptions, pattern system internals, and how to add a detector.
