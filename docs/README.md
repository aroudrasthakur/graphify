# depOS documentation

**depOS** is the working name for the Dependency Map OS application: CI-centric dependency intelligence, cross-branch and cross-repository blast radius, diagnostics fused into graphs for AI tools, and a product UI on top.

## Contents

1. **[Product](product.md)** — Problem, positioning, MVP goals, and product intelligence artifacts.
2. **[Architecture](architecture.md)** — High-level components, layered pipeline, and how diagnostics attach to graphs.
3. **[Pipeline target spec](depos-pipeline.md)** — The 11-stage depOS target-state pipeline spec.
4. **[Pipeline current state](depos-pipeline-current-state.md)** — Canonical redline of what the repo actually implements today, stage by stage.
5. **[Detector platform](detector-platform.md)** — Platform layers, detector contract, and cross-universe node kinds.
6. **[Detectors](detectors.md)** — Full per-detector reference: Groups A/B/C, domain-specific detectors, pattern system, and how to add a detector.
7. **[Graphify internals](graphify-internals.md)** — The vendored `graphify/` Python package: pipeline, modules, and extending extraction.
8. **[Development](development.md)** — Local setup, tests, and packaging notes.
9. **[Dataset pipeline](dataset-pipeline.md)** — Running the raw AST dataset through normalization and the canonical Stage 1–11 pipeline.
10. **[Performance acceleration](perf-acceleration.md)** — Phase 5–10 cache, parallelism, graph indexes, and CFG/DFG/taint compute.
11. **[CI / OIDC trust](ci-oidc.md)** — How GitHub Actions authenticates to the depOS API and how to wire the CI gate.

## Runbooks

- [Reasoner zero findings](runbooks/reasoner-zero-findings.md) — 30-second triage for "0 findings" runs.
- [Reasoner performance](runbooks/reasoner-performance.md) — Performance optimization for reasoner calls.

## Relationship to graphify

This repo contains the **graphify** library as the engine for parsing code into nodes and edges. depOS documentation describes the **product and intelligence platform**; graphify internals describe the **library** used inside that product.
