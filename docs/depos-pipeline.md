# depOS — 11-stage pipeline (canonical spec)

This document is the in-repo source of truth for the depOS analysis pipeline.
`depos-pipeline.jsx` is the visual mirror; both must stay in sync (content-hash
lint in `tests/test_jsx_spec_sync.py`).

## Stages

1. **AST ingest** — Tree-sitter / graphify extraction into JSON.
2. **Graph construction** — `graphify.build.build_from_json` → `networkx.DiGraph`.
3. **Semantic layer (Phase 1a/1b)** — GraphMetrics, SeamEdge index, cross-language
   cycles, intra-procedural CFG, DFG, taint pre-computation; per-scope
   `cfg_available` / `dfg_available` / `taint_edges_available`.
4. **Change manifest** — CPG diff, git diff, or manual JSON.
5. **identify_candidates** — Seeds: diff_anchor, interface_surface, graph_anomaly, ai_driven.
6. **Bug detectors** — Registry in `depos/analysis/detectors/__init__.py`; Groups A/B/C.
7. **Ranking** — `CandidateScore.composite`.
8. **Bundle + LLM** — `GraphContextBundle` + BundlePrompter + reasoner.
9. **Verifier** — Typed `VerifierRule` engine + `GLOBAL_AUTO_GRAYZONE`.
10. **Gray-zone** — Structured audit; never promotes to CONFIRMED.
11. **Output** — JSON, SARIF 2.1.0, PR comments; CI gate on critical/high CONFIRMED.

## CandidateScore (vector)

Dimensions (composite is the sort key): structural centrality, seam exposure,
change proximity, detector confidence, evidence quality — weights from config
per analysis mode.

## Detector inventory

- **Group A (graph-only):** seams, cycles, articulation, orphans, dead code,
  centrality, lockfile drift, env exposure, etc.
- **Group B (CFG-gated):** null deref, unreachable branch, logic inversion,
  off-by-one, infinite loop, unhandled exception path.
- **Group C (DFG/taint-gated):** uninit, race approx, auth bypass, injection
  classes, privilege, UAF, overflow.

## Positioning vs CodeRabbit

depOS is **graph-native**: evidence is grounded in the enriched graph, seam
contracts, and pre-computed semantics (CFG/DFG/taint), not file-chunk heuristics
alone.
