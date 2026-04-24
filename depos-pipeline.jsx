/**
 * depOS — canonical 11-stage pipeline (visual spec).
 *
 * Sandbox: from repo root, `npx --yes react-export` is not required for CI;
 * this file is plain JSX consumable by any React 18+ app. For a one-off render
 * check: `npx --yes @babel/node` with @babel/preset-react, or import in a Vite
 * scratch app.
 *
 * **Detector inventory** — `semantic_requirement`: `null` = Group A; `"cfg"` = B;
 * `"dfg"` / `"taint"` = C. Regenerated to match
 * `from depos.analysis.detectors import list_detectors; list_detectors()`.
 *
 * @see docs/depos-pipeline.md
 */
import React from "react";

const STAGES = [
  { id: 1, name: "AST ingest", note: "Tree-sitter / graphify extract" },
  { id: 2, name: "Graph construction", note: "networkx.DiGraph" },
  {
    id: 3,
    name: "Semantic layer",
    note: "GraphMetrics, SeamEdge; Python + JS/TS CFG/DFG/taint (tree-sitter)",
  },
  { id: 4, name: "Change manifest", note: "cpg / git / manual" },
  { id: 5, name: "identify_candidates", note: "seeds + dedup" },
  {
    id: 6,
    name: "Bug detectors",
    note: "Groups A / B / C; policy uses semantic_requirement (see inventory below)",
  },
  { id: 7, name: "Ranking", note: "CandidateScore.composite" },
  { id: 8, name: "Bundle + LLM", note: "GraphContextBundle + BundlePrompter + config.llm" },
  { id: 9, name: "Verifier", note: "VerifierRule engine (VERIFIER_RULES)" },
  { id: 10, name: "Gray-zone", note: "structured audit fields" },
  { id: 11, name: "Output", note: "JSON / SARIF / PR + CI gate" },
];

const SCORE_VECTOR = [
  "structural_centrality",
  "seam_exposure",
  "change_proximity",
  "detector_confidence",
  "evidence_quality",
];

const POLICY = [
  "Group A: semantic_requirement = null (always eligible).",
  'Group B: semantic_requirement = "cfg" (at least one scope with cfg_available).',
  'Group C: semantic_requirement = "dfg" or "taint" (matching layer on some scope).',
];

/** Registered builtin detectors: name, group (A|B|C), semantic_requirement. */
const DETECTOR_INVENTORY = [
  { name: "articulation-point-high-fanin", group: "A", sem: null },
  { name: "auth-bypass-approx", group: "C", sem: "dfg" },
  { name: "awaitable-returned-unawaited", group: "A", sem: null },
  { name: "command-injection-approx", group: "C", sem: "taint" },
  {
    name: "compose-service-depends-on-service-with-different-network",
    group: "A",
    sem: null,
  },
  { name: "cookie-set-without-httponly-or-secure-in-prod", group: "A", sem: null },
  { name: "cors-origin-omits-known-client-origin", group: "A", sem: null },
  { name: "cross-lang-cycle", group: "A", sem: null },
  { name: "dead-code", group: "A", sem: null },
  { name: "dep-version-mismatch-across-workspaces", group: "A", sem: null },
  { name: "diff-anchor", group: "A", sem: null },
  { name: "dockerfile-copies-path-not-in-build-context", group: "A", sem: null },
  { name: "enum-value-used-but-not-in-schema", group: "A", sem: null },
  { name: "env-var-defined-but-unused", group: "A", sem: null },
  { name: "env-var-exposed", group: "A", sem: null },
  { name: "env-var-referenced-but-undefined", group: "A", sem: null },
  { name: "env-var-typed-drift", group: "A", sem: null },
  { name: "error-swallowed-in-async-handler", group: "A", sem: null },
  { name: "gha-matrix-node-version-diverges-from-engines", group: "A", sem: null },
  { name: "gha-workflow-uses-secret-not-declared", group: "A", sem: null },
  { name: "graph-anomaly", group: "A", sem: null },
  { name: "high-centrality-isolated", group: "A", sem: null },
  { name: "infinite-loop", group: "B", sem: "cfg" },
  { name: "integer-overflow-approx", group: "C", sem: "dfg" },
  { name: "interface-surface", group: "A", sem: null },
  { name: "lexical-keyword-seed", group: "A", sem: null },
  { name: "lockfile-drift", group: "A", sem: null },
  { name: "logic-inversion-approx", group: "B", sem: "cfg" },
  { name: "migration-adds-not-null-without-default", group: "A", sem: null },
  { name: "next-route-protected-in-middleware-but-not-layout", group: "A", sem: null },
  { name: "null-dereference-approx", group: "B", sem: "cfg" },
  { name: "off-by-one-approx", group: "B", sem: "cfg" },
  { name: "orphan-surface", group: "A", sem: null },
  {
    name: "password-reset-link-handler-redirects-to-external-origin",
    group: "A",
    sem: null,
  },
  { name: "peer-dep-unsatisfied", group: "A", sem: null },
  { name: "phantom-dep", group: "A", sem: null },
  { name: "privilege-escalation-approx", group: "C", sem: "taint" },
  { name: "prompt-drift-between-provider-versions", group: "A", sem: null },
  { name: "prompt-field-type-mismatch", group: "A", sem: null },
  { name: "prompt-missing-required-field", group: "A", sem: null },
  { name: "prompt-references-undefined-variable", group: "A", sem: null },
  { name: "race-condition-approx", group: "C", sem: "dfg" },
  { name: "redirect-target-not-safelisted", group: "A", sem: null },
  { name: "request-body-missing-required-field", group: "A", sem: null },
  { name: "response-field-consumed-but-not-produced", group: "A", sem: null },
  { name: "route-without-session-check", group: "A", sem: null },
  { name: "rpc-invoked-without-rls-or-service-role", group: "A", sem: null },
  { name: "seam-contract-drift", group: "A", sem: null },
  { name: "sql-injection-approx", group: "C", sem: "taint" },
  { name: "transaction-started-but-not-committed-on-all-branches", group: "A", sem: null },
  { name: "transitive-pin-conflict", group: "A", sem: null },
  { name: "unhandled-exception-path", group: "B", sem: "cfg" },
  { name: "uninit-variable-approx", group: "C", sem: "dfg" },
  { name: "unreachable-branch", group: "B", sem: "cfg" },
  { name: "unused-dep", group: "A", sem: null },
  { name: "use-after-free-approx", group: "C", sem: "dfg" },
  { name: "vulnerable-dep", group: "A", sem: null },
];

export function DeposPipelineDiagram() {
  return (
    <section className="depos-pipeline" aria-label="depOS 11-stage pipeline">
      <header>
        <h1>depOS pipeline</h1>
        <p>
          Graph-native code intelligence: graph evidence + pre-computed
          CFG/DFG/taint, with policy-gated detector groups (semantic_requirement).
        </p>
      </header>
      <ol className="depos-pipeline-stages">
        {STAGES.map((s) => (
          <li key={s.id}>
            <strong>
              {s.id}. {s.name}
            </strong>
            <span> — {s.note}</span>
          </li>
        ))}
      </ol>
      <section>
        <h2>CandidateScore vector</h2>
        <ul>
          {SCORE_VECTOR.map((d) => (
            <li key={d}><code>{d}</code></li>
          ))}
        </ul>
        <p>Composite = weighted sum; sort key for stage 7.</p>
      </section>
      <section>
        <h2>Semantic gating (policy)</h2>
        <ul>
          {POLICY.map((p) => (
            <li key={p}>{p}</li>
          ))}
        </ul>
      </section>
      <section>
        <h2>Registered detectors</h2>
        <p>
          Group A: <code>semantic_requirement: null</code> — B: <code>&quot;cfg&quot;</code> —
          C: <code>&quot;dfg&quot;</code> or <code>&quot;taint&quot;</code>.
        </p>
        <ul className="depos-pipeline-detectors">
          {DETECTOR_INVENTORY.map((d) => (
            <li key={d.name}>
              <code>{d.name}</code> — {d.group} —{" "}
              <code>{d.sem === null ? "null" : JSON.stringify(d.sem)}</code>
            </li>
          ))}
        </ul>
      </section>
    </section>
  );
}

export default DeposPipelineDiagram;
