# depOS — product

## One-line concept

depOS builds **live, diagnostics-aware dependency graphs** across branches and allowlisted repositories, runs **blast-radius** analysis in CI, and exports **structured context** (including erroneous nodes and edges) so AI coding tools can act with immediate, accurate situational awareness.

## Positioning

- Not “only a dependency diagram.” The value is **architecture intelligence**: what a change affects, where defects cluster, who owns impacted paths, and how risk propagates **before and after CI**.
- Complements (does not replace) source hosts, CI, catalogs, and observability by sitting in the **change-risk** layer.

## MVP themes (working)

1. **CI-first** — Primary delivery through GitHub Actions (Checks, artifacts).
2. **Blast radius** — Structural impact plus **defect-aware** ranking using analyzer output (SARIF and ecosystem formats).
3. **Org scope** — Federated view across **allowed** repos only; admins control inclusion.
4. **Cross-branch** — Compare head vs default (and optional long-lived branches) for drift and merge risk signals.
5. **LLM export** — Graph JSON and MCP-style access with **error categories** on nodes and fault marks on edges for Claude Code and similar tools.

## Product intelligence artifacts

CLI analysis now emits additive product-facing artifacts when
`DEPOS_PRODUCT_OUTPUTS_ENABLED` is unset or set to `true`:

- `findings.json` - stable `ProductFinding` records for UI/API triage.
- `impact_paths.json` - graph-backed affected paths per finding.
- `triage_backlog.json` - review queues for unreasoned, gray-zone, suppressed,
  and low-evidence work.
- `mcp_context.json` - capped and redacted context for AI coding tools.
- `product_summary.json` - aggregate product counts plus a product-level CI
  decision.

These files are separate from `violations.json`. The legacy CI gate keeps using
the canonical verifier outcome contract, while product outputs can be more
nuanced: low graph reliability or low impact confidence maps to
`request_review` instead of silently changing the underlying finding.

## Out of scope for early releases

Replacing CI, full observability stacks, universal language coverage on day one, or autonomous code rewriting.

## Naming

**depOS** is a working product name; marketing name may change.
