# CI: OIDC, `violations.json`, and the depOS gate

This document describes how to wire depOS outputs into continuous integration and (optionally) authenticated callbacks.

## `depos-intel gate`

After a pipeline run produces `violations.json`, fail the job when the policy is violated:

```text
depos-intel gate --violations path/to/violations.json
```

Exit codes:

- `0` — no **CONFIRMED** finding with **high** or **critical** severity (or all such findings were allowlisted).
- `1` — at least one blocking finding remains.
- `2` — the violations file was missing or invalid JSON.

Allowlist known baselines while you fix them:

```text
depos-intel gate --violations violations.json --allow-finding-id id1 --allow-finding-id id2
```

The command prints a short JSON summary to stdout (`gate`, `blocking_count`, `blocking_finding_ids`).

## GitHub Actions (no OIDC required)

Minimal job:

```yaml
- name: depOS gate
  run: python -m depos.cli gate --violations graphify-out/run/violations.json
```

Ensure the prior step wrote `violations.json` from `depos-intel analyze repo` / `diff` / `dataset-pipeline`.

## OIDC and external services

depOS itself does not require OpenID Connect for the local CLI. If you integrate with a hosted depOS **API** that issues short-lived tokens (for example to post SARIF or PR comments), configure the standard GitHub **OIDC** trust between your repository and that cloud provider following your provider’s documentation, then pass the issued token to your upload step. The structured outputs used in those flows are:

- **JSON** — `depos.output.json.render_violations_document` (canonical `status` per finding).
- **SARIF** — `depos.output.sarif.render_sarif` for the Security tab.
- **PR comments** — `depos.output.pr_comment.render_violations_pr_comment` for Markdown bodies.

Keep `violations.json` as the source of truth; render other formats from the same document so CI and the UI stay aligned.
