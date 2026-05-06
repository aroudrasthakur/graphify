# Runbook: local API / web viewer and CLI bundles

## CLI-first workflow

1. Run `depos analyze repo` or `depos analyze diff` (see [`local-cli-v1.md`](local-cli-v1.md)).
2. Note the output directory from the JSON summary’s `output_dir`.

## Importing a bundle into the API

When the **API process can read the same filesystem** as the CLI (typical local operator setup), an org **admin** can persist the run:

```http
POST /v1/orgs/{slug}/intelligence/runs/import-local-bundle
Authorization: Bearer <supabase-jwt>
Content-Type: application/json

{
  "bundle_directory": "/absolute/path/to/$DEPOS_DATA/intelligence/<run_id>",
  "repo_slug": "my-service",
  "verify_manifest_checksums": true
}
```

Responses: `{ "run_id": "...", "findings": N, "bundle_directory": "..." }` plus optional **`gate_result`** (full `gate_result.json` when present) and **`run_manifest_summary`** (schema version and artifact count from `run_manifest.json`).

- Set `verify_manifest_checksums` to `false` only if `run_manifest.json` is missing or you are debugging.
- Malformed manifests or checksum mismatches return **400** with a short error.

Implementation: `depos/intelligence_bundle_import.py`, route in `depos/api_server.py`.

## Web dashboard

The Next.js app under `apps/web` can list runs via existing Supabase-backed queries once they are persisted. Wire org/repo navigation to the imported `run_id` as needed for your deployment—no second analysis path should re-run detectors for the same bundle.

## Authorization

- Import requires **admin or owner** on the org (same as `POST .../intelligence/runs`).
- Non-members receive **403**.
