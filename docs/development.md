# depOS — development

## Requirements

- **Python** 3.10+ (`requires-python` in [pyproject.toml](../pyproject.toml))
- **Node.js** — only if you work on `apps/web` (see root [README.md](../README.md))

Dependency groups are defined as **optional extras** on the `graphifyy` package. There is no separate `requirements-lock.txt`; use the repo’s [requirements-dev.txt](../requirements-dev.txt) for a common contributor install, or compose extras as below.

## Install (editable)

From the repository root, in a virtualenv:

```bash
python -m pip install -U pip

# Graphify CLI only (static extraction; no depOS)
pip install -e .

# depOS API + intelligence CLI (Pydantic, FastAPI, SQLAlchemy, httpx, diskcache for fragment cache)
pip install -e ".[depos]"

# + Supabase client (local API + dashboard against Supabase)
pip install -e ".[depos,supabase]"

# + Performance extras: joblib Wave-B parallelism, orjson/xxhash, rustworkx graph metrics,
#   pyinstrument — recommended for serious pipeline / dataset work
pip install -e ".[depos,perf]"

# + PyTorch ranker / transformers (large; only if you use intelligence embeddings / ranker paths)
pip install -e ".[depos,intelligence]"

# Everything declared in pyproject `all` (no torch)
pip install -e ".[all]"
```

**Shortcut:** `pip install -r requirements-dev.txt` installs `depos`, `supabase`, `mcp`, `perf`, and `pytest` in editable mode.

### Fragment cache

Module 1 and Module 2 use an on-disk **fragment cache** when `IntelligenceConfig.cache.enabled` (default). That cache needs **`diskcache`**, which is pulled in by the **`depos`** extra. If you see `diskcache is required for depOS cache`, upgrade to a install that includes `depos`, or pass **`--no-cache`** on `depos analyze` / `depos-intel analyze` to skip caching.

Optional: **`orjson`** and **`xxhash`** (from the **`perf`** extra) speed up cache JSON and hashing.

## Tests

```bash
python -m pytest tests/ -q
```

CI installs `pip install -e ".[depos,supabase,mcp,pdf,watch]"` plus `pytest` (see [.github/workflows/ci.yml](../.github/workflows/ci.yml)).

## Package note

The published distribution is still named **`graphifyy`** on PyPI; the graphify extraction CLI entry point is **`graphify`**. Product CLIs: **`depos`**, **`depos-intel`**, **`depos-api`** ([pyproject.toml](../pyproject.toml) `[project.scripts]`).
