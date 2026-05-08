# depOS worker

Snapshot and CI jobs run the **`depos`** Python package:

- `python -c "from depos.snapshot import build_graph_for_root; ..."` for local graphs.
- `depos-api` (see `pyproject.toml`) starts the FastAPI service used by CI and the dashboard.

Heavy clone/fan-out workers can be added here as separate processes calling the same library.

## Python environment

Install the **`depos`** extra (and typically **`supabase`**) from the repo root — see [docs/development.md](../../docs/development.md) or `pip install -r requirements-dev.txt`.
