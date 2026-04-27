"""Phase 4 extraction adapter for depOS pipeline acceleration.

The graphify extractor has a clean per-file structural pass followed by serial
cross-file resolution. This adapter keeps that boundary explicit: workers only
run file-local extractors, and the main process performs the global merge and
cross-file edge resolution in deterministic input order.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Iterable, Sequence

import networkx as nx

from graphify.build import build_from_json
from graphify.cache import load_cached, save_cached
from graphify.detect import detect
import graphify.extract as graphify_extract

logger = logging.getLogger(__name__)


_DISPATCH: dict[str, Any] = {
    ".py": graphify_extract.extract_python,
    ".js": graphify_extract.extract_js,
    ".jsx": graphify_extract.extract_js,
    ".mjs": graphify_extract.extract_js,
    ".ts": graphify_extract.extract_js,
    ".tsx": graphify_extract.extract_js,
    ".go": graphify_extract.extract_go,
    ".rs": graphify_extract.extract_rust,
    ".java": graphify_extract.extract_java,
    ".c": graphify_extract.extract_c,
    ".h": graphify_extract.extract_c,
    ".cpp": graphify_extract.extract_cpp,
    ".cc": graphify_extract.extract_cpp,
    ".cxx": graphify_extract.extract_cpp,
    ".hpp": graphify_extract.extract_cpp,
    ".rb": graphify_extract.extract_ruby,
    ".cs": graphify_extract.extract_csharp,
    ".kt": graphify_extract.extract_kotlin,
    ".kts": graphify_extract.extract_kotlin,
    ".scala": graphify_extract.extract_scala,
    ".php": graphify_extract.extract_php,
    ".swift": graphify_extract.extract_swift,
    ".lua": graphify_extract.extract_lua,
    ".toc": graphify_extract.extract_lua,
    ".zig": graphify_extract.extract_zig,
    ".ps1": graphify_extract.extract_powershell,
    ".ex": graphify_extract.extract_elixir,
    ".exs": graphify_extract.extract_elixir,
    ".m": graphify_extract.extract_objc,
    ".mm": graphify_extract.extract_objc,
    ".jl": graphify_extract.extract_julia,
    ".vue": graphify_extract.extract_js,
    ".svelte": graphify_extract.extract_js,
    ".dart": graphify_extract.extract_dart,
    ".v": graphify_extract.extract_verilog,
    ".sv": graphify_extract.extract_verilog,
}


def _extractor_for(path: Path):
    if path.name.endswith(".blade.php"):
        return graphify_extract.extract_blade
    return _DISPATCH.get(path.suffix)


def _infer_cache_root(paths: Sequence[Path]) -> Path:
    try:
        if not paths:
            return Path(".")
        if len(paths) == 1:
            return paths[0].parent
        common_len = sum(
            1
            for i in range(min(len(p.parts) for p in paths))
            if len({p.parts[i] for p in paths}) == 1
        )
        return Path(*paths[0].parts[:common_len]) if common_len else Path(".")
    except Exception:
        return Path(".")


def _extract_one(path_str: str, cache_root_str: str, use_cache: bool) -> dict:
    path = Path(path_str)
    cache_root = Path(cache_root_str)
    extractor = _extractor_for(path)
    if extractor is None:
        return {"nodes": [], "edges": []}
    if use_cache:
        cached = load_cached(path, cache_root)
        if cached is not None:
            return cached
    result = extractor(path)
    if use_cache and "error" not in result:
        save_cached(path, result, cache_root)
    return result


def _run_file_pass(
    paths: Sequence[Path],
    *,
    n_jobs: int,
    cache_root: Path,
    cache: bool,
) -> list[dict]:
    if n_jobs < 1:
        raise ValueError("n_jobs must be >= 1")
    work = [(str(path), str(cache_root), cache) for path in paths]
    if n_jobs == 1 or len(work) <= 1:
        return [_extract_one(*item) for item in work]

    try:
        from joblib import Parallel, delayed
    except ImportError as exc:
        raise RuntimeError(
            "joblib is required for parallel extraction. Install graphifyy[perf] "
            "or set n_jobs=1."
        ) from exc

    return Parallel(n_jobs=n_jobs, backend="loky")(
        delayed(_extract_one)(path_str, cache_root_str, use_cache)
        for path_str, cache_root_str, use_cache in work
    )


def _combine_file_results(per_file: Sequence[dict], paths: Sequence[Path]) -> dict:
    all_nodes: list[dict] = []
    all_edges: list[dict] = []
    for result in per_file:
        all_nodes.extend(result.get("nodes", []))
        all_edges.extend(result.get("edges", []))

    py_paths = [path for path in paths if path.suffix == ".py"]
    if py_paths:
        py_results = [result for result, path in zip(per_file, paths) if path.suffix == ".py"]
        try:
            all_edges.extend(graphify_extract._resolve_cross_file_imports(py_results, py_paths))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Cross-file import resolution failed, skipping: %s", exc)

    global_label_to_nid: dict[str, str] = {}
    for node in all_nodes:
        raw = node.get("label", "")
        normalised = raw.strip("()").lstrip(".")
        if normalised:
            global_label_to_nid[normalised.lower()] = node["id"]

    existing_pairs = {(edge["source"], edge["target"]) for edge in all_edges}
    for result in per_file:
        for raw_call in result.get("raw_calls", []):
            callee = raw_call.get("callee", "")
            if not callee:
                continue
            target = global_label_to_nid.get(callee.lower())
            caller = raw_call["caller_nid"]
            if target and target != caller and (caller, target) not in existing_pairs:
                existing_pairs.add((caller, target))
                all_edges.append(
                    {
                        "source": caller,
                        "target": target,
                        "relation": "calls",
                        "confidence": "INFERRED",
                        "confidence_score": 0.8,
                        "source_file": raw_call.get("source_file", ""),
                        "source_location": raw_call.get("source_location"),
                        "weight": 1.0,
                    }
                )

    return {
        "nodes": all_nodes,
        "edges": all_edges,
        "input_tokens": 0,
        "output_tokens": 0,
    }


def extract_paths_parallel(
    paths: Iterable[Path],
    *,
    n_jobs: int = 1,
    cache: bool = True,
    cache_root: Path | None = None,
) -> dict:
    """Extract graphify-compatible JSON from explicit paths.

    ``n_jobs=1`` is the conservative default and should be structurally
    equivalent to ``graphify.extract.extract(paths)``.
    """
    ordered = [Path(path) for path in paths if _extractor_for(Path(path)) is not None]
    graphify_extract._check_tree_sitter_version()
    resolved_cache_root = cache_root if cache_root is not None else _infer_cache_root(ordered)
    per_file = _run_file_pass(
        ordered,
        n_jobs=n_jobs,
        cache_root=resolved_cache_root,
        cache=cache,
    )
    return _combine_file_results(per_file, ordered)


def extract_parallel(
    root: Path,
    *,
    n_jobs: int = 1,
    cache: bool = True,
    cache_root: Path | None = None,
    directed: bool = True,
) -> nx.Graph:
    """Detect code files under *root*, extract them, and return a graph."""
    root = Path(root).resolve()
    detected = detect(root)
    paths = [Path(path) for path in detected.get("files", {}).get("code", [])]
    extraction = extract_paths_parallel(
        paths,
        n_jobs=n_jobs,
        cache=cache,
        cache_root=cache_root or root,
    )
    return build_from_json(extraction, directed=directed)


__all__ = ["extract_parallel", "extract_paths_parallel"]
