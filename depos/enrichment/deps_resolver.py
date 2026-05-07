"""Cross-link code imports to dependency nodes."""
from __future__ import annotations

import sys
from pathlib import Path

import networkx as nx

from depos.analysis.fragments import FragmentEdge, FragmentNode, GraphFragment, make_fragment

_NODE_BUILTIN_MODULES = frozenset(
    {
        "assert",
        "async_hooks",
        "buffer",
        "child_process",
        "cluster",
        "crypto",
        "dns",
        "events",
        "fs",
        "http",
        "http2",
        "https",
        "net",
        "os",
        "path",
        "perf_hooks",
        "process",
        "querystring",
        "readline",
        "stream",
        "string_decoder",
        "timers",
        "tls",
        "url",
        "util",
        "v8",
        "zlib",
    }
)


def _stdlib_modules() -> frozenset[str]:
    names = getattr(sys, "stdlib_module_names", None)
    if names is not None:
        return frozenset(names)
    return frozenset()


_STDLIB_MODULES: frozenset[str] = _stdlib_modules()


def _import_names(attrs: dict) -> set[str]:
    names: set[str] = set()
    for key in ("import_name", "module_name", "package_name"):
        value = attrs.get(key)
        if isinstance(value, str) and value.strip():
            names.add(value.split(".")[0])
    label = str(attrs.get("label") or "")
    if label.startswith("import "):
        target = label.replace("import ", "", 1).split()[0].split(".")[0]
        if target:
            names.add(target)
    return names


def _phantom_package_id(package_name: str) -> str:
    return f"pkg::phantom:{package_name}"


def _guess_ecosystem(importer_attrs: dict) -> str:
    sf = str(importer_attrs.get("source_file") or "").lower()
    if sf.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")):
        return "npm"
    if sf.endswith(".py"):
        return "python"
    if "cargo.toml" in sf or sf.endswith(".rs"):
        return "cargo"
    return "generic"


def _should_skip_phantom_name(name: str, importer_attrs: dict) -> bool:
    if not name or not name.strip():
        return True
    if name.startswith("."):
        return True
    sf = str(importer_attrs.get("source_file") or "").lower()
    if sf.endswith(".py"):
        return name in _STDLIB_MODULES
    if sf.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")):
        return name in _NODE_BUILTIN_MODULES
    return False


def emit_dependency_edges(graph: nx.DiGraph, *, repo_root: Path | None = None) -> GraphFragment:
    _ = repo_root
    dep_index: dict[str, list[tuple[str, dict]]] = {}
    for node_id, attrs in graph.nodes(data=True):
        if str(attrs.get("node_kind") or "") not in {"package_dep", "lockfile_resolution"}:
            continue
        name = str(attrs.get("package_name") or attrs.get("name") or "").split(".")[0]
        if name:
            dep_index.setdefault(name, []).append((node_id, attrs))

    nodes: list[FragmentNode] = []
    edges: list[FragmentEdge] = []
    seen_edges: set[tuple[str, str]] = set()
    phantom_attrs_by_id: dict[str, dict] = {}

    for node_id, attrs in graph.nodes(data=True):
        if str(attrs.get("node_kind") or "") in {"package_dep", "lockfile_resolution", "package_manifest"}:
            continue
        if not attrs.get("source_file"):
            continue
        for name in _import_names(attrs):
            targets = dep_index.get(name, [])
            if targets:
                for target_id, target_attrs in targets:
                    pair = (node_id, target_id)
                    if pair in seen_edges:
                        continue
                    seen_edges.add(pair)
                    edges.append(
                        FragmentEdge(
                            u=node_id,
                            v=target_id,
                            key=None,
                            attrs={
                                "relation": "IMPORTS_PACKAGE",
                                "source_system": "code",
                                "target_system": "deps",
                                "confidence": 1.0,
                                "inferred": False,
                                "drift_kind": "lockfile_drift" if target_attrs.get("lockfile_drift") else "",
                            },
                        )
                    )
                continue

            if _should_skip_phantom_name(name, attrs):
                continue

            phantom_id = _phantom_package_id(name)
            if phantom_id not in phantom_attrs_by_id:
                phantom_attrs_by_id[phantom_id] = {
                    "node_kind": "package_dep",
                    "universe": "deps",
                    "package_name": name,
                    "name": name,
                    "label": name,
                    "declared": False,
                    "declared_range": "",
                    "resolved_version": "",
                    "dep_type": "phantom",
                    "lockfile_match": False,
                    "lockfile_drift": False,
                    "peer_unsatisfied": False,
                    "source_system": "import_resolver",
                    "ecosystem": _guess_ecosystem(attrs),
                }
            pair = (node_id, phantom_id)
            if pair in seen_edges:
                continue
            seen_edges.add(pair)
            edges.append(
                FragmentEdge(
                    u=node_id,
                    v=phantom_id,
                    key=None,
                    attrs={
                        "relation": "IMPORTS_PACKAGE",
                        "source_system": "code",
                        "target_system": "deps",
                        "confidence": 0.75,
                        "inferred": True,
                        "drift_kind": "",
                    },
                )
            )

    for phantom_id, p_attrs in sorted(phantom_attrs_by_id.items(), key=lambda kv: kv[0]):
        nodes.append(FragmentNode(phantom_id, p_attrs))

    return make_fragment("enrich_deps", nodes=nodes, edges=edges)


__all__ = ["emit_dependency_edges"]
