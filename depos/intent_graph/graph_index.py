"""Index graphify NetworkX graph by normalized source path and line ranges."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import networkx as nx

_LINE_RE = re.compile(r"^L(\d+)\s*$")


def parse_source_location(loc: str | None) -> int | None:
    if not loc:
        return None
    m = _LINE_RE.match(str(loc).strip())
    if not m:
        return None
    return int(m.group(1))


def normalize_repo_path(p: str | Path, repo_root: Path) -> str:
    path = Path(p)
    try:
        rr = repo_root.resolve()
        if path.is_absolute():
            rp = path.resolve()
        else:
            rp = (repo_root / path).resolve()
        try:
            return rp.relative_to(rr).as_posix()
        except ValueError:
            return rp.as_posix()
    except (OSError, ValueError):
        return path.as_posix()


def normalize_key_any(p: str | Path, repo_root: Path) -> str:
    """Stable key for matching intent relpaths to graph source_file strings."""
    path = Path(p)
    if path.is_absolute():
        try:
            return normalize_repo_path(path, repo_root)
        except Exception:
            return path.as_posix()
    return Path(p).as_posix()


class GraphPathIndex:
    """Maps normalized relative paths to nodes and line numbers."""

    def __init__(self, G: nx.Graph | nx.DiGraph, repo_root: Path):
        self.repo_root = repo_root.resolve()
        self._files: set[str] = set()
        self._nodes_by_file: dict[str, list[tuple[str, int | None]]] = {}
        for nid, attrs in G.nodes(data=True):
            sf = attrs.get("source_file")
            if not sf:
                continue
            nk = normalize_key_any(str(sf), self.repo_root)
            self._files.add(nk)
            line = parse_source_location(attrs.get("source_location"))
            self._nodes_by_file.setdefault(nk, []).append((nid, line))
        for plist in self._nodes_by_file.values():
            plist.sort(key=lambda x: (x[1] is None, x[1] or 0))

    def has_file(self, relpath: str) -> bool:
        nk = normalize_key_any(relpath, self.repo_root)
        return nk in self._files

    def files_set(self) -> set[str]:
        return set(self._files)

    def nodes_for_file(self, relpath: str) -> list[tuple[str, int | None]]:
        nk = normalize_key_any(relpath, self.repo_root)
        return list(self._nodes_by_file.get(nk, []))

    def best_node_for_line(self, relpath: str, line: int | None) -> tuple[str | None, int | None]:
        """Largest node line <= ``line`` in same file; if line is None pick first scoped node."""
        nodes = self.nodes_for_file(relpath)
        if not nodes:
            return None, None
        if line is None:
            return nodes[0][0], nodes[0][1]
        best: tuple[str, int | None] | None = None
        best_ln = -1
        for nid, ln in nodes:
            if ln is None:
                continue
            if ln <= line and ln >= best_ln:
                best = (nid, ln)
                best_ln = ln
        if best:
            return best[0], best[1]
        return nodes[0][0], nodes[0][1]


def orphan_candidates(
    G: nx.Graph | nx.DiGraph,
    referenced_paths: set[str],
    repo_root: Path,
    *,
    top_n: int = 20,
) -> list[tuple[str, str, int, str]]:
    """Return (node_id, norm_path, in_degree, label) for high in-degree nodes not referenced."""
    if G.is_directed():
        deg: dict[str, int] = dict(G.in_degree())
    else:
        deg = dict(G.degree())
    indexed = GraphPathIndex(G, repo_root)
    rows: list[tuple[str, str, int, str]] = []
    for nid, attrs in G.nodes(data=True):
        sf = attrs.get("source_file")
        if not sf:
            continue
        nk = normalize_key_any(str(sf), repo_root)
        if nk in referenced_paths:
            continue
        label = str(attrs.get("label") or "")
        rows.append((nid, nk, int(deg.get(nid, 0)), label))
    rows.sort(key=lambda x: -x[2])
    return rows[:top_n]
