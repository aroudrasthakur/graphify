"""Thin read-only proxy passed to threading workers to catch accidental mutations.

Workers receive a ReadOnlyGraphView instead of the live nx.DiGraph.  Any call
to a topology-mutating method raises RuntimeError immediately so the error
surfaces in the worker thread and propagates cleanly through joblib.
"""
from __future__ import annotations


class ReadOnlyGraphView:
    """Thin wrapper around nx.DiGraph that forbids topology-mutating calls."""

    _FORBIDDEN: frozenset[str] = frozenset({
        "add_node", "add_edge", "remove_node", "remove_edge",
        "remove_nodes_from", "remove_edges_from", "update", "clear", "clear_edges",
    })

    def __init__(self, g: object) -> None:
        self._g = g

    def __getattr__(self, name: str) -> object:
        if name in self._FORBIDDEN:
            raise RuntimeError(f"mutation forbidden in parallel worker: {name}")
        return getattr(self._g, name)

    def __getitem__(self, key: object) -> object:
        return self._g[key]  # type: ignore[index]

    def __iter__(self):
        return iter(self._g)  # type: ignore[call-overload]

    def __len__(self) -> int:
        return len(self._g)  # type: ignore[arg-type]


__all__ = ["ReadOnlyGraphView"]
