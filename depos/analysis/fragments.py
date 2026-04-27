"""GraphFragment abstraction and deterministic strict-collision reducer.

Phase 3 of the pipeline acceleration plan. This module provides the
infrastructure for fragment-based graph construction; individual enrichers
are migrated to produce fragments in Phase 6.

Design notes
------------
- ``GraphFragment`` is frozen and immutable. ``metadata`` is always a
  ``types.MappingProxyType``; ``__post_init__`` enforces this.
- ``merge_fragments`` is the single writer for the canonical ``nx.DiGraph``.
  It sorts fragments deterministically before merging, so insertion order
  never affects the result.
- Hard collisions on scalar identity keys raise ``FragmentMergeError`` with
  the full ``MergeReport`` attached for debugging. Do not log-and-continue.
- Additive keys (``ADDITIVE_ATTR_KEYS``) receive shallow/union merges.
- Graph-level metadata is only merged for keys in ``GRAPH_METADATA_ALLOWLIST``.
"""
from __future__ import annotations

import copy
import types
from dataclasses import dataclass, field
from typing import Any, Iterable

import networkx as nx


# Keys where a second fragment may update an already-present value.
# Shallow / additive merge rules apply (lists: append+dedup; sets: union;
# dicts: shallow merge). Any key NOT in this set that is already present
# on the graph is a hard collision if the new value differs.
ADDITIVE_ATTR_KEYS: frozenset[str] = frozenset(
    {
        "diagnostics",
        "tags",
        "evidence",
        "http_call_sites",
        "seam_edge_ids",
    }
)

# Only these keys may be written into graph.graph[...] by merge_fragments.
# Workers cannot inject arbitrary metadata.
GRAPH_METADATA_ALLOWLIST: frozenset[str] = frozenset(
    {
        "taint_edges",
        "run_metadata",
        "coverage",
        "migration_glob",
        "seam_edge_index",
    }
)

_STAGE_ORDER: dict[str, int] = {
    "extract": 0,
    "ingest": 1,
    "annotate": 2,
    "enrich": 3,
    "semantic": 4,
    "taint": 5,
}


# ── supporting value types ────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class FragmentNode:
    node_id: str
    attrs: dict[str, Any]


@dataclass(frozen=True, slots=True)
class FragmentEdge:
    u: str
    v: str
    key: str | None
    attrs: dict[str, Any]


@dataclass(frozen=True, slots=True)
class NodeAttrUpdate:
    node_id: str
    key: str
    value: Any


@dataclass(frozen=True, slots=True)
class EdgeAttrUpdate:
    u: str
    v: str
    key: str | None
    attr_key: str
    value: Any


# ── fragment ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class GraphFragment:
    """Immutable snapshot of nodes/edges/updates produced by one pipeline stage.

    *metadata* MUST be ``types.MappingProxyType``; ``__post_init__`` raises
    ``TypeError`` otherwise. Use :func:`make_fragment` to construct fragments
    — it wraps the dict automatically.

    ``frozen=True`` prevents field reassignment but not mutation of values
    inside mutable containers. Treat all fields as read-only after construction.
    Workers must not mutate fragment contents.
    """

    stage: str
    source_file: str | None
    file_hash: str | None
    language: str | None
    nodes: tuple[FragmentNode, ...]
    edges: tuple[FragmentEdge, ...]
    node_attr_updates: tuple[NodeAttrUpdate, ...]
    edge_attr_updates: tuple[EdgeAttrUpdate, ...]
    metadata: Any  # must be types.MappingProxyType at runtime
    diagnostics: tuple[dict, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.metadata, types.MappingProxyType):
            raise TypeError(
                f"GraphFragment.metadata must be types.MappingProxyType, "
                f"got {type(self.metadata).__name__}. "
                "Use make_fragment() or wrap with types.MappingProxyType()."
            )


def make_fragment(
    stage: str,
    *,
    source_file: str | None = None,
    file_hash: str | None = None,
    language: str | None = None,
    nodes: Iterable[FragmentNode] = (),
    edges: Iterable[FragmentEdge] = (),
    node_attr_updates: Iterable[NodeAttrUpdate] = (),
    edge_attr_updates: Iterable[EdgeAttrUpdate] = (),
    metadata: dict[str, Any] | None = None,
    diagnostics: Iterable[dict] = (),
) -> GraphFragment:
    """Factory that wraps *metadata* in ``MappingProxyType`` automatically."""
    return GraphFragment(
        stage=stage,
        source_file=source_file,
        file_hash=file_hash,
        language=language,
        nodes=tuple(nodes),
        edges=tuple(edges),
        node_attr_updates=tuple(node_attr_updates),
        edge_attr_updates=tuple(edge_attr_updates),
        metadata=types.MappingProxyType(metadata or {}),
        diagnostics=tuple(diagnostics),
    )


# ── merge report ──────────────────────────────────────────────────────────────


@dataclass
class HardCollision:
    entity_id: str  # node id, or "u->v" for edges
    key: str
    old_value: Any
    new_value: Any
    stage: str
    source_file: str | None


@dataclass
class MergeReport:
    fragments_processed: int = 0
    nodes_added: int = 0
    edges_added: int = 0
    hard_collisions: list[HardCollision] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.hard_collisions


class FragmentMergeError(Exception):
    """Raised when ``merge_fragments`` finds a hard collision on a scalar key.

    The full ``MergeReport`` is attached as ``.report`` for debugging.
    All collisions are collected before raising so the report is complete.
    """

    def __init__(self, report: MergeReport) -> None:
        self.report = report
        shown = report.hard_collisions[:5]
        details = "; ".join(
            f"{c.entity_id}.{c.key}: {c.old_value!r} → {c.new_value!r} [{c.stage}]"
            for c in shown
        )
        more = (
            f" (+{len(report.hard_collisions) - 5} more)"
            if len(report.hard_collisions) > 5
            else ""
        )
        super().__init__(
            f"{len(report.hard_collisions)} hard collision(s): {details}{more}"
        )


# ── reducer ───────────────────────────────────────────────────────────────────


def _merge_additive(existing: Any, incoming: Any, key: str) -> Any:
    """Shallow / additive merge for keys in ``ADDITIVE_ATTR_KEYS``."""
    if isinstance(existing, list) and isinstance(incoming, list):
        merged = list(existing)
        seen = set()
        for item in existing:
            try:
                seen.add(item)
            except TypeError:
                pass
        for item in incoming:
            try:
                if item not in seen:
                    merged.append(item)
                    seen.add(item)
            except TypeError:
                merged.append(item)
        return merged
    if isinstance(existing, set):
        return existing | (set(incoming) if not isinstance(incoming, set) else incoming)
    if isinstance(existing, dict) and isinstance(incoming, dict):
        return {**existing, **incoming}
    return incoming


def _apply_node_attr(
    node_attrs: dict[str, Any],
    k: str,
    v: Any,
    *,
    entity_id: str,
    frag: GraphFragment,
    report: MergeReport,
) -> None:
    if k not in node_attrs:
        node_attrs[k] = v
    elif k in ADDITIVE_ATTR_KEYS:
        node_attrs[k] = _merge_additive(node_attrs[k], v, k)
    elif node_attrs[k] != v:
        report.hard_collisions.append(
            HardCollision(
                entity_id=entity_id,
                key=k,
                old_value=node_attrs[k],
                new_value=v,
                stage=frag.stage,
                source_file=frag.source_file,
            )
        )


def _apply_edge_attr(
    edge_attrs: dict[str, Any],
    k: str,
    v: Any,
    *,
    entity_id: str,
    frag: GraphFragment,
    report: MergeReport,
) -> None:
    if k not in edge_attrs:
        edge_attrs[k] = v
    elif k in ADDITIVE_ATTR_KEYS:
        edge_attrs[k] = _merge_additive(edge_attrs[k], v, k)
    elif edge_attrs[k] != v:
        report.hard_collisions.append(
            HardCollision(
                entity_id=entity_id,
                key=k,
                old_value=edge_attrs[k],
                new_value=v,
                stage=frag.stage,
                source_file=frag.source_file,
            )
        )


def merge_fragments(
    graph: nx.DiGraph,
    fragments: Iterable[GraphFragment],
) -> MergeReport:
    """Deterministic reducer: merge *fragments* into *graph*.

    Sorts fragments by ``(stage, source_file or "", file_hash or "")`` before
    processing so result is insertion-order independent. Within each fragment,
    nodes are sorted by ``node_id`` and edges by ``(u, v, key or "")``.

    Collects ALL hard collisions before raising ``FragmentMergeError`` so the
    caller gets a complete ``MergeReport`` for debugging. Does not log-and-
    continue for scalar identity conflicts.

    Only the caller (main thread) should hold the unwrapped ``nx.DiGraph``.
    Worker threads must only read the graph; they never call this function.
    """
    report = MergeReport()
    sorted_fragments = sorted(
        fragments,
        key=lambda f: (_STAGE_ORDER.get(f.stage, 100), f.stage, f.source_file or "", f.file_hash or ""),
    )

    for frag in sorted_fragments:
        report.fragments_processed += 1

        # Nodes first across all fragments. This prevents NetworkX from
        # implicitly creating an endpoint during edge insertion before the
        # explicit node fragment for that endpoint is processed.
        for fnode in sorted(frag.nodes, key=lambda n: n.node_id):
            if fnode.node_id not in graph:
                graph.add_node(fnode.node_id, **fnode.attrs)
                report.nodes_added += 1
            else:
                node_attrs = graph.nodes[fnode.node_id]
                for k, v in fnode.attrs.items():
                    _apply_node_attr(
                        node_attrs, k, v,
                        entity_id=fnode.node_id, frag=frag, report=report,
                    )

    for frag in sorted_fragments:
        # Edges — deterministic order
        for fedge in sorted(frag.edges, key=lambda e: (e.u, e.v, e.key or "")):
            if not graph.has_edge(fedge.u, fedge.v):
                edge_kwargs = dict(fedge.attrs)
                if fedge.key is not None:
                    edge_kwargs["key"] = fedge.key
                graph.add_edge(fedge.u, fedge.v, **edge_kwargs)
                report.edges_added += 1
            else:
                edge_attrs = graph.edges[fedge.u, fedge.v]
                for k, v in fedge.attrs.items():
                    if k == "key":
                        continue
                    _apply_edge_attr(
                        edge_attrs, k, v,
                        entity_id=f"{fedge.u}->{fedge.v}", frag=frag, report=report,
                    )

    for frag in sorted_fragments:
        # Metadata — allowlist only; defensive copy to avoid holding fragment ref
        for k, v in frag.metadata.items():
            if k not in GRAPH_METADATA_ALLOWLIST:
                continue
            meta_val = copy.deepcopy(v)
            if k not in graph.graph:
                graph.graph[k] = meta_val
            elif k in ADDITIVE_ATTR_KEYS:
                graph.graph[k] = _merge_additive(graph.graph[k], meta_val, k)
            # Existing non-additive metadata wins (no collision for graph-level keys)

    # Attr updates (second pass — applied after all node/edge existence is settled)
    for frag in sorted_fragments:
        for upd in sorted(frag.node_attr_updates, key=lambda u: (u.node_id, u.key)):
            if upd.node_id in graph:
                _apply_node_attr(
                    graph.nodes[upd.node_id], upd.key, upd.value,
                    entity_id=upd.node_id, frag=frag, report=report,
                )

        for upd in sorted(
            frag.edge_attr_updates,
            key=lambda u: (u.u, u.v, u.key or "", u.attr_key),
        ):
            if graph.has_edge(upd.u, upd.v):
                _apply_edge_attr(
                    graph.edges[upd.u, upd.v], upd.attr_key, upd.value,
                    entity_id=f"{upd.u}->{upd.v}", frag=frag, report=report,
                )

    if report.hard_collisions:
        raise FragmentMergeError(report)

    return report


__all__ = [
    "ADDITIVE_ATTR_KEYS",
    "GRAPH_METADATA_ALLOWLIST",
    "FragmentNode",
    "FragmentEdge",
    "NodeAttrUpdate",
    "EdgeAttrUpdate",
    "GraphFragment",
    "make_fragment",
    "HardCollision",
    "MergeReport",
    "FragmentMergeError",
    "merge_fragments",
]
