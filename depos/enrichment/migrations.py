"""Module 1: migration sequencer.

Reads the configured migration glob (default ``supabase/migrations/*.sql``)
and emits:

- ``SCHEMA_DEFINED_BY_MIGRATION`` edges from each referenced table (synth
  node ``sql:table:<name>``) to a synth migration node
  ``sql:migration:<filename>``.
- ``MIGRATION_PRECEDES`` edges between consecutive migrations sorted by
  their lexical filename (Supabase timestamps make this correct by
  construction).

Each edge carries ``migration_id`` and ``migration_order`` so the
verifier's migration-awareness checks can answer "does this table exist
in this branch yet?" without replaying SQL.
"""
from __future__ import annotations

import re
from pathlib import Path

import networkx as nx

from depos.analysis.config import IntelligenceConfig
from depos.analysis.fragments import FragmentEdge, FragmentNode, GraphFragment, make_fragment
from depos.analysis.schemas import ContractKind, SemanticEdgeMetadata
from depos.graph_relations import MIGRATION_PRECEDES
from depos.graph_relations import SCHEMA_DEFINED_BY_MIGRATION


_CREATE_TABLE = re.compile(
    r"create\s+table\s+(?:if\s+not\s+exists\s+)?(?:public\.)?(?P<table>[a-zA-Z_][a-zA-Z0-9_]*)",
    re.IGNORECASE,
)
_DROP_TABLE = re.compile(
    r"drop\s+table\s+(?:if\s+exists\s+)?(?:public\.)?(?P<table>[a-zA-Z_][a-zA-Z0-9_]*)",
    re.IGNORECASE,
)


def _find_migrations(config: IntelligenceConfig, repo_root: Path | None = None) -> list[Path]:
    base = repo_root or Path()
    return sorted(base.glob(config.migration_glob))


def _table_ops_in(text: str) -> list[tuple[str, str]]:
    """Return list of (op, table) tuples where op is 'create' or 'drop'."""
    stripped = re.sub(r"--[^\n]*", "", text)
    ops: list[tuple[str, str]] = []
    for m in _CREATE_TABLE.finditer(stripped):
        ops.append(("create", m.group("table").lower()))
    for m in _DROP_TABLE.finditer(stripped):
        ops.append(("drop", m.group("table").lower()))
    return ops


def emit_migration_edges(
    graph: nx.DiGraph,
    *,
    config: IntelligenceConfig,
    repo_root: Path | None = None,
) -> GraphFragment:
    migrations = _find_migrations(config, repo_root)
    if not migrations:
        return make_fragment("enrich_migrations")

    new_nodes: list[FragmentNode] = []
    edges: list[FragmentEdge] = []
    seen_nodes: set[str] = set()
    # Track (u, v) pairs to avoid same-pair edges with conflicting attrs
    # (e.g. CREATE and DROP of same table in same migration file).
    seen_table_mig: set[tuple[str, str]] = set()

    prev_mig_node: str | None = None
    for order, path in enumerate(migrations):
        mig_node = f"sql:migration:{path.name}"
        if mig_node not in seen_nodes and not graph.has_node(mig_node):
            seen_nodes.add(mig_node)
            new_nodes.append(FragmentNode(
                node_id=mig_node,
                attrs={
                    "label": path.name,
                    "file_type": "sql_migration",
                    "synthetic": True,
                    "source_file": str(path),
                    "migration_order": order,
                },
            ))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        for op, table in _table_ops_in(text):
            table_node = f"sql:table:{table}"
            if table_node not in seen_nodes and not graph.has_node(table_node):
                seen_nodes.add(table_node)
                new_nodes.append(FragmentNode(
                    node_id=table_node,
                    attrs={"label": table, "file_type": "sql_table", "synthetic": True},
                ))
            pair = (table_node, mig_node)
            if pair in seen_table_mig:
                continue
            seen_table_mig.add(pair)
            metadata = SemanticEdgeMetadata(
                confidence=1.0,
                inferred=False,
                source_system="postgres",
                target_system="postgres",
                contract_kind=ContractKind.schema,
                table_name=table,
                migration_id=path.name,
                migration_order=order,
                branch_visible=(op == "create"),
            )
            edges.append(FragmentEdge(
                u=table_node,
                v=mig_node,
                key=f"schema:{op}:{path.name}",
                attrs={"relation": SCHEMA_DEFINED_BY_MIGRATION, **metadata.model_dump(mode="json")},
            ))
        if prev_mig_node is not None:
            edges.append(FragmentEdge(
                u=prev_mig_node,
                v=mig_node,
                key=f"precedes:{path.name}",
                attrs={
                    "relation": MIGRATION_PRECEDES,
                    "migration_order": order,
                    "migration_id": path.name,
                },
            ))
        prev_mig_node = mig_node

    return make_fragment("enrich_migrations", nodes=new_nodes, edges=edges)


__all__ = ["emit_migration_edges"]
