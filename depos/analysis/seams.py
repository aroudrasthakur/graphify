"""Seam edge materialization: cross-language boundaries (Section 7.1)."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import networkx as nx

_SEAM_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"http", re.I), "http_bridge"),
    (re.compile(r"rpc|grpc|trpc", re.I), "rpc"),
    (re.compile(r"ffi|native|cffi|ctypes", re.I), "ffi"),
    (re.compile(r"queue|celery|task|sns|sqs", re.I), "queue"),
    (re.compile(r"schema|openapi|zod|pydantic", re.I), "schema"),
    (re.compile(r"edge[_-]?function|serverless|lambda", re.I), "serverless"),
]


@dataclass
class SeamEdge:
    """Lightweight seam record (superseded by schemas.SeamEdge in Phase 2)."""

    edge_id: str
    u: str
    v: str
    source_language: str
    target_language: str
    pattern: str
    relation: str
    contract_defined: bool = False
    contract_verified: bool = False

    @property
    def risk(self) -> float:
        base = {
            "ffi": 0.9,
            "unknown": 0.85,
            "generic": 0.85,
            "wasm": 0.75,
            "ipc": 0.7,
            "rpc": 0.7,
            "serverless": 0.7,
            "queue": 0.6,
            "schema": 0.55,
            "http": 0.5,
            "http_bridge": 0.5,
        }.get(self.pattern, 0.85)
        return base if not self.contract_verified else base * 0.4


def _lang(attrs: dict) -> str:
    for key in ("language", "lang", "source_language"):
        v = attrs.get(key)
        if v:
            return str(v).lower()
    p = str(attrs.get("source_file") or "")
    if p.endswith(".py"):
        return "python"
    if p.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")):
        return "javascript"
    if p.endswith((".go",)):
        return "go"
    if p.endswith((".rs",)):
        return "rust"
    return "unknown"


def _classify(relation: str) -> str:
    r = relation or ""
    for pat, name in _SEAM_PATTERNS:
        if pat.search(r):
            return name
    return "generic"


def _contract_defined(data: dict[str, Any], relation: str) -> bool:
    if any(data.get(key) for key in ("proto_file", "schema_ref", "openapi_ref", "type_stub")):
        return True
    lowered = relation.lower()
    return any(token in lowered for token in ("typed", "proto", "schema", "contract"))


def build_seam_edge_index(graph: nx.DiGraph) -> dict[str, Any]:
    """Attach ``seam`` metadata on cross-language graph edges; return edge_id -> SeamEdge."""
    index: dict[str, SeamEdge] = {}
    for u, v, data in graph.edges(data=True):
        a = graph.nodes.get(u) or {}
        b = graph.nodes.get(v) or {}
        la, lb = _lang(a), _lang(b)
        if not la or not lb or la == lb:
            continue
        eid = str(data.get("edge_id") or f"{u}->{v}")
        if not data.get("edge_id"):
            graph.edges[u, v]["edge_id"] = eid
        rel = str(data.get("relation") or data.get("label") or "edge")
        pat = _classify(rel)
        contract_defined = _contract_defined(data, rel)
        # TODO: static type verification across seam boundaries.
        contract_verified = False
        record = SeamEdge(
            edge_id=eid,
            u=str(u),
            v=str(v),
            source_language=la,
            target_language=lb,
            pattern=pat,
            relation=rel,
            contract_defined=contract_defined,
            contract_verified=contract_verified,
        )
        index[eid] = record
        data["seam"] = {
            "edge_id": eid,
            "source_language": la,
            "target_language": lb,
            "pattern": pat,
            "contract_defined": contract_defined,
            "contract_verified": contract_verified,
        }
    for u, v, data in graph.edges(data=True):
        if not (data.get("source_system") and data.get("target_system")):
            continue
        eid = str(data.get("edge_id") or f"{u}->{v}")
        if not data.get("edge_id"):
            graph.edges[u, v]["edge_id"] = eid
    return index  # type: ignore[return-value]
