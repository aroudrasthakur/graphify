"""Detector policy loading and enablement rules."""
from __future__ import annotations

from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

import networkx as nx
from pydantic import BaseModel, Field

from depos.analysis.schemas import Detector

if TYPE_CHECKING:
    from depos.analysis.run_context import RunContext


class DetectorPolicy(BaseModel):
    enabled: set[str] = Field(default_factory=set)
    disabled: set[str] = Field(default_factory=set)
    severity_overrides: dict[str, str] = Field(default_factory=dict)

    def is_enabled(self, spec: Detector) -> bool:
        if spec.name in self.disabled:
            return False
        if self.enabled:
            return spec.name in self.enabled
        return spec.enabled_by_default

    def severity_for(self, spec: Detector) -> str:
        return self.severity_overrides.get(spec.name, spec.severity_default)

    @staticmethod
    def semantic_layer_satisfied(
        spec: Detector,
        ctx: "RunContext",
        scope_node_id: str,
    ) -> bool:
        req = spec.semantic_requirement
        if req is None:
            return True
        if req == "cfg":
            return bool(ctx.cfg_available.get(scope_node_id, False))
        if req == "dfg":
            return bool(ctx.dfg_available.get(scope_node_id, False))
        if req == "taint":
            return bool(ctx.taint_edges_available.get(scope_node_id, False))
        raise ValueError(f"Unknown semantic_requirement: {req!r}")


def iter_eligible_scopes(
    graph: nx.DiGraph,
    ctx: "RunContext",
    spec: Detector,
) -> Iterator[str]:
    """Yields scope node IDs for which this detector's semantic requirements are satisfied."""
    for node_id in graph.nodes:
        sid = str(node_id)
        if DetectorPolicy.semantic_layer_satisfied(spec, ctx, sid):
            yield sid


def load_policy(raw: Any | None) -> DetectorPolicy:
    if raw is None:
        return DetectorPolicy()
    if isinstance(raw, DetectorPolicy):
        return raw
    if isinstance(raw, dict):
        return DetectorPolicy(
            enabled=set(str(v) for v in raw.get("enabled", []) if str(v).strip()),
            disabled=set(str(v) for v in raw.get("disabled", []) if str(v).strip()),
            severity_overrides={str(k): str(v) for k, v in dict(raw.get("severity_overrides", {})).items()},
        )
    return DetectorPolicy()


__all__ = [
    "DetectorPolicy",
    "load_policy",
    "iter_eligible_scopes",
]
