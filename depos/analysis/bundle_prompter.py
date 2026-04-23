"""LLM prompt construction from a :class:`ContextBundle` (alias: GraphContextBundle)."""
from __future__ import annotations

import json
from typing import Any, Optional

from depos.analysis.schemas import GraphContextBundle, ReasonerMode

_PROMPT_HEAD = """You are a software reasoning engine. Output ONLY JSON that matches the schema for the requested mode.

Mode A: pattern-based bugs (null ref, off-by-one, missing error handling).
Mode B: semantic mismatches (client contract vs server behavior).
Mode C: control/data flow bugs (missing guards, payload drift).

NEVER include natural language outside the JSON document.
"""


def render_bundle_prompt(
    mode: ReasonerMode,
    bundle: GraphContextBundle,
    *,
    rank_metadata: Optional[dict[str, Any]] = None,
) -> str:
    """Build the JSON-in-fenced prompt body. Keeps graph structure out of ``reasoning_engine``."""
    body: dict[str, Any] = {
        "candidate_id": bundle.candidate_id,
        "scope_id": bundle.scope_id,
        "scope_node_id": bundle.scope_node_id,
        "mode": mode.value,
        "score_composite": bundle.score_composite,
        "candidate_score": bundle.candidate_score,
        "semantic_layers": {
            "cfg_available": bundle.cfg_available,
            "dfg_available": bundle.dfg_available,
            "taint_edges_available": bundle.taint_edges_available,
        },
        "data_reads": bundle.data_reads,
        "data_writes": bundle.data_writes,
        "rls_coverage": {k: v.value for k, v in bundle.rls_coverage.items()},
        "migration_state": {k: v.value for k, v in bundle.migration_state.items()},
        "cross_language_seams": [e.model_dump(mode="json") for e in bundle.cross_language_seams],
        "taint_edges": [e.model_dump(mode="json") for e in bundle.taint_edges],
        "call_chain_in": bundle.call_chain_in,
        "call_chain_out": bundle.call_chain_out,
        "code_snippets": [
            {
                "node_id": s.node_id,
                "file": s.source_file,
                "text": s.text[:4000],
                "evidence_quality": s.evidence_quality,
            }
            for s in bundle.code_snippets
        ],
    }
    if rank_metadata:
        body["rank_metadata"] = rank_metadata
    return f"{_PROMPT_HEAD}\n```json\n{json.dumps(body, indent=2)}\n```"


__all__ = ["render_bundle_prompt"]
