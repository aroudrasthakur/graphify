"""LLM prompt construction from a :class:`ContextBundle` (alias: GraphContextBundle)."""
from __future__ import annotations

import json
from typing import Any, Iterable, Optional

from depos.analysis.config import BundleBudget, IntelligenceConfig
from depos.analysis.schemas import GraphContextBundle, ReasonerMode

_PROMPT_HEAD = """You are a software reasoning engine. Output ONLY JSON that matches the schema for the requested mode.

Mode A: pattern-based bugs (null ref, off-by-one, missing error handling).
Mode B: semantic mismatches (client contract vs server behavior).
Mode C: control/data flow bugs (missing guards, payload drift).

NEVER include natural language outside the JSON document.
"""

_RESPONSE_CONTRACTS = {
    ReasonerMode.A: (
        'RESPONSE CONTRACT:\n'
        'Return exactly {"mode":"A","findings":[{"bug_type":"string","description":"string","trigger_condition":"string","affected_path":["node_id"],"confidence":0.0,"graph_anchor_nodes":["node_id"]}]}.\n'
        'If there are no findings, return {"mode":"A","findings":[]}.\n'
        "Allowed finding keys only: bug_type, description, trigger_condition, affected_path, confidence, graph_anchor_nodes."
    ),
    ReasonerMode.B: (
        'RESPONSE CONTRACT:\n'
        'Return exactly {"mode":"B","findings":[{"violation_type":"string","description":"string","component_a":"string","component_b":"string","disagreement":"string","confidence":0.0,"graph_anchor_nodes":["node_id"]}]}.\n'
        'If there are no findings, return {"mode":"B","findings":[]}.\n'
        "Allowed finding keys only: violation_type, description, component_a, component_b, disagreement, confidence, graph_anchor_nodes.\n"
        "Do not use bug_type, remediation_suggestion, severity, or example_code in Mode B."
    ),
    ReasonerMode.C: (
        'RESPONSE CONTRACT:\n'
        'Return exactly {"mode":"C","findings":[{"flow_bug_type":"string","description":"string","operation":"string","violating_path":["node_id"],"missing_guard":"string","confidence":0.0,"graph_anchor_nodes":["node_id"]}]}.\n'
        'If there are no findings, return {"mode":"C","findings":[]}.\n'
        "Allowed finding keys only: flow_bug_type, description, operation, violating_path, missing_guard, confidence, graph_anchor_nodes.\n"
        "Do not use bug_type or remediation_suggestion in Mode C."
    ),
}

_DEFAULT_BUNDLE_BUDGET = BundleBudget()


def _bundle_budget(config: IntelligenceConfig | None) -> BundleBudget:
    return config.bundles if config is not None else _DEFAULT_BUNDLE_BUDGET


def _estimate_tokens(text: str) -> int:
    return max(1, (len(text) + 3) // 4)


def _truncate_text(text: str, max_chars: int) -> str:
    if max_chars <= 0:
        return ""
    if len(text) <= max_chars:
        return text
    if max_chars <= 3:
        return text[:max_chars]
    return text[: max_chars - 3] + "..."


def _ordered_text_items(
    texts: dict[str, str],
    preferred_order: Iterable[str] | None = None,
) -> list[tuple[str, str]]:
    if not preferred_order:
        return list(texts.items())
    ordered: list[tuple[str, str]] = []
    seen: set[str] = set()
    for node_id in preferred_order:
        if node_id in texts and node_id not in seen:
            ordered.append((node_id, texts[node_id]))
            seen.add(node_id)
    for node_id, text in texts.items():
        if node_id not in seen:
            ordered.append((node_id, text))
    return ordered


def _truncate_texts(
    texts: dict[str, str],
    *,
    max_entries: int,
    max_chars: int,
    preferred_order: Iterable[str] | None = None,
) -> dict[str, str]:
    if max_entries <= 0 or max_chars <= 0 or not texts:
        return {}
    ordered = _ordered_text_items(texts, preferred_order)
    return {
        node_id: _truncate_text(text, max_chars)
        for node_id, text in ordered[:max_entries]
    }


def _truncate_snippets(bundle: GraphContextBundle, *, max_chars: int) -> list[dict[str, Any]]:
    if max_chars <= 0:
        return []
    return [
        {
            "node_id": snippet.node_id,
            "file": snippet.source_file,
            "text": _truncate_text(snippet.text, max_chars),
            "evidence_quality": snippet.evidence_quality,
        }
        for snippet in bundle.code_snippets
    ]


def _limit_node_ids(node_ids: list[str], *, max_entries: int) -> list[str]:
    if max_entries <= 0:
        return []
    return list(node_ids[:max_entries])


def _body_json(body: dict[str, Any]) -> str:
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False)


def _render_prompt_text(citation_block: str, body: dict[str, Any]) -> str:
    return f"{_PROMPT_HEAD}\n{citation_block}\n```json\n{_body_json(body)}\n```"


def _pop_last_mapping_entry(
    mapping: dict[str, str],
    linked_ids: list[str] | None = None,
) -> bool:
    if not mapping:
        return False
    last_key = next(reversed(mapping))
    mapping.pop(last_key, None)
    if linked_ids is not None:
        linked_ids[:] = [node_id for node_id in linked_ids if node_id != last_key]
    return True


def _shrink_largest_snippet(snippets: list[dict[str, Any]]) -> bool:
    largest_idx = -1
    largest_size = 0
    for idx, snippet in enumerate(snippets):
        size = len(str(snippet.get("text") or ""))
        if size > largest_size:
            largest_idx = idx
            largest_size = size
    if largest_idx == -1 or largest_size <= 96:
        return False
    target = max(96, largest_size // 2)
    snippets[largest_idx]["text"] = _truncate_text(
        str(snippets[largest_idx].get("text") or ""),
        target,
    )
    return True


def _enforce_prompt_budget(
    citation_block: str,
    body: dict[str, Any],
    *,
    max_prompt_tokens: int,
) -> str:
    prompt = _render_prompt_text(citation_block, body)
    if max_prompt_tokens <= 0:
        return prompt
    while _estimate_tokens(prompt) > max_prompt_tokens:
        if _pop_last_mapping_entry(body["seam_neighbor_texts"]):
            prompt = _render_prompt_text(citation_block, body)
            continue
        if _pop_last_mapping_entry(body["callee_texts"], body["callees"]):
            prompt = _render_prompt_text(citation_block, body)
            continue
        if body["callees"]:
            body["callees"].pop()
            prompt = _render_prompt_text(citation_block, body)
            continue
        if _pop_last_mapping_entry(body["caller_texts"], body["callers"]):
            prompt = _render_prompt_text(citation_block, body)
            continue
        if body["callers"]:
            body["callers"].pop()
            prompt = _render_prompt_text(citation_block, body)
            continue
        if _shrink_largest_snippet(body["code_snippets"]):
            prompt = _render_prompt_text(citation_block, body)
            continue
        if body["code_snippets"]:
            body["code_snippets"].pop()
            prompt = _render_prompt_text(citation_block, body)
            continue
        if body["call_chain_out"]:
            body["call_chain_out"].pop()
            prompt = _render_prompt_text(citation_block, body)
            continue
        if body["call_chain_in"]:
            body["call_chain_in"].pop()
            prompt = _render_prompt_text(citation_block, body)
            continue
        if body.get("null_paths"):
            body["null_paths"] = None
            prompt = _render_prompt_text(citation_block, body)
            continue
        if body.get("cfg_summary"):
            body["cfg_summary"] = None
            prompt = _render_prompt_text(citation_block, body)
            continue
        if body["taint_edges"]:
            body["taint_edges"].pop()
            prompt = _render_prompt_text(citation_block, body)
            continue
        if body["cross_language_seams"]:
            body["cross_language_seams"].pop()
            prompt = _render_prompt_text(citation_block, body)
            continue
        break
    return prompt


def render_bundle_prompt(
    mode: ReasonerMode,
    bundle: GraphContextBundle,
    *,
    rank_metadata: Optional[dict[str, Any]] = None,
    config: IntelligenceConfig | None = None,
) -> str:
    """Build the JSON-in-fenced prompt body. Keeps graph structure out of ``reasoning_engine``."""
    budget = _bundle_budget(config)
    response_contract = _RESPONSE_CONTRACTS[mode]
    citation_block = f"""CITATION REQUIREMENT:
Every claim you make must cite at least one of the following from the evidence bundle:
- A node_id from: scope_node, callers, callees, or seam neighbor nodes
- An edge_id from: seam_edges
- A step from: taint_chain (intermediate_path entries)

Format citations inline as [node:<node_id>], [edge:<edge_id>], or [taint:<step>].
Any claim without a citation will be treated as unconfirmed and sent to gray-zone.
Semantic layers available for this candidate:
- CFG: {bundle.cfg_available}
- DFG/def-use: {bundle.dfg_available}
- Pre-computed taint edges: {bundle.taint_edges_available}
If a finding requires a layer that is not available, state this explicitly
and recommend GRAY-ZONE pending that analysis.

{response_contract}
"""
    callers = _limit_node_ids(bundle.callers, max_entries=budget.max_caller_texts)
    callees = _limit_node_ids(bundle.callees, max_entries=budget.max_callee_texts)
    caller_texts = _truncate_texts(
        bundle.caller_texts,
        max_entries=budget.max_caller_texts,
        max_chars=budget.max_snippet_chars,
        preferred_order=callers,
    )
    callee_texts = _truncate_texts(
        bundle.callee_texts,
        max_entries=budget.max_callee_texts,
        max_chars=budget.max_snippet_chars,
        preferred_order=callees,
    )
    seam_neighbor_texts = _truncate_texts(
        bundle.seam_neighbor_texts,
        max_entries=budget.max_seam_neighbor_texts,
        max_chars=budget.max_snippet_chars,
    )
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
        "callers": callers,
        "callees": callees,
        "caller_texts": caller_texts,
        "callee_texts": callee_texts,
        "seam_neighbor_texts": seam_neighbor_texts,
        "data_reads": bundle.data_reads,
        "data_writes": bundle.data_writes,
        "rls_coverage": {k: v.value for k, v in bundle.rls_coverage.items()},
        "migration_state": {k: v.value for k, v in bundle.migration_state.items()},
        "cross_language_seams": [e.model_dump(mode="json") for e in bundle.cross_language_seams],
        "taint_edges": [e.model_dump(mode="json") for e in bundle.taint_edges],
        "cfg_summary": bundle.cfg_summary,
        "null_paths": bundle.null_paths,
        "call_chain_in": bundle.call_chain_in,
        "call_chain_out": bundle.call_chain_out,
        "code_snippets": _truncate_snippets(bundle, max_chars=budget.max_snippet_chars),
    }
    if rank_metadata:
        body["rank_metadata"] = rank_metadata
    return _enforce_prompt_budget(
        citation_block,
        body,
        max_prompt_tokens=budget.max_prompt_tokens,
    )


__all__ = ["render_bundle_prompt"]
