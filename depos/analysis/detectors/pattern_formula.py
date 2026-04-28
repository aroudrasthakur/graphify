"""Small scope-keyed formula evaluator for pattern detector rules."""
from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from depos.analysis.detectors.pattern_types import PatternMatch, PatternScope

PrimitiveEvaluator = Callable[[dict[str, Any], Iterable[PatternScope]], dict[str, PatternMatch]]


def _base_match(rule_id: str, detector_name: str, scope: PatternScope) -> PatternMatch:
    node_ids = [scope.node_id] if scope.node_id else []
    return PatternMatch(
        rule_id=rule_id,
        detector_name=detector_name,
        scope=scope,
        node_ids=node_ids,
        confidence=1.0,
    )


def merge_matches(left: PatternMatch, right: PatternMatch) -> PatternMatch:
    """Merge two child matches for the same scope into one replayable witness."""

    node_ids = list(dict.fromkeys([*left.node_ids, *right.node_ids]))
    edge_ids = list(dict.fromkeys([*left.edge_ids, *right.edge_ids]))
    return left.model_copy(
        update={
            "matched_text": left.matched_text or right.matched_text,
            "metavars": {**right.metavars, **left.metavars},
            "node_ids": node_ids,
            "edge_ids": edge_ids,
            "evidence": [*left.evidence, *right.evidence],
            "confidence": min(float(left.confidence), float(right.confidence)),
        }
    )


def evaluate_formula(
    formula: dict[str, Any],
    scopes: Iterable[PatternScope],
    *,
    rule_id: str,
    detector_name: str,
    eval_primitive: PrimitiveEvaluator,
) -> dict[str, PatternMatch]:
    """Evaluate a v1 pattern formula and return matches keyed by scope_id."""

    scope_list = list(scopes)
    by_scope = {scope.scope_id: scope for scope in scope_list}

    def eval_node(node: Any) -> dict[str, PatternMatch]:
        if not isinstance(node, dict):
            return {}
        if "all_of" in node:
            children = list(node.get("all_of") or [])
            if not children:
                return {
                    scope.scope_id: _base_match(rule_id, detector_name, scope)
                    for scope in scope_list
                }
            current: dict[str, PatternMatch] | None = None
            for child in children:
                child_matches = eval_node(child)
                if current is None:
                    current = child_matches
                    continue
                kept = set(current) & set(child_matches)
                current = {
                    scope_id: merge_matches(current[scope_id], child_matches[scope_id])
                    for scope_id in kept
                }
            return current or {}
        if "any_of" in node:
            merged: dict[str, PatternMatch] = {}
            for child in list(node.get("any_of") or []):
                for scope_id, match in eval_node(child).items():
                    merged[scope_id] = (
                        merge_matches(merged[scope_id], match)
                        if scope_id in merged
                        else match
                    )
            return merged
        if "not" in node:
            excluded = set(eval_node(node.get("not") or {}).keys())
            return {
                scope_id: _base_match(rule_id, detector_name, scope)
                for scope_id, scope in by_scope.items()
                if scope_id not in excluded
            }
        if "requires_edge" in node:
            return eval_primitive({"edge_exists": node.get("requires_edge")}, scope_list)
        if "requires_node" in node:
            return eval_primitive({"requires_node": node.get("requires_node")}, scope_list)
        return eval_primitive(node, scope_list)

    return eval_node(formula)


__all__ = ["evaluate_formula", "merge_matches"]
