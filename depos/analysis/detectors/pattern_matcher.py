"""Primitive pattern probes and Candidate conversion for detector rules."""
from __future__ import annotations

import re
from collections import OrderedDict
from pathlib import Path
from typing import Any, Iterable, Optional

import networkx as nx

from depos.analysis.detectors.builtin.common import make_candidate
from depos.analysis.detectors.pattern_formula import evaluate_formula
from depos.analysis.detectors.pattern_types import (
    PatternEvidence,
    PatternMatch,
    PatternRule,
    PatternScope,
    PatternScopeType,
)
from depos.analysis.schemas import AnalysisMode, Candidate, SeedType


class PatternSourceCache:
    """Bounded per-run source reader used by source-backed pattern probes."""

    def __init__(self, *, repo_root: Optional[Path] = None, max_entries: int = 128) -> None:
        self.repo_root = repo_root
        self.max_entries = max_entries
        self._cache: OrderedDict[str, str] = OrderedDict()
        self.read_count = 0

    def read(self, rel_or_abs: str | None) -> str | None:
        if not rel_or_abs:
            return None
        path = Path(rel_or_abs)
        if not path.is_absolute():
            if self.repo_root is None:
                return None
            path = self.repo_root / path
        try:
            key = str(path.resolve())
            cached = self._cache.get(key)
            if cached is not None:
                self._cache.move_to_end(key)
                return cached
            if not path.is_file():
                return None
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        self.read_count += 1
        self._cache[key] = text
        if len(self._cache) > self.max_entries:
            self._cache.popitem(last=False)
        return text


def _node_kind(attrs: dict[str, Any]) -> str:
    return str(
        attrs.get("node_kind")
        or attrs.get("entity_kind")
        or attrs.get("ast_kind")
        or attrs.get("kind")
        or ""
    )


def _scope_type(attrs: dict[str, Any], default: str) -> PatternScopeType:
    kind = _node_kind(attrs).lower()
    if attrs.get("is_fastapi_route") or kind in {"next_route", "route_handler"}:
        return "route"
    if kind == "env_var":
        return "env_var"
    if "function" in kind or "method" in kind:
        return "function"
    if "class" in kind:
        return "class"
    if kind == "prompt_template":
        return "prompt"
    if kind in {"config_key", "infra_service", "infra_workflow"}:
        return "config"
    if default in PatternScopeType.__args__:  # type: ignore[attr-defined]
        return default  # type: ignore[return-value]
    return "node"


def _line_from_span(attrs: dict[str, Any], key: str) -> int | None:
    span = attrs.get("span") or {}
    if isinstance(span, dict):
        point = span.get(key) or {}
        if isinstance(point, dict) and point.get("line") is not None:
            try:
                return int(point["line"])
            except (TypeError, ValueError):
                return None
    raw = attrs.get(f"{key}_line")
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def collect_pattern_scopes(
    graph: nx.DiGraph,
    rule: PatternRule,
    *,
    scope_ids: Iterable[str] | None = None,
) -> list[PatternScope]:
    """Build rule-eligible scopes from graph nodes."""

    allowed = {str(value) for value in scope_ids} if scope_ids is not None else None
    scopes: list[PatternScope] = []
    for node_id, attrs in graph.nodes(data=True):
        sid = str(node_id)
        if allowed is not None and sid not in allowed:
            continue
        attrs = dict(attrs or {})
        scope_type = _scope_type(attrs, rule.scope)
        if rule.scope not in {"node", "any"} and scope_type != rule.scope:
            continue
        scopes.append(
            PatternScope(
                scope_id=sid,
                scope_type=scope_type,
                file_path=str(attrs.get("source_file") or "") or None,
                node_id=sid,
                line_start=_line_from_span(attrs, "start"),
                line_end=_line_from_span(attrs, "end"),
                language=str(attrs.get("language") or attrs.get("lang") or "") or None,
            )
        )
    return scopes


def _match(
    rule: PatternRule,
    scope: PatternScope,
    *,
    matched_text: str | None = None,
    node_ids: list[str] | None = None,
    edge_ids: list[str] | None = None,
    evidence: list[PatternEvidence] | None = None,
    confidence: float = 1.0,
    metavars: dict[str, str] | None = None,
) -> PatternMatch:
    return PatternMatch(
        rule_id=rule.id,
        detector_name=rule.detector_name,
        scope=scope,
        matched_text=matched_text,
        metavars=dict(metavars or {}),
        node_ids=list(dict.fromkeys([*(node_ids or []), *([scope.node_id] if scope.node_id else [])])),
        edge_ids=list(edge_ids or []),
        evidence=list(evidence or []),
        confidence=confidence,
    )


def _source_for_scope(
    graph: nx.DiGraph,
    source_cache: PatternSourceCache,
    scope: PatternScope,
) -> str | None:
    text = source_cache.read(scope.file_path)
    if text is not None:
        return text
    if scope.node_id and graph.has_node(scope.node_id):
        attrs = graph.nodes[scope.node_id]
        embedded = str(attrs.get("embedded_text") or attrs.get("label") or "")
        return embedded or None
    return None


def _regex_flags(raw: Any) -> int:
    flags = 0
    for name in list(raw or []):
        if str(name).lower() in {"i", "ignorecase"}:
            flags |= re.I
        if str(name).lower() in {"m", "multiline"}:
            flags |= re.M
        if str(name).lower() in {"s", "dotall"}:
            flags |= re.S
    return flags


def _line_range(text: str, start: int, end: int) -> tuple[int, int]:
    line_start = text[:start].count("\n") + 1
    line_end = line_start + text[start:end].count("\n")
    return line_start, line_end


def _primitive_source_regex(
    graph: nx.DiGraph,
    source_cache: PatternSourceCache,
    rule: PatternRule,
    raw: Any,
    scopes: Iterable[PatternScope],
) -> dict[str, PatternMatch]:
    spec = {"pattern": raw} if isinstance(raw, str) else dict(raw or {})
    pattern = str(spec.get("pattern") or spec.get("regex") or "")
    if not pattern:
        return {}
    regex = re.compile(pattern, _regex_flags(spec.get("flags")))
    confidence = float(spec.get("confidence", 1.0))
    out: dict[str, PatternMatch] = {}
    for scope in scopes:
        text = _source_for_scope(graph, source_cache, scope)
        if not text:
            continue
        found = regex.search(text)
        if not found:
            continue
        line_start, line_end = _line_range(text, found.start(), found.end())
        match_scope = scope.model_copy(
            update={
                "line_start": line_start,
                "line_end": line_end,
            }
        )
        out[scope.scope_id] = _match(
            rule,
            match_scope,
            matched_text=found.group(0),
            evidence=[
                PatternEvidence(
                    kind="source_regex",
                    message=f"Matched source regex for {rule.id}",
                    node_id=scope.node_id,
                    file_path=scope.file_path,
                    line_start=line_start,
                    line_end=line_end,
                    data={"pattern": pattern},
                )
            ],
            confidence=confidence,
            metavars={str(k): str(v) for k, v in found.groupdict().items()},
        )
    return out


def _primitive_node_kind(
    graph: nx.DiGraph,
    rule: PatternRule,
    raw: Any,
    scopes: Iterable[PatternScope],
) -> dict[str, PatternMatch]:
    expected = str(raw.get("kind") if isinstance(raw, dict) else raw)
    out: dict[str, PatternMatch] = {}
    for scope in scopes:
        if not scope.node_id or not graph.has_node(scope.node_id):
            continue
        actual = _node_kind(dict(graph.nodes[scope.node_id]))
        if actual != expected:
            continue
        out[scope.scope_id] = _match(
            rule,
            scope,
            evidence=[
                PatternEvidence(
                    kind="node_kind",
                    message=f"Node kind is {actual}",
                    node_id=scope.node_id,
                    data={"expected": expected, "actual": actual},
                )
            ],
        )
    return out


def _primitive_node_attr(
    graph: nx.DiGraph,
    rule: PatternRule,
    raw: Any,
    scopes: Iterable[PatternScope],
) -> dict[str, PatternMatch]:
    spec = dict(raw or {})
    key = str(spec.get("key") or "")
    if not key:
        return {}
    expected = spec.get("equals", spec.get("value"))
    exists = spec.get("exists")
    regex = re.compile(str(spec["regex"])) if spec.get("regex") is not None else None
    out: dict[str, PatternMatch] = {}
    for scope in scopes:
        if not scope.node_id or not graph.has_node(scope.node_id):
            continue
        attrs = dict(graph.nodes[scope.node_id])
        value = attrs.get(key)
        ok = True
        if exists is not None:
            ok = (key in attrs and value not in (None, "")) is bool(exists)
        if expected is not None:
            ok = value == expected
        if regex is not None:
            ok = bool(regex.search(str(value or "")))
        if not ok:
            continue
        out[scope.scope_id] = _match(
            rule,
            scope,
            evidence=[
                PatternEvidence(
                    kind="node_attr",
                    message=f"Node attribute {key} matched",
                    node_id=scope.node_id,
                    data={"key": key, "value": value},
                )
            ],
        )
    return out


def _edge_id(u: str, v: str, data: dict[str, Any]) -> str:
    return str(data.get("edge_id") or f"{u}->{v}")


def _node_matches_kind(graph: nx.DiGraph, node_id: str, expected_kind: str | None) -> bool:
    if not expected_kind:
        return True
    if not graph.has_node(node_id):
        return False
    return _node_kind(dict(graph.nodes[node_id])) == expected_kind


def _primitive_edge_exists(
    graph: nx.DiGraph,
    rule: PatternRule,
    raw: Any,
    scopes: Iterable[PatternScope],
) -> dict[str, PatternMatch]:
    spec = dict(raw or {})
    relation = spec.get("relation") or spec.get("type")
    direction = str(spec.get("direction") or "either")
    source_kind = spec.get("source_kind")
    target_kind = spec.get("target_kind")
    out: dict[str, PatternMatch] = {}
    for scope in scopes:
        if not scope.node_id or not graph.has_node(scope.node_id):
            continue
        candidate_edges: list[tuple[str, str, dict[str, Any]]] = []
        if direction in {"incoming", "in", "either"}:
            candidate_edges.extend((str(u), str(v), dict(d)) for u, v, d in graph.in_edges(scope.node_id, data=True))
        if direction in {"outgoing", "out", "either"}:
            candidate_edges.extend((str(u), str(v), dict(d)) for u, v, d in graph.out_edges(scope.node_id, data=True))
        for u, v, data in candidate_edges:
            if relation is not None and data.get("relation") != relation:
                continue
            if not _node_matches_kind(graph, u, source_kind):
                continue
            if not _node_matches_kind(graph, v, target_kind):
                continue
            eid = _edge_id(u, v, data)
            out[scope.scope_id] = _match(
                rule,
                scope,
                node_ids=[u, v],
                edge_ids=[eid],
                evidence=[
                    PatternEvidence(
                        kind="edge_exists",
                        message=f"Found edge {eid}",
                        node_id=scope.node_id,
                        edge_id=eid,
                        data={"source": u, "target": v, "relation": data.get("relation")},
                    )
                ],
            )
            break
    return out


def _primitive_requires_node(
    graph: nx.DiGraph,
    rule: PatternRule,
    raw: Any,
    scopes: Iterable[PatternScope],
) -> dict[str, PatternMatch]:
    spec = dict(raw or {})
    kind = str(spec.get("kind") or "")
    direction = str(spec.get("direction") or "either")
    edge_spec = {
        "direction": direction,
        "relation": spec.get("relation"),
        "source_kind": kind if direction in {"incoming", "in"} else None,
        "target_kind": kind if direction in {"outgoing", "out"} else None,
    }
    if direction == "either":
        incoming = _primitive_edge_exists(
            graph, rule, {**edge_spec, "direction": "incoming", "source_kind": kind}, scopes
        )
        outgoing = _primitive_edge_exists(
            graph, rule, {**edge_spec, "direction": "outgoing", "target_kind": kind}, scopes
        )
        return {**outgoing, **incoming}
    return _primitive_edge_exists(graph, rule, edge_spec, scopes)


def _primitive_label_regex(
    graph: nx.DiGraph,
    rule: PatternRule,
    raw: Any,
    scopes: Iterable[PatternScope],
    *,
    kind: str,
) -> dict[str, PatternMatch]:
    pattern = str(raw.get("pattern") if isinstance(raw, dict) else raw)
    if not pattern:
        return {}
    regex = re.compile(pattern)
    out: dict[str, PatternMatch] = {}
    for scope in scopes:
        if not scope.node_id or not graph.has_node(scope.node_id):
            continue
        attrs = dict(graph.nodes[scope.node_id])
        haystack = " ".join(
            str(attrs.get(key) or "")
            for key in ("label", "name", "call_name", "import_name", "route_pattern", "path")
        )
        if not regex.search(haystack):
            continue
        out[scope.scope_id] = _match(
            rule,
            scope,
            evidence=[
                PatternEvidence(
                    kind=kind,
                    message=f"{kind} matched",
                    node_id=scope.node_id,
                    data={"pattern": pattern},
                )
            ],
        )
    return out


def _primitive_env_var(
    graph: nx.DiGraph,
    rule: PatternRule,
    raw: Any,
    scopes: Iterable[PatternScope],
) -> dict[str, PatternMatch]:
    spec = dict(raw or {})
    name_regex = re.compile(str(spec.get("name_regex") or ".*"))
    defined = spec.get("defined")
    out: dict[str, PatternMatch] = {}
    for scope in scopes:
        if not scope.node_id or not graph.has_node(scope.node_id):
            continue
        attrs = dict(graph.nodes[scope.node_id])
        if _node_kind(attrs) != "env_var":
            continue
        name = str(attrs.get("name") or attrs.get("label") or scope.node_id)
        if not name_regex.search(name):
            continue
        if defined is not None and bool(attrs.get("defined")) is not bool(defined):
            continue
        out[scope.scope_id] = _match(
            rule,
            scope,
            evidence=[
                PatternEvidence(
                    kind="env_var",
                    message=f"Environment variable {name} matched",
                    node_id=scope.node_id,
                    file_path=str(attrs.get("source_file") or "") or None,
                    data={"name": name, "defined": bool(attrs.get("defined"))},
                )
            ],
            metavars={"ENV": name},
        )
    return out


def evaluate_primitive(
    graph: nx.DiGraph,
    source_cache: PatternSourceCache,
    rule: PatternRule,
    primitive: dict[str, Any],
    scopes: Iterable[PatternScope],
) -> dict[str, PatternMatch]:
    if "source_regex" in primitive:
        return _primitive_source_regex(graph, source_cache, rule, primitive["source_regex"], scopes)
    if "node_kind" in primitive:
        return _primitive_node_kind(graph, rule, primitive["node_kind"], scopes)
    if "node_attr" in primitive:
        return _primitive_node_attr(graph, rule, primitive["node_attr"], scopes)
    if "edge_exists" in primitive:
        return _primitive_edge_exists(graph, rule, primitive["edge_exists"], scopes)
    if "requires_node" in primitive:
        return _primitive_requires_node(graph, rule, primitive["requires_node"], scopes)
    if "import_name" in primitive:
        return _primitive_label_regex(graph, rule, primitive["import_name"], scopes, kind="import_name")
    if "call_name" in primitive:
        return _primitive_label_regex(graph, rule, primitive["call_name"], scopes, kind="call_name")
    if "route_path" in primitive:
        return _primitive_label_regex(graph, rule, primitive["route_path"], scopes, kind="route_path")
    if "env_var" in primitive:
        return _primitive_env_var(graph, rule, primitive["env_var"], scopes)
    return {}


def run_pattern_rule(
    graph: nx.DiGraph,
    source_cache: PatternSourceCache,
    rule: PatternRule,
    scopes: Iterable[PatternScope],
    ctx: dict[str, Any] | None = None,
) -> list[PatternMatch]:
    """Run a pattern rule against scopes and return deterministic matches."""

    del ctx
    matches = evaluate_formula(
        rule.formula,
        scopes,
        rule_id=rule.id,
        detector_name=rule.detector_name,
        eval_primitive=lambda primitive, local_scopes: evaluate_primitive(
            graph, source_cache, rule, primitive, local_scopes
        ),
    )
    return list(matches.values())


def pattern_match_to_candidate(
    match: PatternMatch,
    rule: PatternRule,
    *,
    mode: AnalysisMode,
    config: Any,
    graph: nx.DiGraph | None = None,
    run_context: Any = None,
    seed_type: SeedType = SeedType.graph_anomaly,
    extra: dict[str, Any] | None = None,
) -> Candidate:
    """Convert a pattern match into the normal depOS Candidate path."""

    raw = {
        "rule_id": rule.id,
        "risk_category": rule.risk_category,
        "message": rule.message,
        "matched_scope": match.scope.model_dump(mode="json"),
        "matched_text": match.matched_text,
        "metavars": dict(match.metavars),
        "node_ids": list(match.node_ids),
        "edge_ids": list(match.edge_ids),
        "evidence": [e.model_dump(mode="json") for e in match.evidence],
        "semantic_requirement": rule.semantic_requirement,
    }
    raw.update(extra or {})
    return make_candidate(
        scope_id=match.scope.scope_id,
        seed_type=seed_type,
        detector_confidence=float(match.confidence),
        analysis_mode=mode,
        diff_anchors=list(dict.fromkeys(match.node_ids)),
        seam_edges=match.edge_ids,
        extra=raw,
        config=config,
        requires_cfg=rule.semantic_requirement == "cfg",
        requires_dfg=rule.semantic_requirement in {"dfg", "taint"},
        graph=graph,
        run_context=run_context,
    )


__all__ = [
    "PatternSourceCache",
    "collect_pattern_scopes",
    "evaluate_primitive",
    "pattern_match_to_candidate",
    "run_pattern_rule",
]
