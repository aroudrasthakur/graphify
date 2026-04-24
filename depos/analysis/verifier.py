"""Module 6 — deterministic verifier.

After Stage 6 closure the verifier consumes only :class:`ContextBundle`
facts and never reads the graph directly.

Reasoner-backed findings are audited through an explicit rule engine with
global auto-grayzone conditions applied first. Mechanical detectors keep
their direct bundle-only structural probes so existing non-reasoner
detectors remain deterministic and testable.
"""
from __future__ import annotations

from collections import OrderedDict
from pathlib import Path
from typing import Any, Callable, Iterable

from depos.analysis import verifier_rules
from depos.analysis.citations import evidence_cites_bundle
from depos.analysis.config import IntelligenceConfig
from depos.analysis.oracles import ORACLES
from depos.analysis.schemas import (
    Candidate,
    ContextBundle,
    Finding,
    ModeAFinding,
    ModeAOutput,
    ModeBFinding,
    ModeBOutput,
    ModeCFinding,
    ModeCOutput,
    ReasonerMode,
    RLSCoverage,
    VerifierAuditEntry,
    VerifierCheckResult,
    VerifierOutcome,
    VerifierStageResult,
)

Probe = Callable[[], VerifierCheckResult]


class SourceSnippetCache:
    """Bounded per-run source reader for advisory verifier stages."""

    def __init__(self, max_entries: int = 128) -> None:
        self.max_entries = max_entries
        self._cache: OrderedDict[tuple[str, int, int, int, int], str] = OrderedDict()
        self.read_count = 0

    def read(self, path: str | Path, start_line: int = 0, end_line: int = 0) -> str:
        source_path = Path(path).resolve()
        stat = source_path.stat()
        key = (
            str(source_path),
            int(start_line),
            int(end_line),
            int(stat.st_mtime_ns),
            int(stat.st_size),
        )
        cached = self._cache.get(key)
        if cached is not None:
            self._cache.move_to_end(key)
            return cached
        text = source_path.read_text(encoding="utf-8", errors="replace")
        self.read_count += 1
        if start_line > 0 or end_line > 0:
            lines = text.splitlines()
            start = max(start_line - 1, 0) if start_line > 0 else 0
            end = max(end_line, start_line) if end_line > 0 else len(lines)
            text = "\n".join(lines[start:end])
        self._cache[key] = text
        if len(self._cache) > self.max_entries:
            self._cache.popitem(last=False)
        return text


def _detector_meta(candidate: Candidate) -> dict[str, Any]:
    return candidate.detector_payload.model_dump(mode="json")


def _detector_name(candidate: Candidate) -> str:
    return str(_detector_meta(candidate).get("detector_name") or "legacy")


def _detector_spec(candidate: Candidate):
    try:
        from depos.analysis.detectors import get_detector

        name = _detector_name(candidate)
        if name == "legacy":
            return None
        return get_detector(name)
    except Exception as e:  # noqa: BLE001
        import logging
        logging.getLogger(__name__).warning("Failed to load detector '%s': %s", _detector_name(candidate), e)
        return None


def _safe_probe(name: str, fn: Probe) -> VerifierCheckResult:
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001
        import logging
        logging.getLogger(__name__).warning("Probe '%s' failed unexpectedly: %s", name, exc)
        return VerifierCheckResult(name=name, result="unavailable", detail=f"exception:{exc}")


def _candidate_witness_path(candidate: Candidate) -> list[str]:
    if candidate.diff_anchors:
        return list(dict.fromkeys(candidate.diff_anchors))
    nodes: list[str] = []
    for seam in candidate.seam_edges:
        if seam.source:
            nodes.append(str(seam.source))
        if seam.target:
            nodes.append(str(seam.target))
    if nodes:
        return list(dict.fromkeys(nodes))
    if candidate.scope_id.startswith("node:"):
        return [candidate.scope_id[5:]]
    if candidate.scope_id:
        return [candidate.scope_id]
    return []


def _bundle_node_ids(bundle: ContextBundle) -> set[str]:
    return set(bundle.node_facts)


def _edge_facts_for_path(bundle: ContextBundle, source: str, target: str) -> list[Any]:
    return [edge for edge in bundle.edge_facts if edge.source == source and edge.target == target]


def graph_path_probe(bundle: ContextBundle, nodes: list[str]) -> VerifierCheckResult:
    if not nodes:
        return VerifierCheckResult(name="graph_path_exists", result="unavailable", detail="no nodes cited")
    missing = [node_id for node_id in nodes if node_id not in _bundle_node_ids(bundle)]
    if missing:
        return VerifierCheckResult(
            name="graph_path_exists",
            result="fail",
            detail=f"missing_nodes={missing}",
        )
    return VerifierCheckResult(name="graph_path_exists", result="pass")


def edge_confidence_probe(
    bundle: ContextBundle,
    path: list[str],
    *,
    floor: float,
    inferred_floor_applied: bool,
) -> VerifierCheckResult:
    if len(path) < 2:
        return VerifierCheckResult(name="edge_confidence_floor", result="unavailable")
    min_conf = 1.0
    all_inferred = True
    checked = 0
    for source, target in zip(path, path[1:]):
        facts = _edge_facts_for_path(bundle, source, target)
        if not facts:
            continue
        checked += 1
        for fact in facts:
            conf = float(fact.confidence)
            if not fact.inferred:
                all_inferred = False
            if conf < min_conf:
                min_conf = conf
    if checked == 0:
        return VerifierCheckResult(name="edge_confidence_floor", result="unavailable")
    effective_floor = floor + (0.1 if inferred_floor_applied else 0.0)
    if all_inferred and min_conf < effective_floor:
        return VerifierCheckResult(
            name="edge_confidence_floor",
            result="fail",
            detail=f"min_conf={min_conf:.2f} floor={effective_floor:.2f} all_inferred=true",
        )
    return VerifierCheckResult(name="edge_confidence_floor", result="pass", detail=f"min_conf={min_conf:.2f}")


def rls_awareness_probe(bundle: ContextBundle, candidate: Candidate) -> VerifierCheckResult:
    detector_name = _detector_name(candidate)
    rls_detector = "rls" in detector_name
    if not rls_detector and not bundle.rls_coverage:
        return VerifierCheckResult(name="rls_awareness", result="unavailable")
    if not bundle.rls_coverage:
        return VerifierCheckResult(name="rls_awareness", result="insufficient_static_evidence")
    states = list(bundle.rls_coverage.values())
    if any(cov == RLSCoverage.full for cov in states):
        return VerifierCheckResult(name="rls_awareness", result="rls_covered", detail="full_on_any_cited_table")
    if any(cov in {RLSCoverage.partial_operation, RLSCoverage.partial_predicate} for cov in states):
        return VerifierCheckResult(name="rls_awareness", result="rls_partial")
    return VerifierCheckResult(name="rls_awareness", result="pass", detail="no_coverage_claimed")


def migration_branch_probe(bundle: ContextBundle, cited_tables: list[str]) -> VerifierCheckResult:
    if not cited_tables:
        return VerifierCheckResult(name="migration_branch_state", result="unavailable")
    missing = [table for table in cited_tables if table not in bundle.migration_state]
    if missing:
        return VerifierCheckResult(
            name="migration_branch_state",
            result="invalid",
            detail=f"not_in_branch={missing}",
        )
    return VerifierCheckResult(name="migration_branch_state", result="pass")


def payload_contract_probe(bundle: ContextBundle, cited_nodes: list[str]) -> VerifierCheckResult:
    for edge in bundle.edge_facts:
        if edge.source not in cited_nodes:
            continue
        missing = list(edge.payload_missing_fields)
        extra = list(edge.payload_extra_fields)
        if missing or extra:
            return VerifierCheckResult(
                name="payload_contract",
                result="fail",
                detail=f"missing={missing or []} extra={extra or []}",
            )
    return VerifierCheckResult(name="payload_contract", result="pass")


def phantom_anchor_probe(candidate: Candidate, witness_path: list[str], *, enabled: bool) -> VerifierCheckResult:
    if not enabled or not candidate.diff_anchors:
        return VerifierCheckResult(name="phantom_anchor_short_circuit", result="unavailable")
    if not witness_path:
        return VerifierCheckResult(name="phantom_anchor_short_circuit", result="unavailable")
    if set(candidate.diff_anchors) & set(witness_path):
        return VerifierCheckResult(name="phantom_anchor_short_circuit", result="pass")
    return VerifierCheckResult(
        name="phantom_anchor_short_circuit",
        result="fail",
        detail="diff_anchors_not_in_witness",
    )


def external_oracle_probe(candidate: Candidate) -> VerifierCheckResult:
    meta = _detector_meta(candidate)
    hints = dict(meta.get("oracle_hints") or candidate.detector_payload.oracle_hints or {})
    if not hints:
        return VerifierCheckResult(name="external_oracle_lookup", result="unavailable")
    oracle_name = str(hints.get("oracle") or "")
    if not oracle_name:
        if hints.get("schema"):
            oracle_name = "json_schema"
        elif hints.get("ecosystem") or hints.get("name"):
            oracle_name = "advisory_db"
        elif hints.get("declared_range") and hints.get("resolved_version"):
            oracle_name = "lockfile_resolver"
    oracle = ORACLES.get(oracle_name)
    if oracle is None:
        return VerifierCheckResult(name="external_oracle_lookup", result="unavailable", detail=f"oracle_missing:{oracle_name}")
    result = oracle(hints)
    if result.conclusion == "pass":
        return VerifierCheckResult(name="external_oracle_lookup", result="pass", detail=result.detail)
    if result.conclusion == "fail":
        return VerifierCheckResult(name="external_oracle_lookup", result="fail", detail=result.detail)
    return VerifierCheckResult(name="external_oracle_lookup", result="insufficient_static_evidence", detail=result.detail)


def cross_universe_probe(bundle: ContextBundle, witness_path: list[str], candidate: Candidate) -> VerifierCheckResult:
    required_pairs = {
        tuple(pair)
        for pair in candidate.detector_payload.raw.get("required_universe_pairs", [])
        if isinstance(pair, (list, tuple)) and len(pair) == 2
    }
    nodes = list(dict.fromkeys(witness_path or _candidate_witness_path(candidate)))
    witness_node_set = set(nodes)
    pairs = {
        (edge.source_universe, edge.target_universe)
        for edge in bundle.edge_facts
        if edge.source in witness_node_set and edge.target in witness_node_set
    }
    if not pairs and candidate.seam_edges:
        for seam in candidate.seam_edges:
            if seam.metadata.source_system and seam.metadata.target_system:
                pairs.add((str(seam.metadata.source_system), str(seam.metadata.target_system)))
    if not pairs:
        return VerifierCheckResult(name="cross_universe_edge_exists", result="unavailable")
    if not required_pairs or pairs & required_pairs:
        return VerifierCheckResult(name="cross_universe_edge_exists", result="pass", detail=f"pairs={sorted(pairs)}")
    return VerifierCheckResult(name="cross_universe_edge_exists", result="fail", detail=f"pairs={sorted(pairs)}")


def negation_probe(bundle: ContextBundle, candidate: Candidate) -> VerifierCheckResult:
    detector_name = _detector_name(candidate)
    anchors = _candidate_witness_path(candidate)
    if not anchors:
        return VerifierCheckResult(name="negation_witness", result="unavailable")
    if detector_name == "env-var-referenced-but-undefined":
        for node_id in anchors:
            node = bundle.node_facts.get(node_id)
            if node is not None and node.node_kind == "env_var":
                defined_edges = "DEFINED_BY_CONFIG" in node.incoming_relations
                if not defined_edges and not node.defined:
                    return VerifierCheckResult(name="negation_witness", result="pass", detail="env_var_has_no_definition_edge")
        return VerifierCheckResult(name="negation_witness", result="fail", detail="definition_edge_present")
    if detector_name == "env-var-defined-but-unused":
        for node_id in anchors:
            node = bundle.node_facts.get(node_id)
            if node is not None and node.node_kind == "env_var":
                reads = "READS_ENV_VAR" in node.incoming_relations
                return VerifierCheckResult(
                    name="negation_witness",
                    result="pass" if not reads else "fail",
                    detail="no_readers" if not reads else "readers_present",
                )
    return VerifierCheckResult(name="negation_witness", result="unavailable")


def version_satisfaction_probe(candidate: Candidate) -> VerifierCheckResult:
    meta = _detector_meta(candidate)
    hints = dict(meta.get("oracle_hints") or candidate.detector_payload.oracle_hints or {})
    if not hints.get("declared_range") or not hints.get("resolved_version"):
        return VerifierCheckResult(name="version_satisfaction", result="unavailable")
    oracle_name = "pep440" if str(hints.get("ecosystem") or "").lower() in {"pip", "python"} else "semver"
    result = ORACLES[oracle_name](hints)
    if result.conclusion == "pass":
        return VerifierCheckResult(name="version_satisfaction", result="pass", detail=result.detail)
    if result.conclusion == "fail":
        return VerifierCheckResult(name="version_satisfaction", result="fail", detail=result.detail)
    return VerifierCheckResult(name="version_satisfaction", result="insufficient_static_evidence", detail=result.detail)


def cross_language_cycle_probe(bundle: ContextBundle, candidate: Candidate) -> VerifierCheckResult:
    if bundle.on_cross_lang_cycle or bundle.cross_language_seams or candidate.seam_edges:
        return VerifierCheckResult(name="cross_language_cycle_witness", result="pass")
    return VerifierCheckResult(name="cross_language_cycle_witness", result="unavailable")


def seam_index_probe(candidate: Candidate) -> VerifierCheckResult:
    if candidate.seam_edges and all(edge.edge_id for edge in candidate.seam_edges):
        return VerifierCheckResult(name="seam_index_consistency", result="pass")
    return VerifierCheckResult(name="seam_index_consistency", result="unavailable")


def centrality_probe(bundle: ContextBundle, candidate: Candidate) -> VerifierCheckResult:
    if bundle.is_articulation_point or candidate.score.blast_radius_norm >= verifier_rules.ARCHITECTURE_BLAST_RADIUS_THRESHOLD:
        return VerifierCheckResult(name="centrality_witness", result="pass")
    if bundle.pagerank_percentile > 0.0:
        return VerifierCheckResult(name="centrality_witness", result="pass", detail=f"pagerank={bundle.pagerank_percentile:.4f}")
    return VerifierCheckResult(name="centrality_witness", result="unavailable")


def in_degree_probe(bundle: ContextBundle, candidate: Candidate) -> VerifierCheckResult:
    if bundle.callers or candidate.score.blast_radius_norm > 0.0:
        return VerifierCheckResult(name="in_degree_witness", result="pass")
    return VerifierCheckResult(name="in_degree_witness", result="unavailable")


def staleness_probe(bundle: ContextBundle) -> VerifierCheckResult:
    if bundle.callers:
        return VerifierCheckResult(name="staleness_witness", result="fail", detail="callers_present")
    if bundle.scope_node_id or bundle.scope_id:
        return VerifierCheckResult(name="staleness_witness", result="pass", detail="no_callers_observed")
    return VerifierCheckResult(name="staleness_witness", result="unavailable")


def manifest_overlap_probe(bundle: ContextBundle) -> VerifierCheckResult:
    if bundle.graph_distance_to_diff >= 0 or bundle.diff_anchors:
        return VerifierCheckResult(name="manifest_overlap", result="pass")
    return VerifierCheckResult(name="manifest_overlap", result="unavailable")


def source_snippet_probe(bundle: ContextBundle) -> VerifierCheckResult:
    if bundle.scope_text or any(snippet.text for snippet in bundle.code_snippets):
        return VerifierCheckResult(name="source_snippet", result="pass")
    return VerifierCheckResult(name="source_snippet", result="unavailable")


def cfg_path_probe(bundle: ContextBundle) -> VerifierCheckResult:
    if not bundle.cfg_available:
        return VerifierCheckResult(name="cfg_path_exists", result="unavailable")
    if bundle.cfg_summary or bundle.null_paths is not None:
        return VerifierCheckResult(name="cfg_path_exists", result="pass")
    return VerifierCheckResult(name="cfg_path_exists", result="fail", detail="cfg_bundle_missing_summary")


def taint_sql_probe(bundle: ContextBundle) -> VerifierCheckResult:
    for edge in bundle.taint_edges:
        blob = f"{edge.sink_pattern} {edge.source_chain}".lower()
        if "sql" in blob or "select" in blob or "insert" in blob or "db" in blob:
            return VerifierCheckResult(name="taint_sinks_sql", result="pass")
    return VerifierCheckResult(name="taint_sinks_sql", result="unavailable")


def taint_subprocess_probe(bundle: ContextBundle) -> VerifierCheckResult:
    for edge in bundle.taint_edges:
        blob = f"{edge.sink_pattern} {edge.source_chain}".lower()
        if "exec" in blob or "subprocess" in blob or "system" in blob:
            return VerifierCheckResult(name="taint_sinks_subprocess", result="pass")
    return VerifierCheckResult(name="taint_sinks_subprocess", result="unavailable")


def dfg_probe(bundle: ContextBundle) -> VerifierCheckResult:
    if bundle.dfg_available:
        return VerifierCheckResult(name="dfg_witness", result="pass")
    return VerifierCheckResult(name="dfg_witness", result="unavailable")


def dfg_def_use_probe(bundle: ContextBundle) -> VerifierCheckResult:
    if bundle.dfg_available:
        return VerifierCheckResult(name="dfg_def_before_use", result="pass")
    return VerifierCheckResult(name="dfg_def_before_use", result="unavailable")


def static_pattern_probe(bundle: ContextBundle, candidate: Candidate) -> VerifierCheckResult:
    if bundle.scope_text or candidate.detector_payload.raw:
        return VerifierCheckResult(name="static_pattern", result="pass")
    return VerifierCheckResult(name="static_pattern", result="unavailable")


def router_context_probe(bundle: ContextBundle, candidate: Candidate) -> VerifierCheckResult:
    blob = " ".join(
        [
            bundle.scope_id,
            bundle.scope_node_id,
            bundle.scope_text,
            str(candidate.detector_payload.raw),
        ]
    ).lower()
    if any(token in blob for token in ("route", "router", "middleware", "auth")):
        return VerifierCheckResult(name="router_context", result="pass")
    return VerifierCheckResult(name="router_context", result="unavailable")


def sudo_pattern_probe(bundle: ContextBundle, candidate: Candidate) -> VerifierCheckResult:
    blob = f"{bundle.scope_text} {candidate.detector_payload.raw}".lower()
    if any(token in blob for token in ("sudo", "setuid", "seteuid", "chmod 4755")):
        return VerifierCheckResult(name="sudo_pattern", result="pass")
    return VerifierCheckResult(name="sudo_pattern", result="unavailable")


def graph_context_probe(bundle: ContextBundle) -> VerifierCheckResult:
    if bundle.callers or bundle.callees or bundle.cross_language_seams:
        return VerifierCheckResult(name="graph_context", result="pass")
    return VerifierCheckResult(name="graph_context", result="unavailable")


def free_delete_probe(bundle: ContextBundle, candidate: Candidate) -> VerifierCheckResult:
    blob = f"{bundle.scope_text} {candidate.detector_payload.raw}".lower()
    if "free(" in blob or "delete " in blob:
        return VerifierCheckResult(name="free_delete_pattern", result="pass")
    return VerifierCheckResult(name="free_delete_pattern", result="unavailable")


def bitshift_probe(bundle: ContextBundle, candidate: Candidate) -> VerifierCheckResult:
    blob = f"{bundle.scope_text} {candidate.detector_payload.raw}".lower()
    if "<<" in blob or "math.imul" in blob or "0x" in blob:
        return VerifierCheckResult(name="bitshift_pattern", result="pass")
    return VerifierCheckResult(name="bitshift_pattern", result="unavailable")


def arithmetic_probe(bundle: ContextBundle) -> VerifierCheckResult:
    if bundle.scope_text:
        return VerifierCheckResult(name="arithmetic_witness", result="pass")
    return VerifierCheckResult(name="arithmetic_witness", result="unavailable")


def async_await_probe(bundle: ContextBundle, candidate: Candidate) -> VerifierCheckResult:
    blob = f"{bundle.scope_text} {candidate.detector_payload.raw}".lower()
    if "async" in blob or "await" in blob:
        return VerifierCheckResult(name="async_await", result="pass")
    return VerifierCheckResult(name="async_await", result="unavailable")


def shared_mutation_probe(bundle: ContextBundle, candidate: Candidate) -> VerifierCheckResult:
    blob = f"{bundle.scope_text} {candidate.detector_payload.raw}"
    if any(token in blob for token in ("+=", "-=", "++", "--", ".push(")):
        return VerifierCheckResult(name="shared_mutation", result="pass")
    return VerifierCheckResult(name="shared_mutation", result="unavailable")


def _mechanical_probes(
    *,
    bundle: ContextBundle,
    candidate: Candidate,
    witness_path: list[str],
    config: IntelligenceConfig,
    full_repo_scan: bool,
) -> dict[str, Probe]:
    cited_tables = sorted(bundle.rls_coverage.keys())
    return {
        "graph_path_exists": lambda: graph_path_probe(bundle, witness_path),
        "edge_confidence_floor": lambda: edge_confidence_probe(
            bundle,
            witness_path,
            floor=config.verifier.min_edge_confidence_for_confirmed,
            inferred_floor_applied=full_repo_scan,
        ),
        "rls_awareness": lambda: rls_awareness_probe(bundle, candidate),
        "migration_branch_state": lambda: migration_branch_probe(bundle, cited_tables),
        "payload_contract": lambda: payload_contract_probe(bundle, witness_path),
        "phantom_anchor_short_circuit": lambda: phantom_anchor_probe(
            candidate,
            witness_path,
            enabled=config.verifier.phantom_anchor_short_circuit,
        ),
        "external_oracle_lookup": lambda: external_oracle_probe(candidate),
        "cross_universe_edge_exists": lambda: cross_universe_probe(bundle, witness_path, candidate),
        "negation_witness": lambda: negation_probe(bundle, candidate),
        "version_satisfaction": lambda: version_satisfaction_probe(candidate),
        "cross_language_cycle_witness": lambda: cross_language_cycle_probe(bundle, candidate),
        "seam_index_consistency": lambda: seam_index_probe(candidate),
        "centrality_witness": lambda: centrality_probe(bundle, candidate),
        "in_degree_witness": lambda: in_degree_probe(bundle, candidate),
        "staleness_witness": lambda: staleness_probe(bundle),
        "manifest_overlap": lambda: manifest_overlap_probe(bundle),
        "source_snippet": lambda: source_snippet_probe(bundle),
        "cfg_path_exists": lambda: cfg_path_probe(bundle),
        "taint_sinks_sql": lambda: taint_sql_probe(bundle),
        "taint_sinks_subprocess": lambda: taint_subprocess_probe(bundle),
        "dfg_witness": lambda: dfg_probe(bundle),
        "dfg_def_before_use": lambda: dfg_def_use_probe(bundle),
        "static_pattern": lambda: static_pattern_probe(bundle, candidate),
        "router_context": lambda: router_context_probe(bundle, candidate),
        "sudo_pattern": lambda: sudo_pattern_probe(bundle, candidate),
        "graph_context": lambda: graph_context_probe(bundle),
        "free_delete_pattern": lambda: free_delete_probe(bundle, candidate),
        "bitshift_pattern": lambda: bitshift_probe(bundle, candidate),
        "arithmetic_witness": lambda: arithmetic_probe(bundle),
        "async_await": lambda: async_await_probe(bundle, candidate),
        "shared_mutation": lambda: shared_mutation_probe(bundle, candidate),
    }


def _mechanical_outcome(probe_results: list[VerifierCheckResult], *, mechanical: bool = False) -> VerifierOutcome:
    executed = sum(1 for probe in probe_results if probe.result in {"pass", "fail", "invalid", "rls_covered", "rls_partial"})
    passes = sum(1 for probe in probe_results if probe.result == "pass")
    fails = sum(1 for probe in probe_results if probe.result in {"fail", "invalid"})
    if mechanical and passes >= 1 and fails == 0:
        return VerifierOutcome.confirmed
    if fails >= 2:
        return VerifierOutcome.invalid_reasoning
    if fails == 1 and passes >= 2 and executed >= 2:
        return VerifierOutcome.partially_confirmed
    if passes >= 3 and executed >= 2:
        return VerifierOutcome.confirmed
    if passes == 0 and executed >= 1:
        return VerifierOutcome.unconfirmed
    if passes >= 1 and executed >= 2:
        return VerifierOutcome.partially_confirmed
    return VerifierOutcome.unconfirmed


def _rule_text_blob(
    *,
    candidate: Candidate,
    bug_type: str,
    description: str,
    missing_guard: str | None,
    witness_path: list[str],
) -> str:
    parts = [
        description,
        bug_type,
        missing_guard or "",
        " ".join(witness_path),
        str(candidate.detector_payload.raw),
        str(candidate.detector_payload.oracle_hints),
    ]
    return " ".join(part for part in parts if part).lower()


def _condition_matches(
    condition: str,
    *,
    uncited: bool,
    bundle: ContextBundle,
    narrative: str,
) -> bool:
    lowered = condition.strip().lower()
    if lowered == "llm output contains no bundle node/edge citation":
        return uncited
    if lowered == "cfg_available is false":
        return not bundle.cfg_available
    if "full alias analysis" in lowered:
        return "alias analysis" in narrative
    if "dynamic dispatch" in lowered or "reflection" in lowered:
        return "dynamic dispatch" in narrative or "reflection" in narrative
    if "inter-procedural cfg" in lowered:
        return "inter-procedural cfg" in narrative or "interprocedural cfg" in narrative
    if "heap object identity" in lowered:
        return "heap object identity" in narrative
    if "unmodeled sanitizer" in lowered:
        return "unmodeled sanitizer" in narrative or "unknown sanitizer" in narrative
    return False


def _score_dimension_gaps(
    *,
    rule: verifier_rules.VerifierRule,
    candidate: Candidate,
    bundle: ContextBundle,
) -> list[str]:
    gaps: list[str] = []
    for key, expected in rule.required_score_dimensions.items():
        if hasattr(candidate.score, key):
            actual = getattr(candidate.score, key)
        elif hasattr(bundle, key):
            actual = getattr(bundle, key)
        else:
            actual = None
        if actual != expected:
            gaps.append(str(key))
    return gaps


def _bundle_evidence_gaps(
    *,
    rule: verifier_rules.VerifierRule,
    candidate: Candidate,
    bundle: ContextBundle,
) -> list[str]:
    gaps: list[str] = []
    for requirement in rule.required_bundle_evidence:
        if requirement == "taint_edges":
            satisfied = bool(bundle.taint_edges)
        elif requirement == "taint_sources_in_bundle":
            satisfied = bool(bundle.taint_edges) and any(
                edge.source_node in bundle.node_facts for edge in bundle.taint_edges
            )
        elif requirement == "taint_sinks_in_bundle":
            satisfied = bool(bundle.taint_edges) and any(
                edge.sink_node in bundle.node_facts for edge in bundle.taint_edges
            )
        elif requirement == "is_articulation_point_or_blast_radius_above_threshold":
            satisfied = bundle.is_articulation_point or (
                candidate.score.blast_radius_norm >= verifier_rules.ARCHITECTURE_BLAST_RADIUS_THRESHOLD
            )
        elif requirement == "cfg_summary":
            satisfied = bool(bundle.cfg_summary or bundle.null_paths)
        else:
            satisfied = bool(getattr(bundle, requirement, None))
        if not satisfied:
            gaps.append(requirement)
    return gaps


def _finding_shape(
    *,
    candidate: Candidate,
    bundle: ContextBundle,
    mode: ReasonerMode | None,
    finding: ModeAFinding | ModeBFinding | ModeCFinding | None,
) -> tuple[str, str, float, str | None, list[str], str, bool]:
    witness_path: list[str] = _candidate_witness_path(candidate)
    if isinstance(finding, ModeAFinding):
        witness_path = list(finding.affected_path or []) + list(finding.graph_anchor_nodes or [])
        bug_type = finding.bug_type
        description = finding.description
        confidence = float(finding.confidence)
        missing_guard = None
    elif isinstance(finding, ModeBFinding):
        witness_path = list(finding.graph_anchor_nodes or [])
        bug_type = finding.violation_type
        description = f"{finding.description} (A={finding.component_a}, B={finding.component_b})"
        confidence = float(finding.confidence)
        missing_guard = None
    elif isinstance(finding, ModeCFinding):
        witness_path = list(finding.violating_path or []) + list(finding.graph_anchor_nodes or [])
        bug_type = finding.flow_bug_type
        description = finding.description
        confidence = float(finding.confidence)
        missing_guard = finding.missing_guard
    else:
        raw = candidate.detector_payload.raw
        bug_type = str(raw.get("anomaly") or raw.get("surface_type") or _detector_name(candidate))
        description = str(raw.get("description") or bug_type.replace("_", " ").replace("-", " "))
        confidence = 1.0
        missing_guard = str(raw.get("missing_guard") or "") or None
    evidence_text = f"{description} {bug_type} {' '.join(witness_path)} {missing_guard or ''}".strip()
    uncited = bool(mode is not None) and (not evidence_cites_bundle(evidence_text, bundle))
    return bug_type, description, confidence, missing_guard, witness_path, evidence_text, uncited


def _common_finding(
    *,
    candidate: Candidate,
    bundle: ContextBundle,
    mode: ReasonerMode | None,
    outcome: VerifierOutcome,
    bug_type: str,
    description: str,
    confidence: float,
    missing_guard: str | None,
    witness_path: list[str],
    evidence_text: str,
    uncited: bool,
    probe_results: list[VerifierCheckResult],
) -> tuple[VerifierAuditEntry, Finding]:
    mode_label = mode.value if mode is not None else "na"
    finding_id = f"{candidate.candidate_id}:{mode_label}:{bug_type}"[:96]
    audit = VerifierAuditEntry(
        finding_id=finding_id,
        verifier_outcome=outcome,
        checks_run=probe_results,
        inferred_edge_confidence_floor_applied=False,
        pack_manifest_id=bundle.pack_manifest.manifest_id,
        reasoner_mode=mode,
    )

    rls_verdict: RLSCoverage | None = None
    for cov in bundle.rls_coverage.values():
        if cov in {
            RLSCoverage.full,
            RLSCoverage.partial_operation,
            RLSCoverage.partial_predicate,
            RLSCoverage.context_mismatch,
            RLSCoverage.none,
        }:
            rls_verdict = cov
            break

    affected: list[str] = []
    if isinstance(mode, ReasonerMode) and mode == ReasonerMode.B:
        affected = witness_path[:2]
    elif witness_path:
        affected = witness_path[:4]

    out_finding = Finding(
        finding_id=finding_id,
        trust_level=outcome,
        mode=mode,
        verifier_outcome=outcome,
        bug_type=bug_type,
        description=description,
        affected_components=affected,
        witness_path=witness_path,
        missing_guard=missing_guard,
        reasoner_confidence=confidence,
        ranking_phase=0,
        verifier_checks_passed=[probe.name for probe in probe_results if probe.result == "pass"],
        verifier_checks_inconclusive=[
            probe.name
            for probe in probe_results
            if probe.result in {"unavailable", "insufficient_static_evidence", "rls_partial"}
        ],
        rls_verdict=rls_verdict,
        pack_manifest_id=bundle.pack_manifest.manifest_id,
        detector_name=_detector_name(candidate),
        detector_version=str(_detector_meta(candidate).get("detector_version") or "0"),
        pipeline_version=str(_detector_meta(candidate).get("pipeline_version") or "0"),
        severity=str(_detector_meta(candidate).get("severity") or "medium"),
        uncited=uncited,
        evidence_text=evidence_text,
    )
    if outcome == VerifierOutcome.partially_confirmed:
        out_finding.partially_confirmed_caveat = (
            "Verifier routed this finding to gray-zone review because deterministic evidence was incomplete."
        )
    return audit, out_finding


def _verify_mechanical(
    *,
    candidate: Candidate,
    bundle: ContextBundle,
    config: IntelligenceConfig,
    full_repo_scan: bool,
) -> tuple[VerifierAuditEntry, Finding]:
    spec = _detector_spec(candidate)
    bug_type, description, confidence, missing_guard, witness_path, evidence_text, uncited = _finding_shape(
        candidate=candidate,
        bundle=bundle,
        mode=None,
        finding=None,
    )
    requested = list(spec.verifier_checks) if spec is not None else [
        "graph_path_exists",
        "edge_confidence_floor",
        "rls_awareness",
        "migration_branch_state",
        "payload_contract",
        "phantom_anchor_short_circuit",
    ]
    probes = _mechanical_probes(
        bundle=bundle,
        candidate=candidate,
        witness_path=witness_path,
        config=config,
        full_repo_scan=full_repo_scan,
    )
    probe_results: list[VerifierCheckResult] = []
    for probe_name in requested:
        runner = probes.get(probe_name)
        if runner is None:
            probe_results.append(VerifierCheckResult(name=probe_name, result="unavailable", detail="unsupported_probe"))
            continue
        probe_results.append(_safe_probe(probe_name, runner))
    outcome = _mechanical_outcome(
        probe_results,
        mechanical=bool(spec is not None and not spec.requires_reasoner),
    )
    audit, out_finding = _common_finding(
        candidate=candidate,
        bundle=bundle,
        mode=None,
        outcome=outcome,
        bug_type=bug_type,
        description=description,
        confidence=confidence,
        missing_guard=missing_guard,
        witness_path=witness_path,
        evidence_text=evidence_text,
        uncited=uncited,
        probe_results=probe_results,
    )
    audit.inferred_edge_confidence_floor_applied = full_repo_scan
    if outcome == VerifierOutcome.partially_confirmed:
        out_finding.partially_confirmed_caveat = (
            "Verifier confirmed some but not all structural probes; treat as suggestive, not proof."
        )
    return audit, out_finding


def _verify_reasoner_finding(
    *,
    candidate: Candidate,
    bundle: ContextBundle,
    mode: ReasonerMode,
    finding: ModeAFinding | ModeBFinding | ModeCFinding,
) -> tuple[VerifierAuditEntry, Finding]:
    bug_type, description, confidence, missing_guard, witness_path, evidence_text, uncited = _finding_shape(
        candidate=candidate,
        bundle=bundle,
        mode=mode,
        finding=finding,
    )
    narrative = _rule_text_blob(
        candidate=candidate,
        bug_type=bug_type,
        description=description,
        missing_guard=missing_guard,
        witness_path=witness_path,
    )
    detector_name = _detector_name(candidate)
    probe_results: list[VerifierCheckResult] = []

    global_hits = [
        condition
        for condition in verifier_rules.GLOBAL_AUTO_GRAYZONE
        if _condition_matches(condition, uncited=uncited, bundle=bundle, narrative=narrative)
    ]
    probe_results.append(
        VerifierCheckResult(
            name="global_auto_grayzone",
            result="fail" if global_hits else "pass",
            detail="; ".join(global_hits),
        )
    )
    if global_hits:
        outcome = VerifierOutcome.partially_confirmed
        audit, out_finding = _common_finding(
            candidate=candidate,
            bundle=bundle,
            mode=mode,
            outcome=outcome,
            bug_type=bug_type,
            description=description,
            confidence=confidence,
            missing_guard=missing_guard,
            witness_path=witness_path,
            evidence_text=evidence_text,
            uncited=uncited,
            probe_results=probe_results,
        )
        audit.failed_rule = global_hits[0]
        return audit, out_finding

    category = verifier_rules.resolve_finding_category(detector_name=detector_name, bug_type=bug_type)
    probe_results.append(
        VerifierCheckResult(
            name="verifier_category",
            result="pass" if category is not None else "fail",
            detail=str(category or "unknown_category"),
        )
    )
    if category is None:
        outcome = VerifierOutcome.unconfirmed
        audit, out_finding = _common_finding(
            candidate=candidate,
            bundle=bundle,
            mode=mode,
            outcome=outcome,
            bug_type=bug_type,
            description=description,
            confidence=confidence,
            missing_guard=missing_guard,
            witness_path=witness_path,
            evidence_text=evidence_text,
            uncited=uncited,
            probe_results=probe_results,
        )
        audit.failed_rule = "unknown_finding_category"
        return audit, out_finding

    rule = verifier_rules.VERIFIER_RULES[category]
    rule_auto_hits = [
        condition
        for condition in rule.auto_grayzone_conditions
        if _condition_matches(condition, uncited=uncited, bundle=bundle, narrative=narrative)
    ]
    probe_results.append(
        VerifierCheckResult(
            name="rule_auto_grayzone",
            result="fail" if rule_auto_hits else "pass",
            detail="; ".join(rule_auto_hits),
        )
    )
    if rule_auto_hits:
        outcome = VerifierOutcome.partially_confirmed
        audit, out_finding = _common_finding(
            candidate=candidate,
            bundle=bundle,
            mode=mode,
            outcome=outcome,
            bug_type=bug_type,
            description=description,
            confidence=confidence,
            missing_guard=missing_guard,
            witness_path=witness_path,
            evidence_text=evidence_text,
            uncited=uncited,
            probe_results=probe_results,
        )
        audit.failed_rule = rule_auto_hits[0]
        return audit, out_finding

    score_gaps = _score_dimension_gaps(rule=rule, candidate=candidate, bundle=bundle)
    bundle_gaps = _bundle_evidence_gaps(rule=rule, candidate=candidate, bundle=bundle)
    probe_results.append(
        VerifierCheckResult(
            name="rule_score_dimensions",
            result="fail" if score_gaps else "pass",
            detail=", ".join(score_gaps),
        )
    )
    probe_results.append(
        VerifierCheckResult(
            name="rule_bundle_evidence",
            result="fail" if bundle_gaps else "pass",
            detail=", ".join(bundle_gaps),
        )
    )

    missing = [*score_gaps, *bundle_gaps]
    outcome = VerifierOutcome.confirmed if not missing else VerifierOutcome.unconfirmed
    audit, out_finding = _common_finding(
        candidate=candidate,
        bundle=bundle,
        mode=mode,
        outcome=outcome,
        bug_type=bug_type,
        description=description,
        confidence=confidence,
        missing_guard=missing_guard,
        witness_path=witness_path,
        evidence_text=evidence_text,
        uncited=uncited,
        probe_results=probe_results,
    )
    if missing:
        audit.failed_rule = missing[0]
        audit.missing_evidence = missing
    return audit, out_finding


def verify(
    *,
    candidate: Candidate,
    bundle: ContextBundle,
    mode: ReasonerMode | None,
    finding: ModeAFinding | ModeBFinding | ModeCFinding | None,
    config: IntelligenceConfig,
    full_repo_scan: bool,
) -> tuple[VerifierAuditEntry, Finding]:
    if mode is None or finding is None:
        return _verify_mechanical(
            candidate=candidate,
            bundle=bundle,
            config=config,
            full_repo_scan=full_repo_scan,
        )
    return _verify_reasoner_finding(
        candidate=candidate,
        bundle=bundle,
        mode=mode,
        finding=finding,
    )


def verify_all(
    *,
    candidate: Candidate,
    bundle: ContextBundle,
    reasoner_outputs: dict[ReasonerMode, Any],
    config: IntelligenceConfig,
    full_repo_scan: bool,
    deterministic_only: bool = False,
) -> tuple[list[VerifierAuditEntry], list[Finding]]:
    audits: list[VerifierAuditEntry] = []
    findings: list[Finding] = []
    spec = _detector_spec(candidate)
    if (not reasoner_outputs) and spec is not None and (
        not spec.requires_reasoner or deterministic_only
    ):
        audit, finding = verify(
            candidate=candidate,
            bundle=bundle,
            mode=None,
            finding=None,
            config=config,
            full_repo_scan=full_repo_scan,
        )
        audits.append(audit)
        findings.append(finding)
        return audits, findings
    for mode, output in reasoner_outputs.items():
        raw_findings: Iterable[Any]
        if isinstance(output, ModeAOutput):
            raw_findings = output.findings
        elif isinstance(output, ModeBOutput):
            raw_findings = output.findings
        elif isinstance(output, ModeCOutput):
            raw_findings = output.findings
        else:
            continue
        for raw in raw_findings:
            audit, finding = verify(
                candidate=candidate,
                bundle=bundle,
                mode=mode,
                finding=raw,
                config=config,
                full_repo_scan=full_repo_scan,
            )
            audits.append(audit)
            findings.append(finding)
    return audits, findings


def verify_staged(
    audits: list[VerifierAuditEntry],
    *,
    bundle: ContextBundle,
    cache: SourceSnippetCache | None = None,
) -> list[VerifierAuditEntry]:
    """Attach advisory staged verifier metadata without changing outcomes."""

    cache = cache or SourceSnippetCache()
    source_checks = _source_stage_results(bundle, cache)
    for audit in audits:
        checks = list(audit.checks_run)
        pass_count = sum(1 for check in checks if check.result in {"pass", "rls_covered"})
        fail_count = sum(1 for check in checks if check.result in {"fail", "invalid"})
        unavailable_count = sum(1 for check in checks if check.result in {"unavailable", "insufficient_static_evidence"})
        stage_results = [
            VerifierStageResult(
                stage="legacy_rules",
                result="fail" if fail_count else "pass" if pass_count else "unavailable",
                detail=f"pass={pass_count} fail={fail_count} unavailable={unavailable_count}",
            ),
            *source_checks,
        ]
        audit.stage_results = stage_results
        if fail_count:
            audit.advisory_validity = "invalid"
            audit.advisory_reason = "legacy verifier checks failed"
        elif any(stage.result == "fail" for stage in source_checks):
            audit.advisory_validity = "needs_review"
            audit.advisory_reason = "source evidence could not be validated"
        elif pass_count or any(stage.result == "pass" for stage in source_checks):
            audit.advisory_validity = "valid"
            audit.advisory_reason = "advisory stages passed"
        else:
            audit.advisory_validity = "unknown"
            audit.advisory_reason = "no advisory stages were conclusive"
    return audits


def _source_stage_results(
    bundle: ContextBundle,
    cache: SourceSnippetCache,
) -> list[VerifierStageResult]:
    if not bundle.code_snippets:
        return [VerifierStageResult(stage="source_snippets", result="unavailable", detail="no snippets")]
    results: list[VerifierStageResult] = []
    for snippet in bundle.code_snippets[:5]:
        if not snippet.source_file:
            results.append(
                VerifierStageResult(
                    stage="source_snippets",
                    result="unavailable",
                    detail=f"{snippet.node_id}: no source_file",
                )
            )
            continue
        try:
            text = cache.read(snippet.source_file, snippet.start_line, snippet.end_line)
        except OSError as exc:
            results.append(
                VerifierStageResult(
                    stage="source_snippets",
                    result="fail",
                    detail=f"{snippet.node_id}: {exc.__class__.__name__}",
                )
            )
            continue
        results.append(
            VerifierStageResult(
                stage="source_snippets",
                result="pass" if text.strip() else "unavailable",
                detail=f"{snippet.node_id}: read {len(text)} chars",
            )
        )
    return results


__all__ = ["verify", "verify_all"]
