from __future__ import annotations

from depos.analysis.detectors import register
from depos.analysis.detectors.builtin.common import simple_spec
from depos.analysis.detectors.pattern_matcher import (
    PatternSourceCache,
    collect_pattern_scopes,
    pattern_match_to_candidate,
    run_pattern_rule,
)
from depos.analysis.detectors.pattern_registry import ENV_VAR_REFERENCED_BUT_UNDEFINED
from depos.analysis.schemas import Universe


SPEC = simple_spec(
    name="env-var-referenced-but-undefined",
    universe=Universe.env,
    verifier_checks=["graph_path_exists", "negation_witness", "cross_universe_edge_exists"],
    requires_reasoner=False,
    severity="high",
    semantic_requirement=None,)


def run(graph, manifest, mode, config, ctx):
    rule = ENV_VAR_REFERENCED_BUT_UNDEFINED
    rctx = ctx.get("run_context")
    scopes = collect_pattern_scopes(graph, rule)
    source_cache = PatternSourceCache(repo_root=getattr(rctx, "repo_root", None))
    candidates = []
    for match in run_pattern_rule(graph, source_cache, rule, scopes, ctx):
        env_name = match.metavars.get("ENV") or (
            graph.nodes[match.scope.node_id].get("name")
            if match.scope.node_id and graph.has_node(match.scope.node_id)
            else match.scope.scope_id
        )
        readers = [node_id for node_id in match.node_ids if node_id != match.scope.node_id]
        candidates.append(
            pattern_match_to_candidate(
                match.model_copy(update={"confidence": 0.82}),
                rule,
                mode=mode,
                config=config,
                graph=graph,
                run_context=rctx,
                extra={
                    "env_var": env_name,
                    "readers": readers,
                    "missing_evidence": [],
                    "required_universe_pairs": [("code", "env")],
                },
            )
        )
    return candidates


register(SPEC, run)
