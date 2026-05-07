from __future__ import annotations

from depos.analysis.candidate_identifier import _lexical_keyword_candidates
from depos.analysis.detectors import register
from depos.analysis.detectors.builtin.common import simple_spec
from depos.analysis.embedding_seed import embedding_seed_candidates
from depos.analysis.schemas import Universe


SPEC = simple_spec(
    name="lexical-keyword-seed",
    universe=Universe.code,
    verifier_checks=["graph_path_exists"],
    requires_reasoner=True,
    severity="low",
    semantic_requirement=None,
)


def run(graph, manifest, mode, config, ctx):
    seeds = _lexical_keyword_candidates(graph, config, mode, ctx=ctx)
    if getattr(config, "enable_embedding_seeds", False):
        seeds.extend(embedding_seed_candidates(graph, config, mode, ctx=ctx))
    return seeds


register(SPEC, run)
