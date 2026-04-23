"""Typed verifier rules — registry and global gray-zone hooks for :func:`depos.analysis.verifier.verify`."""
from __future__ import annotations

from typing import Any, Callable

import networkx as nx

from depos.analysis.citations import evidence_cites_bundle
from depos.analysis.schemas import Candidate, ContextBundle

VERIFIER_RULES: dict[str, str] = {
    "llm_cites_bundle": "LLM output contains no bundle node/edge citation in the evidence string.",
    "auto_grayzone_uncited": "Reasoner text did not cite any bundle id (global auto gray-zone).",
}


def auto_grayzone_uncited(
    graph: nx.DiGraph,
    candidate: Candidate,
    bundle: ContextBundle,
    evidence_text: str,
) -> bool:
    if not (evidence_text and str(evidence_text).strip()):
        return False
    return not evidence_cites_bundle(str(evidence_text), bundle)


# Predicates: return True to append a failed auto_grayzone check (downgrades outcome).
GLOBAL_AUTO_GRAYZONE: list[Callable[..., bool]] = [auto_grayzone_uncited]


def register_rule(name: str, rule: Any) -> None:
    VERIFIER_RULES[name] = rule


__all__ = [
    "GLOBAL_AUTO_GRAYZONE",
    "VERIFIER_RULES",
    "auto_grayzone_uncited",
    "register_rule",
]
