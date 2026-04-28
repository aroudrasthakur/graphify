from __future__ import annotations

from depos.analysis.schemas import SeamEdge


def test_seam_edge_risk_scores_contract_verification() -> None:
    contracted = SeamEdge(
        edge_id="a->b",
        source="a",
        target="b",
        relation="ffi_call",
        source_language="python",
        target_language="rust",
        pattern="ffi",
        contract_defined=True,
        contract_verified=True,
    )
    unknown = SeamEdge(
        edge_id="c->d",
        source="c",
        target="d",
        relation="dynamic",
        source_language="python",
        target_language="javascript",
        pattern="unknown",
    )

    assert contracted.risk < unknown.risk
    assert unknown.risk == 0.85
    assert contracted.risk == 0.9 * 0.4
