from __future__ import annotations

from depos.analysis.schemas import Candidate, CandidateScore, SeedType


def test_candidate_accepts_language_path_field() -> None:
    candidate = Candidate(
        candidate_id="test",
        scope_id="test",
        seed_type=SeedType.graph_anomaly,
        score=CandidateScore(),
        detector_payload={},
        language_path=["python", "rust"],
    )

    assert candidate.language_path == ["python", "rust"]
