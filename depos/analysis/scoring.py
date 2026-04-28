"""Deterministic ``CandidateScore.composite`` from vector dimensions + config weights."""
from __future__ import annotations

from typing import TYPE_CHECKING

from depos.analysis.schemas import AnalysisMode, CandidateScore

if TYPE_CHECKING:
    from depos.analysis.config import IntelligenceConfig

SEVERITY_CONFIDENCE_PRIOR: dict[str, float] = {
    "info": 0.35,
    "low": 0.50,
    "medium": 0.65,
    "high": 0.82,
    "critical": 0.95,
}
SEVERITY_CONFIDENCE_BLEND = 0.25

WEIGHTS_DEFAULT: dict[str, dict[str, float]] = {
    AnalysisMode.diff_aware.value: {
        "structural_centrality": 0.10,
        "seam_exposure": 0.20,
        "change_proximity": 0.25,
        "detector_confidence": 0.20,
        "evidence_quality": 0.15,
        "taint_chain_present": 0.05,
        "blast_radius_norm": 0.05,
    },
    AnalysisMode.full_repo_scan.value: {
        "structural_centrality": 0.15,
        "seam_exposure": 0.20,
        "change_proximity": 0.15,
        "detector_confidence": 0.20,
        "evidence_quality": 0.20,
        "taint_chain_present": 0.05,
        "blast_radius_norm": 0.05,
    },
}


def _clamp01(value: object) -> float:
    number = float(value)
    if number != number or number <= 0.0:
        return 0.0
    if number >= 1.0:
        return 1.0
    return number


def _validate_weights(weights_by_mode: dict[str, dict[str, float]]) -> None:
    for mode, weights in weights_by_mode.items():
        if abs(sum(float(weight) for weight in weights.values()) - 1.0) > 1e-9:
            raise ValueError(f"CandidateScore weights for {mode!r} must sum to 1.0")


_validate_weights(WEIGHTS_DEFAULT)


def calibrate_detector_confidence(confidence: float, severity: str | None = None) -> float:
    confidence = _clamp01(float(confidence))
    if severity is None:
        return confidence
    prior = SEVERITY_CONFIDENCE_PRIOR.get(str(severity).lower())
    if prior is None:
        return confidence
    return (confidence * (1.0 - SEVERITY_CONFIDENCE_BLEND)) + (prior * SEVERITY_CONFIDENCE_BLEND)


def compute_composite(
    score: CandidateScore,
    *,
    mode: AnalysisMode,
    config: "IntelligenceConfig | None" = None,
    severity: str | None = None,
) -> float:
    """Weighted sum of score dimensions; result is written to ``score.composite``."""
    key = mode.value
    wmap: dict[str, float]
    if config is not None and getattr(config, "scoring", None) is not None and config.scoring.weights.get(key):
        wmap = config.scoring.weights[key]
    else:
        wmap = WEIGHTS_DEFAULT.get(key) or next(iter(WEIGHTS_DEFAULT.values()))
    total = 0.0
    for k, w in wmap.items():
        if k == "composite":
            continue
        value = (
            calibrate_detector_confidence(score.detector_confidence, severity)
            if k == "detector_confidence"
            else getattr(score, k, None)
        )
        if value is not None:
            total += float(value) * float(w)
    return _clamp01(total)


def apply_composite(
    score: CandidateScore,
    *,
    mode: AnalysisMode,
    config: "IntelligenceConfig | None" = None,
    severity: str | None = None,
) -> CandidateScore:
    score.composite = compute_composite(score, mode=mode, config=config, severity=severity)
    return score
