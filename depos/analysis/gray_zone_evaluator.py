"""Module 7 — gray zone evaluator.

Handles findings that the verifier left in an ambiguous state. After
Stage 6 closure the evaluator consumes finding, audit, and bundle data
only; it never reads the graph directly.

Each panel role (A/B/C) calls the configured LLM with a role-specific prompt
when the resolved provider is not :class:`StubProvider`. Provider resolution
uses :data:`GrayZoneConfig.model_*_provider` when set; otherwise it inherits
``IntelligenceConfig.llm.provider`` so a run configured for Ollama does not
default the panel to ``gemma`` (which becomes a stub when ``GEMMA_API_URL`` is
unset). On LLM failure or non-JSON replies, votes fall back to
:func:`_heuristic_panel_vote`.
"""
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Iterable

from depos.analysis.config import IntelligenceConfig
from depos.analysis.reasoning_engine import StubProvider, get_provider
from depos.analysis.schemas import (
    ContextBundle,
    Finding,
    GrayZoneAuditRow,
    GrayZoneEntryReason,
    GrayZoneVote,
    GrayZoneVoteOutcome,
    ReasonerMode,
    RLSCoverage,
    VerifierAuditEntry,
    VerifierOutcome,
)


def _pass_count(audit: VerifierAuditEntry) -> int:
    return sum(1 for check in audit.checks_run if check.result == "pass")


def _fail_count(audit: VerifierAuditEntry) -> int:
    return sum(1 for check in audit.checks_run if check.result == "fail")


def _all_inferred_edges(audit: VerifierAuditEntry) -> bool:
    for check in audit.checks_run:
        if check.name == "edge_confidence_floor" and "all_inferred=true" in check.detail:
            return True
    return False


def _classify_entry_reason(
    finding: Finding,
    audit: VerifierAuditEntry,
    *,
    run_low_stitcher_coverage: bool,
    unconfirmed_threshold: float,
) -> GrayZoneEntryReason | None:
    passes = _pass_count(audit)
    if audit.verifier_outcome == VerifierOutcome.partially_confirmed and passes <= 1:
        return GrayZoneEntryReason.partially_confirmed_1_check
    if audit.verifier_outcome == VerifierOutcome.unconfirmed and finding.reasoner_confidence >= unconfirmed_threshold:
        return GrayZoneEntryReason.unconfirmed_high_confidence
    if _all_inferred_edges(audit):
        return GrayZoneEntryReason.all_inferred_edges
    if finding.rls_verdict == RLSCoverage.context_mismatch:
        return GrayZoneEntryReason.rls_context_mismatch
    if run_low_stitcher_coverage:
        return GrayZoneEntryReason.low_stitcher_coverage
    return None


def _edge_facts_for_path(bundle: ContextBundle, source: str, target: str) -> list[object]:
    return [edge for edge in bundle.edge_facts if edge.source == source and edge.target == target]


def _witness_edge_facts(bundle: ContextBundle, finding: Finding) -> dict[str, object]:
    path = list(finding.witness_path or [])
    if len(path) < 2:
        return {"path_edges_checked": 0, "all_inferred": False, "reachable_sequence": False}
    checked = 0
    all_inferred = True
    reachable = True
    for source, target in zip(path, path[1:]):
        facts = _edge_facts_for_path(bundle, source, target)
        if not facts:
            reachable = False
            continue
        checked += 1
        if any(not fact.inferred for fact in facts):
            all_inferred = False
    return {
        "path_edges_checked": checked,
        "all_inferred": checked > 0 and all_inferred,
        "reachable_sequence": reachable and checked == max(len(path) - 1, 0),
    }


def _structural_questions(finding: Finding, audit: VerifierAuditEntry) -> list[str]:
    questions = [
        "Does the witness path exist as a complete graph sequence?",
        "Are all cited witness edges inferred rather than concrete?",
    ]
    if finding.missing_guard:
        questions.append(f"Is the missing guard '{finding.missing_guard}' present elsewhere on the path?")
    if finding.rls_verdict == RLSCoverage.context_mismatch:
        questions.append("Does the graph show an RLS context mismatch rather than a proven gap?")
    if any(check.name == "migration_branch_state" and check.result == "invalid" for check in audit.checks_run):
        questions.append("Does migration state make the cited path unreachable in this branch?")
    return questions


def _structural_answers(
    finding: Finding,
    audit: VerifierAuditEntry,
    *,
    bundle: ContextBundle,
) -> list[str]:
    facts = _witness_edge_facts(bundle, finding)
    answers = [
        "yes" if facts["reachable_sequence"] else "no_or_incomplete",
        "yes" if facts["all_inferred"] else "no",
    ]
    if finding.missing_guard:
        guard_text = finding.missing_guard.lower()
        present = any(guard_text in str(component).lower() for component in finding.affected_components)
        answers.append("present_elsewhere" if present else "not_seen")
    if finding.rls_verdict == RLSCoverage.context_mismatch:
        answers.append("context_mismatch")
    if any(check.name == "migration_branch_state" and check.result == "invalid" for check in audit.checks_run):
        answers.append("branch_state_invalid")
    return answers


def _prompt_for_role(
    role: str,
    finding: Finding,
    audit: VerifierAuditEntry,
    *,
    bundle: ContextBundle,
) -> str:
    payload = {
        "finding_id": finding.finding_id,
        "bug_type": finding.bug_type,
        "description": finding.description,
        "verifier_outcome": audit.verifier_outcome.value,
        "reasoner_confidence": finding.reasoner_confidence,
        "rls_verdict": finding.rls_verdict.value if finding.rls_verdict else None,
        "witness_path": finding.witness_path,
        "checks": [check.model_dump(mode="json") for check in audit.checks_run],
        "bundle_id": bundle.bundle_id,
    }
    if role == "A":
        instruction = (
            "Blind reprompt. Decide independently whether this is a bug using only the evidence pack. "
            "Return JSON with keys verdict, confidence, reasoning."
        )
    elif role == "B":
        instruction = (
            "Devil's advocate. Argue every reason this is NOT a bug, including missing graph context, "
            "possible guards, or intentional design. Return JSON with keys verdict, confidence, reasoning."
        )
    else:
        instruction = (
            "Structural probe. Answer graph-shaped questions only. Return JSON with keys verdict, "
            "confidence, reasoning, structural_questions, structural_answers."
        )
        payload["structural_questions"] = _structural_questions(finding, audit)
        payload["structural_answers_seed"] = _structural_answers(finding, audit, bundle=bundle)
    return f"{instruction}\n{json.dumps(payload, indent=2)}"


def _heuristic_panel_vote(
    role: str,
    finding: Finding,
    audit: VerifierAuditEntry,
    *,
    bundle: ContextBundle,
) -> tuple[GrayZoneVote, float, str, list[str], list[str]]:
    facts = _witness_edge_facts(bundle, finding)
    questions = _structural_questions(finding, audit) if role == "C" else []
    answers = _structural_answers(finding, audit, bundle=bundle) if role == "C" else []
    if role == "A":
        if audit.verifier_outcome == VerifierOutcome.partially_confirmed and _pass_count(audit) >= 2:
            return GrayZoneVote.bug, 0.72, "independent_rerun_converged_on_bug_like_signal", questions, answers
        if finding.reasoner_confidence >= 0.85 and not facts["all_inferred"]:
            return GrayZoneVote.bug, 0.78, "high_model_confidence_with_some_concrete_graph_support", questions, answers
        return GrayZoneVote.uncertain, 0.5, "insufficient_independent_signal", questions, answers
    if role == "B":
        if facts["all_inferred"] or finding.rls_verdict == RLSCoverage.context_mismatch:
            return GrayZoneVote.no_bug, 0.74, "counterfactual_explanation_prefers_missing_context_over_bug", questions, answers
        if audit.verifier_outcome == VerifierOutcome.unconfirmed and _fail_count(audit) == 0 and facts["reachable_sequence"]:
            return GrayZoneVote.uncertain, 0.54, "verifier_only_had_unavailable_checks_despite_a_reachable_sequence", questions, answers
        if audit.verifier_outcome == VerifierOutcome.unconfirmed:
            return GrayZoneVote.no_bug, 0.68, "verifier_did_not_establish_structural_support", questions, answers
        return GrayZoneVote.uncertain, 0.5, "no_strong_rebuttal_found", questions, answers
    if facts["reachable_sequence"] and not facts["all_inferred"]:
        return GrayZoneVote.bug, 0.7, "structural_probe_found_a_reachable_non_inferred_path", questions, answers
    if facts["all_inferred"]:
        return GrayZoneVote.no_bug, 0.66, "structural_probe_found_only_inferred_edges", questions, answers
    return GrayZoneVote.uncertain, 0.5, "structural_probe_could_not_resolve_path", questions, answers


def _parse_vote(value: str) -> GrayZoneVote | None:
    try:
        return GrayZoneVote(value)
    except ValueError:
        lowered = value.strip().lower()
        aliases = {
            "bug": GrayZoneVote.bug,
            "confirmed": GrayZoneVote.confirmed,
            "no_bug": GrayZoneVote.no_bug,
            "not_bug": GrayZoneVote.no_bug,
            "refuted": GrayZoneVote.refuted,
            "uncertain": GrayZoneVote.uncertain,
        }
        return aliases.get(lowered)


def _panel_vote(
    role: str,
    provider_name: str,
    *,
    finding: Finding,
    audit: VerifierAuditEntry,
    bundle: ContextBundle,
    config: IntelligenceConfig,
) -> tuple[GrayZoneVote, float, str, list[str], list[str]]:
    prompt = _prompt_for_role(role, finding, audit, bundle=bundle)
    provider_config = deepcopy(config)
    provider_config.llm.provider = provider_name
    provider = get_provider(provider_config, ReasonerMode.A)
    if not isinstance(provider, StubProvider):
        try:
            raw, _meta = provider.complete(prompt, max_tokens=config.llm.default_max_tokens)
            data = json.loads(raw)
            vote = _parse_vote(str(data.get("verdict", "")))
            if vote is not None:
                confidence = float(data.get("confidence", 0.5))
                reasoning = str(data.get("reasoning", ""))
                questions = [str(x) for x in data.get("structural_questions", [])]
                answers = [str(x) for x in data.get("structural_answers", [])]
                return vote, confidence, reasoning, questions, answers
        except Exception:  # noqa: BLE001
            pass
    return _heuristic_panel_vote(role, finding, audit, bundle=bundle)


def _is_bug_vote(vote: GrayZoneVote) -> bool:
    return vote in {GrayZoneVote.bug, GrayZoneVote.confirmed}


def _is_no_bug_vote(vote: GrayZoneVote) -> bool:
    return vote in {GrayZoneVote.no_bug, GrayZoneVote.refuted}


def _follow_up_structural_probe(
    finding: Finding,
    audit: VerifierAuditEntry,
    *,
    bundle: ContextBundle,
) -> tuple[GrayZoneVote, str]:
    facts = _witness_edge_facts(bundle, finding)
    if facts["reachable_sequence"] and not facts["all_inferred"]:
        return GrayZoneVote.bug, "targeted_follow_up_found_reachable_non_inferred_sequence"
    if facts["all_inferred"]:
        return GrayZoneVote.no_bug, "targeted_follow_up_found_only_inferred_support"
    if any(check.name == "migration_branch_state" and check.result == "invalid" for check in audit.checks_run):
        return GrayZoneVote.no_bug, "targeted_follow_up_blocked_by_branch_state"
    return GrayZoneVote.uncertain, "targeted_follow_up_remained_inconclusive"


def _reconcile(
    *,
    vote_a: GrayZoneVote,
    vote_b: GrayZoneVote,
    vote_c: GrayZoneVote,
    finding: Finding,
    audit: VerifierAuditEntry,
    bundle: ContextBundle,
) -> tuple[GrayZoneVoteOutcome, str]:
    votes = [vote_a, vote_b, vote_c]
    if len(set(votes)) == 1:
        if _is_bug_vote(vote_a):
            return GrayZoneVoteOutcome.evaluator_surfaced, "unanimous_bug_panel"
        if _is_no_bug_vote(vote_a):
            return GrayZoneVoteOutcome.discard, "unanimous_reject_panel"
        return GrayZoneVoteOutcome.hold_for_review, "unanimous_uncertain_panel"

    bug = sum(1 for vote in votes if _is_bug_vote(vote))
    no_bug = sum(1 for vote in votes if _is_no_bug_vote(vote))

    if bug >= 2 and vote_b == GrayZoneVote.no_bug:
        return GrayZoneVoteOutcome.hold_for_review, "majority_bug_but_model_b_dissented"
    if bug >= 2 and _is_no_bug_vote(vote_c):
        follow_up_vote, detail = _follow_up_structural_probe(finding, audit, bundle=bundle)
        if _is_bug_vote(follow_up_vote):
            return GrayZoneVoteOutcome.evaluator_surfaced, f"majority_bug_after_model_c_follow_up:{detail}"
        return GrayZoneVoteOutcome.hold_for_review, f"majority_bug_model_c_dissent:{detail}"
    if bug >= 2:
        return GrayZoneVoteOutcome.evaluator_surfaced, "majority_bug_panel"
    if no_bug == 3:
        return GrayZoneVoteOutcome.discard, "unanimous_reject_panel"
    if no_bug >= 2:
        return GrayZoneVoteOutcome.discard, "majority_reject_panel"
    if len(set(votes)) == 3:
        return GrayZoneVoteOutcome.hold_for_review, "split_panel"
    return GrayZoneVoteOutcome.hold_for_review, "ambiguous_panel"


def _gray_panel_provider(config: IntelligenceConfig, configured: str | None) -> str:
    """Resolve A/B/C panel backend; None means inherit global ``llm.provider``."""
    return (configured or config.llm.provider or "stub").strip().lower()


def evaluate(
    triples: Iterable[tuple[Finding, VerifierAuditEntry, ContextBundle]],
    *,
    config: IntelligenceConfig,
    run_id: str,
    run_low_stitcher_coverage: bool,
) -> list[GrayZoneAuditRow]:
    if not config.gray_zone.enabled:
        return []
    _ = run_id

    rows: list[GrayZoneAuditRow] = []
    for finding, audit, bundle in triples:
        reason = _classify_entry_reason(
            finding,
            audit,
            run_low_stitcher_coverage=run_low_stitcher_coverage,
            unconfirmed_threshold=config.gray_zone.unconfirmed_confidence_threshold,
        )
        if reason is None:
            continue

        vote_a, conf_a, reason_a, _, _ = _panel_vote(
            "A",
            _gray_panel_provider(config, config.gray_zone.model_a_provider),
            finding=finding,
            audit=audit,
            bundle=bundle,
            config=config,
        )
        vote_b, _conf_b, reason_b, _, _ = _panel_vote(
            "B",
            _gray_panel_provider(config, config.gray_zone.model_b_provider),
            finding=finding,
            audit=audit,
            bundle=bundle,
            config=config,
        )
        vote_c, _conf_c, reason_c, questions_c, answers_c = _panel_vote(
            "C",
            _gray_panel_provider(config, config.gray_zone.model_c_provider),
            finding=finding,
            audit=audit,
            bundle=bundle,
            config=config,
        )

        outcome, outcome_detail = _reconcile(
            vote_a=vote_a,
            vote_b=vote_b,
            vote_c=vote_c,
            finding=finding,
            audit=audit,
            bundle=bundle,
        )
        votes = [vote_a, vote_b, vote_c]
        agree_count = max(votes.count(vote) for vote in set(votes))
        row = GrayZoneAuditRow(
            finding_id=finding.finding_id,
            entry_reason=reason,
            model_a_verdict=vote_a,
            model_a_confidence=conf_a,
            model_a_reasoning=reason_a,
            model_b_verdict=vote_b,
            model_b_counter_reasoning=f"{reason_b} [{outcome_detail}]".strip(),
            model_c_structural_questions=questions_c,
            model_c_graph_answers=answers_c + ([reason_c] if reason_c and reason_c not in answers_c else []),
            model_c_verdict=vote_c,
            vote_outcome=outcome,
            surfaced=outcome == GrayZoneVoteOutcome.evaluator_surfaced,
            final_label=(
                "bug"
                if outcome == GrayZoneVoteOutcome.evaluator_surfaced
                else "not_bug"
                if outcome == GrayZoneVoteOutcome.discard
                else "uncertain"
            ),
            training_export=True,
            failed_rule=audit.failed_rule or "verifier_check_failed",
            missing_evidence=list(audit.missing_evidence or []),
            confidence_range=(
                (0.7, 0.85)
                if agree_count == 3
                else (0.3, 0.65)
                if agree_count == 2
                else (0.1, 0.4)
            ),
            recommended_action=(
                "REVIEW_REQUIRED"
                if outcome == GrayZoneVoteOutcome.evaluator_surfaced
                else "MONITOR"
                if outcome == GrayZoneVoteOutcome.hold_for_review
                else "DISMISS"
            ),
        )
        rows.append(row)

        if row.surfaced:
            finding.evaluator_surfaced_caveat = (
                "Surfaced by the gray-zone evaluator panel after ambiguous verifier evidence; not graph-confirmed."
            )
            finding.trust_level = VerifierOutcome.evaluator_surfaced
    return rows


def persist(
    rows: Iterable[GrayZoneAuditRow],
    *,
    config: IntelligenceConfig,
    run_id: str,
) -> Path:
    out_dir = config.data_dir / config.run_output_subdir / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "gray_zone_audit.jsonl"
    with path.open("w", encoding="utf-8") as fp:
        for row in rows:
            fp.write(row.model_dump_json() + "\n")
    return path


__all__ = ["evaluate", "persist"]
