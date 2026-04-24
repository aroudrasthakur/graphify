from __future__ import annotations

import json

from depos.analysis.bundle_prompter import render_bundle_prompt
from depos.analysis.config import IntelligenceConfig
from depos.analysis.citations import evidence_cites_bundle
from depos.analysis.schemas import (
    CodeSnippet,
    ContextBundle,
    PackManifest,
    ReasonerMode,
    SeamEdge,
    TaintEdge,
)


def _bundle() -> ContextBundle:
    return ContextBundle(
        bundle_id="bundle_1",
        candidate_id="cand_1",
        scope_id="node:scope",
        scope_node_id="scope",
        cfg_available=True,
        dfg_available=True,
        taint_edges_available=True,
        callers=["caller"],
        callees=["callee"],
        seam_neighbor_texts={"neighbor": "neighbor text"},
        cross_language_seams=[
            SeamEdge(
                edge_id="edge:scope->neighbor",
                source="scope",
                target="neighbor",
                relation="SEAM_HTTP",
            )
        ],
        taint_edges=[
            TaintEdge(
                source_node="source",
                sink_node="sink",
                intermediate_path=["source", "scope", "sink"],
                scope="scope",
            )
        ],
        cfg_summary="entry -> branch -> exit",
        null_paths=[["scope", "sink"]],
        pack_manifest=PackManifest(manifest_id="pack_1"),
    )


def _prompt_payload(prompt: str) -> dict:
    start = prompt.index("```json") + len("```json")
    end = prompt.rindex("```")
    return json.loads(prompt[start:end].strip())


def test_render_bundle_prompt_includes_citation_contract() -> None:
    prompt = render_bundle_prompt(ReasonerMode.A, _bundle())
    payload = _prompt_payload(prompt)

    assert "CITATION REQUIREMENT" in prompt
    assert "RESPONSE CONTRACT" in prompt
    assert "Allowed finding keys only" in prompt
    assert "[node:<node_id>]" in prompt
    assert "[edge:<edge_id>]" in prompt
    assert "[taint:<step>]" in prompt
    assert payload["semantic_layers"]["cfg_available"] is True
    assert payload["semantic_layers"]["taint_edges_available"] is True
    assert payload["callers"] == ["caller"]
    assert payload["callees"] == ["callee"]
    assert payload["callee_texts"] == {}


def test_evidence_cites_bundle_recognizes_explicit_citation_formats() -> None:
    bundle = _bundle()

    assert evidence_cites_bundle("Null dereference [node:scope]", bundle)
    assert evidence_cites_bundle("Cross-language seam [edge:edge:scope->neighbor]", bundle)
    assert evidence_cites_bundle("Taint flow [taint:scope]", bundle)
    assert not evidence_cites_bundle("Narrative with no structural citation", bundle)


def test_render_bundle_prompt_enforces_bundle_prompt_budget() -> None:
    bundle = _bundle()
    bundle.callers = ["caller-a", "caller-b", "caller-c"]
    bundle.callees = ["callee-a", "callee-b", "callee-c"]
    bundle.caller_texts = {
        "caller-a": "A" * 120,
        "caller-b": "B" * 120,
        "caller-c": "C" * 120,
    }
    bundle.callee_texts = {
        "callee-a": "D" * 120,
        "callee-b": "E" * 120,
        "callee-c": "F" * 120,
    }
    bundle.seam_neighbor_texts = {
        "neighbor-a": "G" * 120,
        "neighbor-b": "H" * 120,
        "neighbor-c": "I" * 120,
    }
    bundle.code_snippets = [
        CodeSnippet(node_id="snippet-1", source_file="a.py", text="J" * 400),
        CodeSnippet(node_id="snippet-2", source_file="b.py", text="K" * 400),
    ]

    config = IntelligenceConfig()
    config.bundles.max_caller_texts = 1
    config.bundles.max_callee_texts = 1
    config.bundles.max_seam_neighbor_texts = 1
    config.bundles.max_snippet_chars = 40
    config.bundles.max_prompt_tokens = 500

    prompt = render_bundle_prompt(ReasonerMode.A, bundle, config=config)
    payload = _prompt_payload(prompt)

    assert len(payload["callers"]) <= 1
    assert len(payload["callees"]) <= 1
    assert len(payload["caller_texts"]) <= 1
    assert len(payload["callee_texts"]) <= 1
    assert len(payload["seam_neighbor_texts"]) <= 1
    assert all(len(snippet["text"]) <= 40 for snippet in payload["code_snippets"])
    assert max(1, (len(prompt) + 3) // 4) <= config.bundles.max_prompt_tokens


def test_render_bundle_prompt_logs_truncation_when_budget_exceeded(caplog) -> None:
    """Test that structured logging occurs when prompt budget enforcement truncates content."""
    import logging
    
    bundle = _bundle()
    bundle.callers = ["caller-a", "caller-b", "caller-c", "caller-d"]
    bundle.callees = ["callee-a", "callee-b", "callee-c", "callee-d"]
    bundle.caller_texts = {
        "caller-a": "A" * 500,
        "caller-b": "B" * 500,
        "caller-c": "C" * 500,
        "caller-d": "D" * 500,
    }
    bundle.callee_texts = {
        "callee-a": "E" * 500,
        "callee-b": "F" * 500,
        "callee-c": "G" * 500,
        "callee-d": "H" * 500,
    }
    bundle.seam_neighbor_texts = {
        "neighbor-a": "I" * 500,
        "neighbor-b": "J" * 500,
        "neighbor-c": "K" * 500,
    }
    bundle.code_snippets = [
        CodeSnippet(node_id="snippet-1", source_file="a.py", text="L" * 800),
        CodeSnippet(node_id="snippet-2", source_file="b.py", text="M" * 800),
    ]

    config = IntelligenceConfig()
    config.bundles.max_prompt_tokens = 800  # Very low to force truncation

    with caplog.at_level(logging.INFO, logger="depos.analysis.bundle_prompter"):
        prompt = render_bundle_prompt(ReasonerMode.A, bundle, config=config)
    
    # Verify truncation occurred
    assert max(1, (len(prompt) + 3) // 4) <= config.bundles.max_prompt_tokens
    
    # Verify logging occurred
    assert len(caplog.records) > 0
    log_record = caplog.records[0]
    assert log_record.levelname == "INFO"
    assert log_record.message == "Prompt budget enforcement applied"
    
    # Verify structured logging fields
    assert "original_tokens" in log_record.__dict__
    assert "final_tokens" in log_record.__dict__
    assert "truncation_order_applied" in log_record.__dict__
    assert "max_prompt_tokens" in log_record.__dict__
    assert "candidate_id" in log_record.__dict__
    
    # Verify truncation order follows priority: seam_neighbor_texts → callee_texts → caller_texts → code_snippets → call_chain_out → call_chain_in
    truncation_order = log_record.__dict__["truncation_order_applied"]
    assert isinstance(truncation_order, list)
    assert len(truncation_order) > 0
    
    # Verify original_tokens > final_tokens
    assert log_record.__dict__["original_tokens"] > log_record.__dict__["final_tokens"]
    assert log_record.__dict__["final_tokens"] <= config.bundles.max_prompt_tokens
    assert log_record.__dict__["max_prompt_tokens"] == config.bundles.max_prompt_tokens
    assert log_record.__dict__["candidate_id"] == "cand_1"


def test_render_bundle_prompt_no_logging_when_within_budget() -> None:
    """Test that no logging occurs when prompt is within budget."""
    import logging
    from unittest.mock import patch
    
    bundle = _bundle()
    config = IntelligenceConfig()
    config.bundles.max_prompt_tokens = 10000  # Very high, no truncation needed
    
    with patch("depos.analysis.bundle_prompter.logger") as mock_logger:
        prompt = render_bundle_prompt(ReasonerMode.A, bundle, config=config)
        
        # Verify no logging occurred
        mock_logger.info.assert_not_called()
