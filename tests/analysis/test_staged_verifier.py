from __future__ import annotations

from pathlib import Path

from depos.analysis.schemas import (
    CodeSnippet,
    ContextBundle,
    PackManifest,
    VerifierAuditEntry,
    VerifierCheckResult,
    VerifierOutcome,
)
from depos.analysis.verifier import SourceSnippetCache, verify_staged


def _bundle(source: Path) -> ContextBundle:
    return ContextBundle(
        bundle_id="b1",
        candidate_id="c1",
        scope_id="n1",
        pack_manifest=PackManifest(manifest_id="m1"),
        code_snippets=[
            CodeSnippet(
                node_id="n1",
                source_file=str(source),
                start_line=1,
                end_line=1,
                text="def f(): pass",
            )
        ],
    )


def test_source_snippet_cache_keys_by_file_metadata_and_line_range(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("line1\nline2\n", encoding="utf-8")
    cache = SourceSnippetCache()

    assert cache.read(source, 1, 1) == "line1"
    assert cache.read(source, 1, 1) == "line1"
    assert cache.read_count == 1

    source.write_text("changed\nline2\n", encoding="utf-8")
    assert cache.read(source, 1, 1) == "changed"
    assert cache.read_count == 2


def test_verify_staged_is_advisory_only(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("def f(): pass\n", encoding="utf-8")
    audit = VerifierAuditEntry(
        finding_id="f1",
        verifier_outcome=VerifierOutcome.confirmed,
        checks_run=[VerifierCheckResult(name="rule", result="pass")],
    )

    staged = verify_staged([audit], bundle=_bundle(source), cache=SourceSnippetCache())

    assert staged[0].verifier_outcome == VerifierOutcome.confirmed
    assert staged[0].advisory_validity == "valid"
    assert {stage.stage for stage in staged[0].stage_results} == {"legacy_rules", "source_snippets"}
