"""Tests for Graphical Intent Context (GIC): intent IR ↔ graph join and reports."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from depos.intent_graph.run import (
    build_report,
    run_graphical_intent_compare,
)
from depos.intent_graph.loader import load_manifest, load_units
from depos.snapshot import load_graph_json_from_dict


def _minimal_manifest(repo_sha: str = "cafecafe0123456789abcdefcafecafe01234567") -> dict:
    return {
        "intent_schema_version": 2,
        "repo_sha": repo_sha,
        "built_at": "2020-01-01T00:00:00+00:00",
        "files": [],
        "counts_by_tier": {},
    }


def _mini_graph(repo_root: Path, rel: str = "svc.py") -> dict:
    abs_path = (repo_root / rel).resolve()
    rp = abs_path.relative_to(repo_root.resolve()).as_posix()
    return {
        "nodes": [
            {
                "id": "file_node",
                "label": rel,
                "file_type": "code",
                "source_file": str(abs_path),
                "source_location": "L1",
            },
            {
                "id": "fn_node",
                "label": "tick()",
                "file_type": "code",
                "source_file": str(abs_path),
                "source_location": "L5",
            },
        ],
        "edges": [
            {
                "source": "file_node",
                "target": "fn_node",
                "relation": "contains",
                "confidence": "EXTRACTED",
                "source_file": rp,
            },
        ],
    }


def test_gic_aligned_supported_line_match(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "depos.intent_graph.run._git_head",
        lambda _repo: "cafecafe0123456789abcdefcafecafe01234567",
    )
    rr = tmp_path / "repo"
    rr.mkdir()
    svc = rr / "svc.py"
    svc.write_text("# line1\n#\n#\n#\ndef tick():\n    return 1\n", encoding="utf-8")

    intent_out = rr / "intent-out"
    intent_out.mkdir()

    manifest = _minimal_manifest(repo_sha="cafecafe0123456789abcdefcafecafe01234567")
    (intent_out / "intent_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    units = [
        {
            "unit_id": "u_main",
            "extractor": "rules_v0",
            "confidence": 0.9,
            "natural_language": "Service tick exists",
            "scope_hints": ["svc.py"],
            "evidence": [{"chunk_id": "ch1", "start_line": 5}],
            "effective_tier": "P0",
            "effective_weight": 1.0,
            "tier_lineage": [],
        },
    ]
    (intent_out / "intent_units.json").write_text(json.dumps(units), encoding="utf-8")

    chunks = {"ch1": ("svc.py", 1, 10)}
    with (intent_out / "intent_chunks.jsonl").open("w", encoding="utf-8") as f:
        f.write(
            json.dumps(
                {
                    "chunk_id": "ch1",
                    "source_relpath": "svc.py",
                    "start_line": 1,
                    "end_line": 10,
                    "heading_stack": [],
                    "text": "doc",
                    "path_classification": "intent",
                    "effective_tier": "P0",
                    "effective_weight": 1.0,
                    "tier_lineage": [],
                }
            )
            + "\n"
        )

    gdata = _mini_graph(rr)
    G = load_graph_json_from_dict(gdata)
    mf = load_manifest(intent_out)
    us = load_units(intent_out)

    rep = build_report(
        rr.resolve(),
        intent_out.resolve(),
        G,
        graph_source="test",
        manifest=mf,
        units=us,
        chunks=chunks,
        coverage_tags=[],
        trace_hints=None,
    )
    row = next(u for u in rep.units if u.unit_id == "u_main")
    assert row.status == "supported"
    assert rep.graph_layer.gic_resolved_rate_p0 == 1.0
    assert rep.composite.gic_alignment_score == pytest.approx(1.0)

    gj = rr / "stub.json"
    gj.write_text(json.dumps(gdata), encoding="utf-8")

    _code_rep, exit_code = run_graphical_intent_compare(
        rr.resolve(),
        intent_out.resolve(),
        gj,
        output_dir=intent_out,
        strict=False,
    )
    assert exit_code == 0
    assert (intent_out / "intent_graph_report.json").exists()
    md = (intent_out / "intent_graph_report.md").read_text(encoding="utf-8")
    assert "Graphical Intent Context report" in md


def test_gic_drift_unresolved(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "depos.intent_graph.run._git_head",
        lambda _repo: "cafecafe0123456789abcdefcafecafe01234567",
    )
    rr = tmp_path / "r2"
    rr.mkdir()
    (rr / "stay.py").write_text("x = 1\n")

    intent_out = rr / "out"
    intent_out.mkdir()

    (intent_out / "intent_manifest.json").write_text(
        json.dumps(_minimal_manifest()),
        encoding="utf-8",
    )

    stay_g = _mini_graph(rr, rel="stay.py")
    gj = rr / "g.json"
    gj.write_text(json.dumps(stay_g), encoding="utf-8")

    units = [
        {
            "unit_id": "ghost",
            "extractor": "rules_v0",
            "confidence": 0.5,
            "natural_language": "Missing module",
            "scope_hints": ["never_existed.py"],
            "evidence": [],
            "effective_tier": "P0",
            "effective_weight": 1.0,
            "tier_lineage": [],
        },
    ]
    (intent_out / "intent_units.json").write_text(json.dumps(units), encoding="utf-8")

    rep, code = run_graphical_intent_compare(
        rr.resolve(),
        intent_out.resolve(),
        gj,
        output_dir=intent_out,
        strict=False,
    )
    row = next(u for u in rep.units if u.unit_id == "ghost")
    assert row.status == "unresolved"
    assert row.unresolved_reason == "no_matching_file"
    assert code == 0

    rep2, code2 = run_graphical_intent_compare(
        rr.resolve(),
        intent_out.resolve(),
        gj,
        output_dir=intent_out,
        strict=True,
    )
    assert code2 == 1
    assert rep2.composite.p0_unresolved_weighted > 0


def test_gic_require_same_commit_exits_one(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "depos.intent_graph.run._git_head",
        lambda _repo: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    rr = tmp_path / "r3"
    rr.mkdir()
    (rr / "a.py").write_text("pass\n")
    intent_out = rr / "out"
    intent_out.mkdir()

    (intent_out / "intent_manifest.json").write_text(
        json.dumps(_minimal_manifest(repo_sha="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")),
        encoding="utf-8",
    )
    (intent_out / "intent_units.json").write_text(json.dumps([]), encoding="utf-8")

    gdata = _mini_graph(rr, rel="a.py")
    gj = rr / "g.json"
    gj.write_text(json.dumps(gdata), encoding="utf-8")

    _rep, code = run_graphical_intent_compare(
        rr.resolve(),
        intent_out.resolve(),
        gj,
        require_same_commit=True,
    )
    assert code == 1


def test_gic_llm_env_warning(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("DEPOS_GIC_LLM", "1")
    monkeypatch.setattr(
        "depos.intent_graph.run._git_head",
        lambda _repo: "cafecafe0123456789abcdefcafecafe01234567",
    )
    rr = tmp_path / "r4"
    rr.mkdir()
    (rr / "svc.py").write_text("x = 1\n", encoding="utf-8")
    io = rr / "intent"
    io.mkdir()
    (io / "intent_manifest.json").write_text(
        json.dumps(_minimal_manifest()),
        encoding="utf-8",
    )
    (io / "intent_units.json").write_text(json.dumps([]), encoding="utf-8")
    gdata = _mini_graph(rr, rel="svc.py")
    gj = rr / "x.json"
    gj.write_text(json.dumps(gdata), encoding="utf-8")

    rep, code = run_graphical_intent_compare(rr.resolve(), io.resolve(), gj)
    assert code == 0
    assert any("DEPOS_GIC_LLM" in w for w in rep.warnings)


def test_gic_intent_trace_hints_adds_candidate_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """OFT-only unit: no scope_hints; path comes from intent_trace_hints node → chunk."""
    from depos.intent_context.schemas import IntentTraceHints, TraceHintNode

    monkeypatch.setattr(
        "depos.intent_graph.run._git_head",
        lambda _repo: "cafecafe0123456789abcdefcafecafe01234567",
    )
    rr = tmp_path / "tr"
    rr.mkdir()
    tag_py = rr / "tagged.py"
    tag_py.write_text("def f():\n    return 1\n")

    intent_out = rr / "intent"
    intent_out.mkdir()
    (intent_out / "intent_manifest.json").write_text(
        json.dumps(_minimal_manifest()),
        encoding="utf-8",
    )
    units = [
        {
            "unit_id": "u_oft",
            "extractor": "oft_markdown_v0",
            "confidence": 1.0,
            "natural_language": "implementation exists",
            "scope_hints": [],
            "evidence": [],
            "effective_tier": "P0",
            "effective_weight": 1.0,
            "tier_lineage": [],
            "oft_spec_item_id": "req~svc~1",
            "oft_covers": [],
            "oft_needs": [],
            "oft_depends": [],
        },
    ]
    (intent_out / "intent_units.json").write_text(json.dumps(units), encoding="utf-8")

    cob = {"ck_doc": ("tagged.py", 1, 20)}
    with (intent_out / "intent_chunks.jsonl").open("w", encoding="utf-8") as f:
        f.write(
            json.dumps(
                {
                    "chunk_id": "ck_doc",
                    "source_relpath": "tagged.py",
                    "start_line": 1,
                    "end_line": 20,
                    "heading_stack": [],
                    "text": "x",
                    "path_classification": "intent",
                    "effective_tier": "P0",
                    "effective_weight": 1.0,
                    "tier_lineage": [],
                }
            )
            + "\n"
        )

    th = IntentTraceHints(
        nodes=[TraceHintNode(id="req~svc~1", kind="spec_item", source_chunk_id="ck_doc")],
        edges=[],
        coverage_tags=[],
    )

    gdata = _mini_graph(rr, rel="tagged.py")
    G = load_graph_json_from_dict(gdata)

    mf = load_manifest(intent_out)
    us = load_units(intent_out)

    rep = build_report(
        rr.resolve(),
        intent_out.resolve(),
        G,
        graph_source="test",
        manifest=mf,
        units=us,
        chunks=cob,
        coverage_tags=[],
        trace_hints=th,
    )

    row = next(u for u in rep.units if u.unit_id == "u_oft")
    assert row.status in {"supported", "partial"}
    assert any(e.kind == "trace_hint" for e in row.evidence)
    assert rep.intent_layer.intent_trace_hints_file_present
    assert rep.raw.get("intent_bundle", {}).get("intent_trace_hints_loaded")


def test_gic_invalid_manifest_exits_two(tmp_path: Path) -> None:
    rr = tmp_path / "inv"
    rr.mkdir()
    io = rr / "intent"
    io.mkdir()
    (io / "intent_manifest.json").write_text("{ not json ", encoding="utf-8")

    gj = rr / "g.json"
    gdata = {
        "nodes": [
            {
                "id": "a",
                "label": "x",
                "file_type": "code",
                "source_file": "x.py",
                "source_location": "L1",
            },
        ],
        "edges": [],
    }
    gj.write_text(json.dumps(gdata), encoding="utf-8")

    rep, code = run_graphical_intent_compare(rr.resolve(), io.resolve(), gj)
    assert code == 2
    assert rep.warnings