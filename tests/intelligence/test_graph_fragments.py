"""Tests for the GraphFragment + merge_fragments infrastructure (Phase 3)."""
from __future__ import annotations

import types

import networkx as nx
import pytest

from depos.analysis.fragments import (
    ADDITIVE_ATTR_KEYS,
    GRAPH_METADATA_ALLOWLIST,
    EdgeAttrUpdate,
    FragmentEdge,
    FragmentMergeError,
    FragmentNode,
    GraphFragment,
    HardCollision,
    MergeReport,
    NodeAttrUpdate,
    make_fragment,
    merge_fragments,
)


# ── helpers ───────────────────────────────────────────────────────────────────


def _node(node_id: str, **attrs: object) -> FragmentNode:
    return FragmentNode(node_id=node_id, attrs=dict(attrs))


def _edge(u: str, v: str, key: str | None = None, **attrs: object) -> FragmentEdge:
    return FragmentEdge(u=u, v=v, key=key, attrs=dict(attrs))


def _frag(
    stage: str,
    nodes: list[FragmentNode] | None = None,
    edges: list[FragmentEdge] | None = None,
    metadata: dict | None = None,
    source_file: str | None = None,
    file_hash: str | None = None,
) -> GraphFragment:
    return make_fragment(
        stage,
        source_file=source_file,
        file_hash=file_hash,
        nodes=nodes or [],
        edges=edges or [],
        metadata=metadata,
    )


# ── construction ──────────────────────────────────────────────────────────────


class TestConstruction:
    def test_metadata_must_be_mappingproxy(self):
        with pytest.raises(TypeError, match="MappingProxyType"):
            GraphFragment(
                stage="test",
                source_file=None,
                file_hash=None,
                language=None,
                nodes=(),
                edges=(),
                node_attr_updates=(),
                edge_attr_updates=(),
                metadata={"raw": "dict"},
                diagnostics=(),
            )

    def test_make_fragment_wraps_metadata(self):
        frag = make_fragment("test", metadata={"key": "val"})
        assert isinstance(frag.metadata, types.MappingProxyType)
        assert frag.metadata["key"] == "val"

    def test_make_fragment_empty_metadata(self):
        frag = make_fragment("test")
        assert isinstance(frag.metadata, types.MappingProxyType)
        assert len(frag.metadata) == 0

    def test_frozen_field_reassignment_fails(self):
        frag = make_fragment("test")
        with pytest.raises((AttributeError, TypeError)):
            frag.stage = "other"  # type: ignore[misc]


# ── basic merge ───────────────────────────────────────────────────────────────


class TestBasicMerge:
    def test_adds_nodes(self):
        g = nx.DiGraph()
        report = merge_fragments(g, [_frag("s1", nodes=[_node("A", label="a"), _node("B", label="b")])])
        assert "A" in g and "B" in g
        assert report.nodes_added == 2
        assert report.ok

    def test_adds_edges(self):
        g = nx.DiGraph()
        g.add_node("A")
        g.add_node("B")
        report = merge_fragments(g, [_frag("s1", edges=[_edge("A", "B", relation="CALLS")])])
        assert g.has_edge("A", "B")
        assert g.edges["A", "B"]["relation"] == "CALLS"
        assert report.edges_added == 1

    def test_adds_nodes_and_edges_together(self):
        g = nx.DiGraph()
        frags = [
            _frag("s1", nodes=[_node("A", type="function")], edges=[_edge("A", "B", relation="IMPORTS")]),
            _frag("s2", nodes=[_node("B", type="module")]),
        ]
        report = merge_fragments(g, frags)
        assert report.nodes_added == 2
        assert report.edges_added == 1

    def test_empty_fragments_list(self):
        g = nx.DiGraph()
        report = merge_fragments(g, [])
        assert report.ok
        assert report.fragments_processed == 0

    def test_node_attrs_are_set(self):
        g = nx.DiGraph()
        merge_fragments(g, [_frag("s1", nodes=[_node("X", label="L", language="python")])])
        assert g.nodes["X"]["label"] == "L"
        assert g.nodes["X"]["language"] == "python"


# ── determinism ───────────────────────────────────────────────────────────────


class TestDeterminism:
    def _build(self, frags: list[GraphFragment]) -> nx.DiGraph:
        g = nx.DiGraph()
        merge_fragments(g, frags)
        return g

    def test_shuffled_input_same_topology(self):
        base = [
            _frag("s1", source_file="a.py", file_hash="h1", nodes=[_node("A", label="a")]),
            _frag("s2", source_file="b.py", file_hash="h2", nodes=[_node("B", label="b")]),
            _frag("s3", source_file="c.py", file_hash="h3", edges=[_edge("A", "B", relation="CALLS")]),
        ]
        orderings = [
            [0, 1, 2],
            [2, 1, 0],
            [1, 2, 0],
            [2, 0, 1],
        ]
        graphs = [self._build([base[i] for i in o]) for o in orderings]
        ref_nodes = set(graphs[0].nodes())
        ref_edges = set(graphs[0].edges())
        for g in graphs[1:]:
            assert set(g.nodes()) == ref_nodes
            assert set(g.edges()) == ref_edges

    def test_same_stage_files_sorted_deterministically(self):
        frags = [
            _frag("enrich", source_file="z.py", nodes=[_node("Z")]),
            _frag("enrich", source_file="a.py", nodes=[_node("A")]),
            _frag("enrich", source_file="m.py", nodes=[_node("M")]),
        ]
        g1 = self._build(frags)
        g2 = self._build(list(reversed(frags)))
        assert set(g1.nodes()) == set(g2.nodes())


# ── scalar identity collisions ────────────────────────────────────────────────


class TestScalarCollisions:
    def test_collision_raises_fragment_merge_error(self):
        g = nx.DiGraph()
        frags = [
            _frag("s1", nodes=[_node("A", type="function")]),
            _frag("s2", nodes=[_node("A", type="class")]),
        ]
        with pytest.raises(FragmentMergeError) as exc_info:
            merge_fragments(g, frags)
        err = exc_info.value
        assert len(err.report.hard_collisions) >= 1
        col = err.report.hard_collisions[0]
        assert col.entity_id == "A"
        assert col.key == "type"
        assert col.old_value == "function"
        assert col.new_value == "class"

    def test_collision_report_has_stage(self):
        g = nx.DiGraph()
        frags = [
            _frag("extract", nodes=[_node("A", name="foo")]),
            _frag("enrich", nodes=[_node("A", name="bar")]),
        ]
        with pytest.raises(FragmentMergeError) as exc_info:
            merge_fragments(g, frags)
        col = exc_info.value.report.hard_collisions[0]
        assert col.stage == "enrich"

    def test_all_collisions_collected_before_raise(self):
        g = nx.DiGraph()
        frags = [
            _frag("s1", nodes=[_node("A", type="fn", label="old"), _node("B", type="cls")]),
            _frag("s2", nodes=[_node("A", type="cls", label="new"), _node("B", type="fn")]),
        ]
        with pytest.raises(FragmentMergeError) as exc_info:
            merge_fragments(g, frags)
        # Both A.type, A.label, and B.type should be recorded
        assert exc_info.value.report.fragments_processed == 2
        assert len(exc_info.value.report.hard_collisions) >= 2

    def test_idempotent_write_is_not_collision(self):
        g = nx.DiGraph()
        frags = [
            _frag("s1", nodes=[_node("A", type="function", label="fn_a")]),
            _frag("s2", nodes=[_node("A", type="function", label="fn_a")]),
        ]
        report = merge_fragments(g, frags)
        assert report.ok
        assert g.nodes["A"]["type"] == "function"

    def test_new_key_on_existing_node_is_not_collision(self):
        g = nx.DiGraph()
        g.add_node("A", type="function")
        frag = _frag("enrich", nodes=[_node("A", language="python")])
        report = merge_fragments(g, [frag])
        assert report.ok
        assert g.nodes["A"]["language"] == "python"

    def test_edge_scalar_collision(self):
        g = nx.DiGraph()
        g.add_edge("A", "B", relation="CALLS")
        frag = _frag("s1", edges=[_edge("A", "B", relation="IMPORTS")])
        with pytest.raises(FragmentMergeError) as exc_info:
            merge_fragments(g, [frag])
        col = exc_info.value.report.hard_collisions[0]
        assert col.entity_id == "A->B"
        assert col.key == "relation"


# ── additive key merges ───────────────────────────────────────────────────────


class TestAdditiveKeys:
    def test_additive_keys_constants(self):
        expected = {"diagnostics", "tags", "evidence", "http_call_sites", "seam_edge_ids"}
        assert expected.issubset(ADDITIVE_ATTR_KEYS)

    def test_list_merge_appends_and_deduplicates(self):
        g = nx.DiGraph()
        frags = [
            _frag("s1", nodes=[_node("A", diagnostics=["d1", "d2"])]),
            _frag("s2", nodes=[_node("A", diagnostics=["d2", "d3"])]),
        ]
        report = merge_fragments(g, frags)
        assert report.ok
        diag = g.nodes["A"]["diagnostics"]
        assert set(diag) == {"d1", "d2", "d3"}
        assert diag.count("d2") == 1

    def test_tags_deduplication(self):
        g = nx.DiGraph()
        frags = [
            _frag("s1", nodes=[_node("A", tags=["api", "route"])]),
            _frag("s2", nodes=[_node("A", tags=["route", "public"])]),
        ]
        report = merge_fragments(g, frags)
        assert report.ok
        tags = g.nodes["A"]["tags"]
        assert tags.count("route") == 1
        assert set(tags) == {"api", "route", "public"}

    def test_http_call_sites_merge(self):
        g = nx.DiGraph()
        frags = [
            _frag("s1", nodes=[_node("N", http_call_sites=[{"url": "/a"}])]),
            _frag("s2", nodes=[_node("N", http_call_sites=[{"url": "/b"}])]),
        ]
        report = merge_fragments(g, frags)
        assert report.ok
        sites = g.nodes["N"]["http_call_sites"]
        urls = {s["url"] for s in sites}
        assert urls == {"/a", "/b"}


# ── metadata allowlist ────────────────────────────────────────────────────────


class TestMetadataAllowlist:
    def test_allowlisted_metadata_merged(self):
        g = nx.DiGraph()
        frag = make_fragment("s1", metadata={"run_metadata": {"foo": "bar"}})
        merge_fragments(g, [frag])
        assert "run_metadata" in g.graph
        assert g.graph["run_metadata"]["foo"] == "bar"

    def test_non_allowlisted_metadata_silently_dropped(self):
        g = nx.DiGraph()
        frag = make_fragment(
            "s1",
            metadata={"injected_key": "should_not_appear", "run_metadata": {"ok": 1}},
        )
        merge_fragments(g, [frag])
        assert "injected_key" not in g.graph
        assert "run_metadata" in g.graph

    def test_all_allowlisted_keys_known(self):
        expected = {"taint_edges", "run_metadata", "coverage", "migration_glob", "seam_edge_index"}
        assert expected == GRAPH_METADATA_ALLOWLIST

    def test_metadata_defensive_copy(self):
        g = nx.DiGraph()
        orig: dict = {"val": [1, 2, 3]}
        frag = make_fragment("s1", metadata={"run_metadata": orig})
        merge_fragments(g, [frag])
        # Mutating the original should not affect the graph
        orig["val"].append(99)
        assert 99 not in g.graph.get("run_metadata", {}).get("val", [])


# ── merge report ──────────────────────────────────────────────────────────────


class TestMergeReport:
    def test_report_counts(self):
        g = nx.DiGraph()
        frags = [
            _frag("s1", nodes=[_node("A"), _node("B")], edges=[_edge("A", "B")]),
            _frag("s2", nodes=[_node("C")]),
        ]
        report = merge_fragments(g, frags)
        assert report.fragments_processed == 2
        assert report.nodes_added == 3
        assert report.edges_added == 1

    def test_error_has_populated_report(self):
        g = nx.DiGraph()
        frags = [
            _frag("s1", nodes=[_node("X", label="old")]),
            _frag("s2", nodes=[_node("X", label="new")]),
        ]
        with pytest.raises(FragmentMergeError) as exc_info:
            merge_fragments(g, frags)
        err = exc_info.value
        assert isinstance(err.report, MergeReport)
        assert err.report.fragments_processed == 2
        assert not err.report.ok

    def test_error_message_includes_collision_details(self):
        g = nx.DiGraph()
        frags = [
            _frag("extract", nodes=[_node("A", type="fn")]),
            _frag("enrich", nodes=[_node("A", type="cls")]),
        ]
        with pytest.raises(FragmentMergeError) as exc_info:
            merge_fragments(g, frags)
        msg = str(exc_info.value)
        assert "type" in msg
        assert "fn" in msg
        assert "cls" in msg


# ── node/edge attr updates ────────────────────────────────────────────────────


class TestAttrUpdates:
    def test_node_attr_update_sets_new_key(self):
        g = nx.DiGraph()
        g.add_node("A", type="fn")
        frag = make_fragment(
            "s1",
            node_attr_updates=[NodeAttrUpdate(node_id="A", key="language", value="python")],
        )
        report = merge_fragments(g, [frag])
        assert report.ok
        assert g.nodes["A"]["language"] == "python"

    def test_node_attr_update_collision_raises(self):
        g = nx.DiGraph()
        g.add_node("A", type="fn")
        frag = make_fragment(
            "s1",
            node_attr_updates=[NodeAttrUpdate(node_id="A", key="type", value="cls")],
        )
        with pytest.raises(FragmentMergeError):
            merge_fragments(g, [frag])

    def test_edge_attr_update_sets_new_key(self):
        g = nx.DiGraph()
        g.add_edge("A", "B", relation="CALLS")
        frag = make_fragment(
            "s1",
            edge_attr_updates=[EdgeAttrUpdate(u="A", v="B", key=None, attr_key="confidence", value=0.9)],
        )
        report = merge_fragments(g, [frag])
        assert report.ok
        assert g.edges["A", "B"]["confidence"] == 0.9
