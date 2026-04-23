"""
Tests for the query pipeline executor.

Covers verb semantics, order sensitivity, named-set flow, orphan policy,
and global-scope provenance. Uses a small hand-built NetworkX graph.

Run: pytest backend/tests/test_pipeline.py -v
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


@pytest.fixture
def graph():
    """Small graph — three nodes, three edges, mixed attrs for realistic conditions."""
    import networkx as nx
    G = nx.MultiDiGraph()
    G.add_node("a", label="alpha-server", packets=100, protocols={"DNS", "TCP"})
    G.add_node("b", label="BETA-host",    packets=5,   protocols={"UDP"})
    G.add_node("c", label="gamma",        packets=50,  protocols=set())
    G.add_edge("a", "b", protocol="DNS",  bytes=400)
    G.add_edge("b", "c", protocol="UDP",  bytes=100)
    G.add_edge("a", "c", protocol="HTTP", bytes=900)
    return G


@pytest.fixture
def run():
    from data.query.pipeline import run_pipeline
    return run_pipeline


# ═══════════════════════════════════════════════════════════════════════
#  Individual verbs
# ═══════════════════════════════════════════════════════════════════════

class TestHighlight:
    def test_records_effective_matches(self, run, graph):
        result = run(graph, [{
            "verb": "highlight", "target": "nodes",
            "conditions": [{"field": "packets", "op": ">", "value": "10"}],
        }])
        assert len(result["highlights"]) == 1
        assert set(result["highlights"][0]["ids"]) == {"a", "c"}

    def test_does_not_affect_visibility(self, run, graph):
        result = run(graph, [{
            "verb": "highlight", "target": "nodes",
            "conditions": [{"field": "packets", "op": ">", "value": "10"}],
        }])
        assert set(result["visible"]["nodes"]) == {"a", "b", "c"}


class TestShowOnly:
    def test_restricts_visible_nodes(self, run, graph):
        result = run(graph, [{
            "verb": "show_only", "target": "nodes",
            "conditions": [{"field": "packets", "op": ">", "value": "10"}],
        }])
        assert set(result["visible"]["nodes"]) == {"a", "c"}
        assert set(result["hidden"]["nodes"]) == {"b"}

    def test_show_only_nodes_drops_edges_touching_hidden(self, run, graph):
        # b is hidden → edges a-b and b-c should be dropped; a-c remains.
        result = run(graph, [{
            "verb": "show_only", "target": "nodes",
            "conditions": [{"field": "packets", "op": ">", "value": "10"}],
        }])
        assert set(result["visible"]["edges"]) == {"a|c"}

    def test_show_only_edges_keeps_nodes_unchanged_but_filters_edges(self, run, graph):
        result = run(graph, [{
            "verb": "show_only", "target": "edges",
            "conditions": [{"field": "protocol", "op": "equals", "value": "DNS"}],
        }])
        assert set(result["visible"]["edges"]) == {"a|b"}
        assert set(result["visible"]["nodes"]) == {"a", "b", "c"}


class TestHide:
    def test_hide_nodes_drops_their_edges(self, run, graph):
        result = run(graph, [{
            "verb": "hide", "target": "nodes",
            "conditions": [{"field": "label", "op": "equals", "value": "gamma"}],
        }])
        assert "c" not in result["visible"]["nodes"]
        assert "b|c" not in result["visible"]["edges"]
        assert "a|c" not in result["visible"]["edges"]

    def test_hide_edges_orphans_isolated_nodes(self, run, graph):
        # Hide both edges touching b (a|b, b|c). Orphan policy should hide b.
        result = run(graph, [{
            "verb": "hide", "target": "edges",
            "conditions": [{"field": "protocol", "op": "contains_any", "value": ["DNS", "UDP"]}],
        }])
        assert set(result["visible"]["edges"]) == {"a|c"}
        assert "b" not in result["visible"]["nodes"]
        # a, c still have the a|c edge, so they stay.
        assert {"a", "c"}.issubset(set(result["visible"]["nodes"]))


class TestGroupVerbs:
    def test_tag_records_group(self, run, graph):
        result = run(graph, [{
            "verb": "tag", "target": "nodes", "group_name": "chatty",
            "conditions": [{"field": "packets", "op": ">", "value": "10"}],
        }])
        assert result["groups"]["tag"]["chatty"]["target"] == "nodes"
        assert set(result["groups"]["tag"]["chatty"]["members"]) == {"a", "c"}

    def test_color_carries_args(self, run, graph):
        result = run(graph, [{
            "verb": "color", "target": "nodes", "group_name": "hot",
            "group_args": {"color": "#f00"},
            "conditions": [{"field": "packets", "op": ">", "value": "50"}],
        }])
        assert result["groups"]["color"]["hot"]["args"] == {"color": "#f00"}
        assert set(result["groups"]["color"]["hot"]["members"]) == {"a"}

    def test_cluster_records_members(self, run, graph):
        result = run(graph, [{
            "verb": "cluster", "target": "nodes", "group_name": "low",
            "conditions": [{"field": "packets", "op": "<", "value": "20"}],
        }])
        assert set(result["groups"]["cluster"]["low"]["members"]) == {"b"}

    def test_missing_group_name_is_skipped_with_warning(self, run, graph):
        result = run(graph, [{
            "verb": "tag", "target": "nodes",
            "conditions": [{"field": "packets", "op": ">", "value": "10"}],
        }])
        assert result["groups"]["tag"] == {}
        assert any("group_name" in w for w in result["warnings"])
        assert result["steps"][0].get("skipped") == "missing group_name"


class TestSaveAsSet:
    def test_saves_to_result_and_mutates_named_sets(self, run, graph):
        named = {}
        result = run(graph, [{
            "verb": "save_as_set", "target": "nodes", "group_name": "chatty",
            "conditions": [{"field": "packets", "op": ">", "value": "10"}],
        }], named_sets=named)
        assert set(result["saved_sets"]["chatty"]["members"]) == {"a", "c"}
        # Live mutation — the same dict passed in is now populated.
        assert named["chatty"]["target"] == "nodes"
        assert set(named["chatty"]["members"]) == {"a", "c"}

    def test_saved_set_referenceable_by_later_step(self, run, graph):
        named = {}
        result = run(graph, [
            {
                "verb": "save_as_set", "target": "nodes", "group_name": "chatty",
                "conditions": [{"field": "packets", "op": ">", "value": "10"}],
            },
            {
                "verb": "highlight", "target": "nodes",
                "conditions": [{"field": "n", "op": "in_set", "value": "chatty"}],
            },
        ], named_sets=named)
        assert len(result["highlights"]) == 1
        assert set(result["highlights"][0]["ids"]) == {"a", "c"}


# ═══════════════════════════════════════════════════════════════════════
#  Order sensitivity — explicitly called out in Phase B exit criterion
# ═══════════════════════════════════════════════════════════════════════

class TestOrderSensitivity:
    def test_show_only_then_cluster_vs_cluster_then_show_only(self, run, graph):
        # show_only → cluster: cluster sees only post-filter nodes
        r1 = run(graph, [
            {"verb": "show_only", "target": "nodes",
             "conditions": [{"field": "packets", "op": ">", "value": "10"}]},
            {"verb": "cluster", "target": "nodes", "group_name": "g",
             "conditions": [{"field": "packets", "op": ">", "value": "0"}]},
        ])
        # cluster → show_only: cluster built first (all members), then filter visibility
        r2 = run(graph, [
            {"verb": "cluster", "target": "nodes", "group_name": "g",
             "conditions": [{"field": "packets", "op": ">", "value": "0"}]},
            {"verb": "show_only", "target": "nodes",
             "conditions": [{"field": "packets", "op": ">", "value": "10"}]},
        ])
        # Different cluster members: r1 excludes "b" (hidden before cluster runs);
        # r2 includes "b" (cluster captured before visibility narrowed).
        assert set(r1["groups"]["cluster"]["g"]["members"]) == {"a", "c"}
        assert set(r2["groups"]["cluster"]["g"]["members"]) == {"a", "b", "c"}


# ═══════════════════════════════════════════════════════════════════════
#  in_set evaluation against a pre-populated store
# ═══════════════════════════════════════════════════════════════════════

class TestInSetOp:
    def test_pre_populated_named_set(self, run, graph):
        named = {"critical": {"target": "nodes", "members": ["a", "c"]}}
        result = run(graph, [{
            "verb": "highlight", "target": "nodes",
            "conditions": [{"field": "n", "op": "in_set", "value": "critical"}],
        }], named_sets=named)
        assert set(result["highlights"][0]["ids"]) == {"a", "c"}

    def test_unknown_set_matches_nothing(self, run, graph):
        result = run(graph, [{
            "verb": "highlight", "target": "nodes",
            "conditions": [{"field": "n", "op": "in_set", "value": "ghost"}],
        }], named_sets={})
        assert result["highlights"] == []


# ═══════════════════════════════════════════════════════════════════════
#  Scope + provenance
# ═══════════════════════════════════════════════════════════════════════

class TestGlobalScope:
    def test_global_hide_logged_as_pending(self, run, graph):
        result = run(graph, [{
            "verb": "hide", "target": "nodes", "scope": "global",
            "conditions": [{"field": "label", "op": "equals", "value": "gamma"}],
        }])
        assert len(result["pending_global"]) == 1
        entry = result["pending_global"][0]
        assert entry["verb"] == "hide"
        assert entry["target"] == "nodes"
        assert entry["matches"] == ["c"]

    def test_viz_scope_not_in_pending(self, run, graph):
        result = run(graph, [{
            "verb": "hide", "target": "nodes",
            "conditions": [{"field": "label", "op": "equals", "value": "gamma"}],
        }])
        assert result["pending_global"] == []

    def test_highlight_even_global_is_not_pending(self, run, graph):
        # Only hide/show_only emit pending_global — highlight/tag/color/cluster are viz-only verbs.
        result = run(graph, [{
            "verb": "highlight", "target": "nodes", "scope": "global",
            "conditions": [{"field": "packets", "op": ">", "value": "10"}],
        }])
        assert result["pending_global"] == []


class TestProvenance:
    def test_per_step_records_include_matches_and_removed(self, run, graph):
        result = run(graph, [{
            "verb": "hide", "target": "nodes",
            "conditions": [{"field": "label", "op": "equals", "value": "gamma"}],
        }])
        step = result["steps"][0]
        assert step["verb"] == "hide"
        assert step["matches"] == ["c"]
        assert "c" in step["removed"]["nodes"]
        assert set(step["removed"]["edges"]) == {"a|c", "b|c"}

    def test_disabled_step_is_recorded_but_skipped(self, run, graph):
        result = run(graph, [{
            "verb": "hide", "target": "nodes", "enabled": False,
            "conditions": [{"field": "label", "op": "equals", "value": "gamma"}],
        }])
        assert result["steps"][0]["skipped"] == "disabled"
        assert "c" in result["visible"]["nodes"]


class TestEmptyAndNoops:
    def test_empty_pipeline_shows_everything(self, run, graph):
        result = run(graph, [])
        assert set(result["visible"]["nodes"]) == {"a", "b", "c"}
        assert set(result["visible"]["edges"]) == {"a|b", "b|c", "a|c"}

    def test_none_graph(self, run):
        result = run(None, [{"verb": "highlight", "target": "nodes", "conditions": []}])
        assert "No capture loaded" in result["warnings"][0]
