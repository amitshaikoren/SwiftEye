"""
Tests for GroupStore + pipeline → group_store wiring + group routes.

Run: pytest backend/tests/test_groups.py -v
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


@pytest.fixture
def graph():
    import networkx as nx
    G = nx.MultiDiGraph()
    G.add_node("a", label="alpha", packets=100, protocols={"DNS"})
    G.add_node("b", label="beta",  packets=5,   protocols={"UDP"})
    G.add_node("c", label="gamma", packets=50,  protocols=set())
    G.add_edge("a", "b", protocol="DNS")
    G.add_edge("a", "c", protocol="HTTP")
    return G


# ═══════════════════════════════════════════════════════════════════════
#  GroupStore CRUD
# ═══════════════════════════════════════════════════════════════════════

class TestGroupStore:
    def test_record_and_list(self):
        from data.query.groups import GroupStore
        s = GroupStore()
        s.record("tag", "t1", "nodes", ["a", "b"], [{"verb": "tag"}])
        out = s.list_all()
        assert out["tag"]["t1"]["target"] == "nodes"
        assert out["tag"]["t1"]["members"] == ["a", "b"]
        assert out["tag"]["t1"]["recipe"] == [{"verb": "tag"}]
        assert out["color"] == {} and out["cluster"] == {} and out["set"] == {}

    def test_record_overwrites_same_name(self):
        from data.query.groups import GroupStore
        s = GroupStore()
        s.record("tag", "t1", "nodes", ["a"], [])
        s.record("tag", "t1", "nodes", ["a", "b", "c"], [])
        assert s.list_all()["tag"]["t1"]["members"] == ["a", "b", "c"]

    def test_record_suffixed_appends_on_collision(self):
        from data.query.groups import GroupStore
        s = GroupStore()
        assert s.record_suffixed("tag", "t1", "nodes", ["a"], []) == "t1"
        assert s.record_suffixed("tag", "t1", "nodes", ["b"], []) == "t1 (2)"
        assert s.record_suffixed("tag", "t1", "nodes", ["c"], []) == "t1 (3)"
        out = s.list_all()["tag"]
        assert set(out.keys()) == {"t1", "t1 (2)", "t1 (3)"}

    def test_delete(self):
        from data.query.groups import GroupStore
        s = GroupStore()
        s.record("color", "c1", "nodes", ["a"], [])
        assert s.delete("color", "c1") is True
        assert s.delete("color", "c1") is False
        assert s.list_all()["color"] == {}

    def test_clear(self):
        from data.query.groups import GroupStore
        s = GroupStore()
        s.record("tag", "t1", "nodes", ["a"], [])
        s.record("cluster", "k1", "edges", ["a|b"], [])
        s.clear()
        out = s.list_all()
        assert out == {"tag": {}, "color": {}, "cluster": {}, "set": {}}

    def test_rejects_bad_kind(self):
        from data.query.groups import GroupStore
        s = GroupStore()
        with pytest.raises(ValueError):
            s.record("zebra", "t1", "nodes", ["a"], [])

    def test_rejects_empty_name(self):
        from data.query.groups import GroupStore
        s = GroupStore()
        with pytest.raises(ValueError):
            s.record("tag", "", "nodes", ["a"], [])

    def test_rejects_bad_target(self):
        from data.query.groups import GroupStore
        s = GroupStore()
        with pytest.raises(ValueError):
            s.record("tag", "t1", "sideways", ["a"], [])

    def test_color_args_stored(self):
        from data.query.groups import GroupStore
        s = GroupStore()
        s.record("color", "c1", "nodes", ["a"], [], group_args={"color": "#ff0"})
        assert s.list_all()["color"]["c1"]["group_args"] == {"color": "#ff0"}

    def test_list_all_is_deep_enough_to_mutate_safely(self):
        from data.query.groups import GroupStore
        s = GroupStore()
        s.record("tag", "t1", "nodes", ["a", "b"], [{"verb": "tag"}])
        snap = s.list_all()
        snap["tag"]["t1"]["members"].append("zzz")
        snap["tag"]["t1"]["recipe"].append({"verb": "hack"})
        # Internal state must not have leaked the mutation.
        assert s.list_all()["tag"]["t1"]["members"] == ["a", "b"]
        assert s.list_all()["tag"]["t1"]["recipe"] == [{"verb": "tag"}]


# ═══════════════════════════════════════════════════════════════════════
#  Pipeline → GroupStore wiring
# ═══════════════════════════════════════════════════════════════════════

class TestPipelineRecordsGroups:
    def test_tag_step_records_with_recipe_slice(self, graph):
        from data.query.pipeline import run_pipeline
        from data.query.groups import GroupStore
        store = GroupStore()
        steps = [
            {"verb": "highlight", "target": "nodes",
             "conditions": [{"field": "packets", "op": ">", "value": "10"}]},
            {"verb": "tag", "target": "nodes", "group_name": "busy",
             "conditions": [{"field": "packets", "op": ">", "value": "40"}]},
        ]
        run_pipeline(graph, steps, group_store=store)
        snap = store.list_all()
        assert set(snap["tag"]["busy"]["members"]) == {"a", "c"}
        # Recipe slice includes the highlight step AND the tag step (idx 0 and 1).
        assert len(snap["tag"]["busy"]["recipe"]) == 2
        assert snap["tag"]["busy"]["recipe"][0]["verb"] == "highlight"
        assert snap["tag"]["busy"]["recipe"][1]["verb"] == "tag"

    def test_color_step_records_with_group_args(self, graph):
        from data.query.pipeline import run_pipeline
        from data.query.groups import GroupStore
        store = GroupStore()
        run_pipeline(graph, [{
            "verb": "color", "target": "nodes", "group_name": "hot",
            "group_args": {"color": "#ff0"},
            "conditions": [{"field": "packets", "op": ">", "value": "10"}],
        }], group_store=store)
        entry = store.list_all()["color"]["hot"]
        assert entry["group_args"] == {"color": "#ff0"}
        assert set(entry["members"]) == {"a", "c"}

    def test_cluster_step_records_visible_only(self, graph):
        from data.query.pipeline import run_pipeline
        from data.query.groups import GroupStore
        store = GroupStore()
        # Hide 'a' first, then cluster packets>10 → cluster should only contain 'c' (visible).
        steps = [
            {"verb": "hide", "target": "nodes", "group_name": None,
             "conditions": [{"field": "label", "op": "equals", "value": "alpha"}]},
            {"verb": "cluster", "target": "nodes", "group_name": "k1",
             "conditions": [{"field": "packets", "op": ">", "value": "10"}]},
        ]
        run_pipeline(graph, steps, group_store=store)
        assert store.list_all()["cluster"]["k1"]["members"] == ["c"]

    def test_save_as_set_records_all_matches_under_set_kind(self, graph):
        from data.query.pipeline import run_pipeline
        from data.query.groups import GroupStore
        store = GroupStore()
        # Hide 'a' then save_as_set — save captures ALL matches ignoring visibility.
        steps = [
            {"verb": "hide", "target": "nodes",
             "conditions": [{"field": "label", "op": "equals", "value": "alpha"}]},
            {"verb": "save_as_set", "target": "nodes", "group_name": "bigs",
             "conditions": [{"field": "packets", "op": ">", "value": "10"}]},
        ]
        run_pipeline(graph, steps, group_store=store)
        snap = store.list_all()
        assert "bigs" in snap["set"]
        assert set(snap["set"]["bigs"]["members"]) == {"a", "c"}  # includes hidden 'a'

    def test_non_group_verbs_do_not_record(self, graph):
        from data.query.pipeline import run_pipeline
        from data.query.groups import GroupStore
        store = GroupStore()
        run_pipeline(graph, [
            {"verb": "highlight", "target": "nodes",
             "conditions": [{"field": "packets", "op": ">", "value": "10"}]},
            {"verb": "show_only", "target": "nodes",
             "conditions": [{"field": "packets", "op": ">", "value": "40"}]},
            {"verb": "hide", "target": "nodes",
             "conditions": [{"field": "label", "op": "equals", "value": "beta"}]},
        ], group_store=store)
        out = store.list_all()
        assert out == {"tag": {}, "color": {}, "cluster": {}, "set": {}}

    def test_pipeline_upserts_same_name_across_runs(self, graph):
        from data.query.pipeline import run_pipeline
        from data.query.groups import GroupStore
        store = GroupStore()
        run_pipeline(graph, [{
            "verb": "tag", "target": "nodes", "group_name": "t1",
            "conditions": [{"field": "packets", "op": ">", "value": "10"}],
        }], group_store=store)
        run_pipeline(graph, [{
            "verb": "tag", "target": "nodes", "group_name": "t1",
            "conditions": [{"field": "packets", "op": ">", "value": "40"}],
        }], group_store=store)
        out = store.list_all()["tag"]
        # No suffix — overwrite policy on pipeline runs.
        assert set(out.keys()) == {"t1"}
        assert set(out["t1"]["members"]) == {"a", "c"}

    def test_no_store_passed_does_not_error(self, graph):
        from data.query.pipeline import run_pipeline
        # Backward-compat: pipeline runs fine without a store.
        result = run_pipeline(graph, [{
            "verb": "tag", "target": "nodes", "group_name": "t1",
            "conditions": [{"field": "packets", "op": ">", "value": "10"}],
        }])
        assert "groups" in result

    def test_disabled_step_does_not_record(self, graph):
        from data.query.pipeline import run_pipeline
        from data.query.groups import GroupStore
        store = GroupStore()
        run_pipeline(graph, [{
            "verb": "tag", "target": "nodes", "group_name": "t1",
            "enabled": False,
            "conditions": [{"field": "packets", "op": ">", "value": "10"}],
        }], group_store=store)
        assert store.list_all()["tag"] == {}


# ═══════════════════════════════════════════════════════════════════════
#  from_group scoping — treat a recorded @group as a sub-dataframe.
# ═══════════════════════════════════════════════════════════════════════

class TestFromGroupScoping:
    def test_scoped_step_filters_within_group_members(self, graph):
        from data.query.pipeline import run_pipeline
        from data.query.groups import GroupStore
        store = GroupStore()
        # First run creates tag "busy" on packets>10 → {a, c}.
        run_pipeline(graph, [{
            "verb": "tag", "target": "nodes", "group_name": "busy",
            "conditions": [{"field": "packets", "op": ">", "value": "10"}],
        }], group_store=store)
        # Second run highlights inside @busy where packets>60 — only 'a' qualifies.
        result = run_pipeline(graph, [{
            "verb": "highlight", "target": "nodes",
            "from_group": {"kind": "tag", "name": "busy"},
            "conditions": [{"field": "packets", "op": ">", "value": "60"}],
        }], group_store=store)
        highlights = result["highlights"]
        assert len(highlights) == 1
        assert set(highlights[0]["ids"]) == {"a"}

    def test_scoped_step_with_no_conditions_uses_group_members_directly(self, graph):
        from data.query.pipeline import run_pipeline
        from data.query.groups import GroupStore
        store = GroupStore()
        run_pipeline(graph, [{
            "verb": "tag", "target": "nodes", "group_name": "busy",
            "conditions": [{"field": "packets", "op": ">", "value": "10"}],
        }], group_store=store)
        result = run_pipeline(graph, [{
            "verb": "highlight", "target": "nodes",
            "from_group": {"kind": "tag", "name": "busy"},
            "conditions": [],
        }], group_store=store)
        assert len(result["highlights"]) == 1
        assert set(result["highlights"][0]["ids"]) == {"a", "c"}

    def test_scoped_step_overrides_target_to_group_target(self, graph):
        """If user says target=edges but the group is on nodes, the group's target wins."""
        from data.query.pipeline import run_pipeline
        from data.query.groups import GroupStore
        store = GroupStore()
        run_pipeline(graph, [{
            "verb": "tag", "target": "nodes", "group_name": "busy",
            "conditions": [{"field": "packets", "op": ">", "value": "10"}],
        }], group_store=store)
        result = run_pipeline(graph, [{
            "verb": "highlight", "target": "edges",  # lies
            "from_group": {"kind": "tag", "name": "busy"},
            "conditions": [],
        }], group_store=store)
        # Step was resolved against the group's node members, not edges.
        assert result["steps"][0]["target"] == "nodes"
        assert set(result["highlights"][0]["ids"]) == {"a", "c"}

    def test_scoped_step_missing_group_skips_with_warning(self, graph):
        from data.query.pipeline import run_pipeline
        from data.query.groups import GroupStore
        store = GroupStore()
        result = run_pipeline(graph, [{
            "verb": "highlight", "target": "nodes",
            "from_group": {"kind": "tag", "name": "ghost"},
            "conditions": [{"field": "packets", "op": ">", "value": "10"}],
        }], group_store=store)
        assert result["highlights"] == []
        assert any("ghost" in w for w in result["warnings"])
        assert result["steps"][0].get("skipped")

    def test_scoped_step_without_group_store_is_skipped(self, graph):
        from data.query.pipeline import run_pipeline
        result = run_pipeline(graph, [{
            "verb": "highlight", "target": "nodes",
            "from_group": {"kind": "tag", "name": "busy"},
            "conditions": [],
        }])  # no group_store
        assert result["highlights"] == []
        assert any("group_store" in w for w in result["warnings"])

    def test_scoped_step_records_from_group_in_step_trace(self, graph):
        from data.query.pipeline import run_pipeline
        from data.query.groups import GroupStore
        store = GroupStore()
        run_pipeline(graph, [{
            "verb": "tag", "target": "nodes", "group_name": "busy",
            "conditions": [{"field": "packets", "op": ">", "value": "10"}],
        }], group_store=store)
        result = run_pipeline(graph, [{
            "verb": "highlight", "target": "nodes",
            "from_group": {"kind": "tag", "name": "busy"},
            "conditions": [],
        }], group_store=store)
        trace = result["steps"][0]
        assert trace["from_group"] == {"kind": "tag", "name": "busy"}

    def test_scoped_tag_creates_nested_group_with_correct_members(self, graph):
        """Tag within a tag: @subset-of-busy = {a} (packets>60 inside @busy)."""
        from data.query.pipeline import run_pipeline
        from data.query.groups import GroupStore
        store = GroupStore()
        run_pipeline(graph, [{
            "verb": "tag", "target": "nodes", "group_name": "busy",
            "conditions": [{"field": "packets", "op": ">", "value": "10"}],
        }], group_store=store)
        run_pipeline(graph, [{
            "verb": "tag", "target": "nodes", "group_name": "very_busy",
            "from_group": {"kind": "tag", "name": "busy"},
            "conditions": [{"field": "packets", "op": ">", "value": "60"}],
        }], group_store=store)
        assert set(store.list_all()["tag"]["very_busy"]["members"]) == {"a"}
