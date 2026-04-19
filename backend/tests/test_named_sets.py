"""
Tests for NamedSetStore + `IN @name` parser extensions + engine in_set op.

Run: pytest backend/tests/test_named_sets.py -v
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from data.query.named_sets import NamedSetStore
from data.query.query_parser import parse_cypher, parse_sql


# ═══════════════════════════════════════════════════════════════════════
#  Store CRUD
# ═══════════════════════════════════════════════════════════════════════

class TestNamedSetStore:
    def test_set_and_get(self):
        s = NamedSetStore()
        s.set("crit", "nodes", ["a", "b", "c"])
        assert s.get("crit") == {"target": "nodes", "members": ["a", "b", "c"]}

    def test_dedup_preserves_order(self):
        s = NamedSetStore()
        s.set("dup", "nodes", ["a", "b", "a", "c", "b"])
        assert s.get("dup")["members"] == ["a", "b", "c"]

    def test_members_coerced_to_str(self):
        s = NamedSetStore()
        s.set("nums", "nodes", [1, 2, 3])
        assert s.get("nums")["members"] == ["1", "2", "3"]

    def test_replace_overwrites(self):
        s = NamedSetStore()
        s.set("x", "nodes", ["a"])
        s.set("x", "edges", ["e1|e2"])
        assert s.get("x")["target"] == "edges"

    def test_delete_returns_bool(self):
        s = NamedSetStore()
        s.set("x", "nodes", ["a"])
        assert s.delete("x") is True
        assert s.delete("x") is False

    def test_clear_empties(self):
        s = NamedSetStore()
        s.set("x", "nodes", ["a"])
        s.set("y", "edges", ["e"])
        s.clear()
        assert s.list_all() == {}

    def test_requires_non_empty_name(self):
        s = NamedSetStore()
        with pytest.raises(ValueError):
            s.set("", "nodes", [])

    def test_rejects_bad_target(self):
        s = NamedSetStore()
        with pytest.raises(ValueError):
            s.set("x", "vertices", [])

    def test_to_from_dict_roundtrip(self):
        s = NamedSetStore()
        s.set("a", "nodes", ["1", "2"])
        s.set("b", "edges", ["x|y"])
        data = s.to_dict()
        s2 = NamedSetStore()
        s2.from_dict(data)
        assert s2.list_all() == s.list_all()


# ═══════════════════════════════════════════════════════════════════════
#  Parser: `IN @name` → in_set op
# ═══════════════════════════════════════════════════════════════════════

class TestCypherInSet:
    def test_basic_in_at_name(self):
        r = parse_cypher("MATCH (n) WHERE n IN @workstations RETURN n")
        assert len(r["conditions"]) == 1
        c = r["conditions"][0]
        assert c["op"] == "in_set"
        assert c["value"] == "workstations"

    def test_still_parses_list_in(self):
        # Backwards-compat: IN [a, b] still produces contains_any.
        r = parse_cypher('MATCH (n) WHERE n.protocols IN ["DNS", "HTTP"] RETURN n')
        assert r["conditions"][0]["op"] == "contains_any"

    def test_combined_with_and(self):
        r = parse_cypher("MATCH (n) WHERE n IN @crit AND n.packets > 10 RETURN n")
        assert r["logic"] == "AND"
        assert r["conditions"][0]["op"] == "in_set"
        assert r["conditions"][1]["op"] == ">"


class TestSqlInSet:
    def test_basic_in_at_name(self):
        r = parse_sql("SELECT * FROM nodes WHERE id IN @workstations")
        c = r["conditions"][0]
        assert c["op"] == "in_set"
        assert c["value"] == "workstations"

    def test_still_parses_list_in(self):
        r = parse_sql("SELECT * FROM nodes WHERE protocols IN ('DNS', 'HTTP')")
        assert r["conditions"][0]["op"] == "contains_any"

    def test_case_insensitive_in_keyword(self):
        # `in @name` (lowercase) should still trigger preprocessing.
        r = parse_sql("SELECT * FROM nodes WHERE id in @workstations")
        assert r["conditions"][0]["op"] == "in_set"


# ═══════════════════════════════════════════════════════════════════════
#  Engine: in_set operator
# ═══════════════════════════════════════════════════════════════════════

class TestEngineInSetOp:
    def setup_method(self):
        import networkx as nx
        from data.query.query_engine import resolve_query
        self.resolve_query = resolve_query
        G = nx.MultiDiGraph()
        G.add_node("a", packets=100)
        G.add_node("b", packets=5)
        G.add_node("c", packets=50)
        self.G = G

    def test_in_set_matches_members_only(self):
        named = {"crit": {"target": "nodes", "members": ["a", "c"]}}
        r = self.resolve_query(
            self.G,
            {"target": "nodes", "logic": "AND",
             "conditions": [{"field": "id", "op": "in_set", "value": "crit"}]},
            named_sets=named,
        )
        assert set(m["id"] for m in r["matched_nodes"]) == {"a", "c"}
        assert set(r["matches"]) == {"a", "c"}

    def test_in_set_unknown_returns_empty(self):
        r = self.resolve_query(
            self.G,
            {"target": "nodes", "logic": "AND",
             "conditions": [{"field": "id", "op": "in_set", "value": "ghost"}]},
            named_sets={},
        )
        assert r["matched_nodes"] == []

    def test_in_set_combined_with_other_op(self):
        named = {"crit": {"target": "nodes", "members": ["a", "b", "c"]}}
        r = self.resolve_query(
            self.G,
            {"target": "nodes", "logic": "AND", "conditions": [
                {"field": "id", "op": "in_set", "value": "crit"},
                {"field": "packets", "op": ">", "value": "10"},
            ]},
            named_sets=named,
        )
        # All in crit, but only a, c pass the packets filter.
        assert set(r["matches"]) == {"a", "c"}

    def test_negate_on_in_set(self):
        named = {"crit": {"target": "nodes", "members": ["a"]}}
        r = self.resolve_query(
            self.G,
            {"target": "nodes", "logic": "AND",
             "conditions": [{"field": "id", "op": "in_set", "value": "crit", "negate": True}]},
            named_sets=named,
        )
        assert set(r["matches"]) == {"b", "c"}
