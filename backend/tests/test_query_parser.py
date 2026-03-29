"""
Tests for backend query parser (Cypher + SQL/Spark SQL → JSON contract).

Run: pytest backend/tests/test_query_parser.py -v
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from analysis.query_parser import (
    detect_syntax,
    parse_cypher,
    parse_sql,
    parse_query_text,
)


# ═══════════════════════════════════════════════════════════════════════
#  Syntax detection
# ═══════════════════════════════════════════════════════════════════════

class TestDetectSyntax:
    def test_cypher(self):
        assert detect_syntax("MATCH (n) RETURN n") == "cypher"
        assert detect_syntax("  match (n) RETURN n") == "cypher"

    def test_sql(self):
        assert detect_syntax("SELECT * FROM nodes") == "sql"
        assert detect_syntax("  select * from edges") == "sql"

    def test_unknown(self):
        assert detect_syntax("BLAH") is None
        assert detect_syntax("") is None


# ═══════════════════════════════════════════════════════════════════════
#  Cypher parser
# ═══════════════════════════════════════════════════════════════════════

class TestCypherParser:
    def test_simple_node_query(self):
        r = parse_cypher('MATCH (n) WHERE n.packets > 100 RETURN n')
        assert r["target"] == "nodes"
        assert len(r["conditions"]) == 1
        assert r["conditions"][0] == {"field": "packets", "op": ">", "value": "100"}

    def test_edge_query(self):
        r = parse_cypher('MATCH (n)-[r]->(m) WHERE r.packets > 50 RETURN r')
        assert r["target"] == "edges"
        assert r["conditions"][0]["field"] == "packets"

    def test_and_logic(self):
        r = parse_cypher('MATCH (n) WHERE n.packets > 100 AND n.bytes > 5000 RETURN n')
        assert r["logic"] == "AND"
        assert len(r["conditions"]) == 2

    def test_or_logic(self):
        r = parse_cypher('MATCH (n) WHERE n.packets > 100 OR n.bytes > 5000 RETURN n')
        assert r["logic"] == "OR"
        assert len(r["conditions"]) == 2

    def test_contains(self):
        r = parse_cypher('MATCH (n) WHERE n.label CONTAINS "Server" RETURN n')
        assert r["conditions"][0] == {"field": "label", "op": "contains", "value": "Server"}

    def test_starts_with(self):
        r = parse_cypher('MATCH (n) WHERE n.os_guess STARTS WITH "Win" RETURN n')
        assert r["conditions"][0] == {"field": "os_guess", "op": "starts_with", "value": "Win"}

    def test_ends_with(self):
        r = parse_cypher('MATCH (n) WHERE n.label ENDS WITH ".local" RETURN n')
        c = r["conditions"][0]
        assert c["op"] == "matches"
        assert c["field"] == "label"

    def test_is_true(self):
        r = parse_cypher('MATCH (n) WHERE n.is_private IS TRUE RETURN n')
        assert r["conditions"][0] == {"field": "is_private", "op": "is_true"}

    def test_is_false(self):
        r = parse_cypher('MATCH (n) WHERE n.is_private IS FALSE RETURN n')
        assert r["conditions"][0] == {"field": "is_private", "op": "is_false"}

    def test_is_null(self):
        r = parse_cypher('MATCH (n) WHERE n.os_guess IS NULL RETURN n')
        assert r["conditions"][0] == {"field": "os_guess", "op": "is_empty"}

    def test_is_not_null(self):
        r = parse_cypher('MATCH (n) WHERE n.os_guess IS NOT NULL RETURN n')
        assert r["conditions"][0] == {"field": "os_guess", "op": "not_empty"}

    def test_regex(self):
        r = parse_cypher('MATCH (n) WHERE n.label =~ ".*Server.*" RETURN n')
        assert r["conditions"][0] == {"field": "label", "op": "matches", "value": ".*Server.*"}

    def test_string_equals(self):
        r = parse_cypher('MATCH (n) WHERE n.label = "192.168.1.1" RETURN n')
        assert r["conditions"][0] == {"field": "label", "op": "equals", "value": "192.168.1.1"}

    def test_numeric_equals(self):
        r = parse_cypher('MATCH (n) WHERE n.packets = 100 RETURN n')
        assert r["conditions"][0] == {"field": "packets", "op": "=", "value": "100"}

    def test_not_equals(self):
        r = parse_cypher('MATCH (n) WHERE n.packets != 0 RETURN n')
        assert r["conditions"][0] == {"field": "packets", "op": "!=", "value": "0"}

    def test_in_list(self):
        r = parse_cypher('MATCH (n)-[r]->(m) WHERE r.protocol IN ["TCP", "UDP"] RETURN r')
        assert r["conditions"][0] == {"field": "protocol", "op": "contains_any", "value": ["TCP", "UDP"]}

    def test_count_gt(self):
        r = parse_cypher('MATCH (n) WHERE count(n.macs) > 1 RETURN n')
        assert r["conditions"][0] == {"field": "macs", "op": "count_gt", "value": "1"}

    def test_count_lt(self):
        r = parse_cypher('MATCH (n) WHERE count(n.protocols) < 3 RETURN n')
        assert r["conditions"][0] == {"field": "protocols", "op": "count_lt", "value": "3"}

    def test_count_eq(self):
        r = parse_cypher('MATCH (n) WHERE count(n.ports) = 1 RETURN n')
        assert r["conditions"][0] == {"field": "ports", "op": "count_eq", "value": "1"}

    def test_mixed_and_or_rejected(self):
        r = parse_cypher('MATCH (n) WHERE n.packets > 100 AND n.bytes > 50 OR n.label = "x" RETURN n')
        assert "error" in r
        assert "Mixed AND/OR" in r["error"]

    def test_empty_returns_error(self):
        r = parse_cypher('')
        assert "error" in r

    def test_no_where_clause(self):
        r = parse_cypher('MATCH (n) RETURN n')
        assert r["target"] == "nodes"
        assert r["conditions"] == []

    def test_gte_lte(self):
        r = parse_cypher('MATCH (n) WHERE n.packets >= 100 AND n.bytes <= 5000 RETURN n')
        assert r["conditions"][0]["op"] == ">="
        assert r["conditions"][1]["op"] == "<="

    def test_diamond_ne(self):
        r = parse_cypher('MATCH (n) WHERE n.packets <> 0 RETURN n')
        assert r["conditions"][0]["op"] == "!="


# ═══════════════════════════════════════════════════════════════════════
#  SQL parser (sqlglot-powered)
# ═══════════════════════════════════════════════════════════════════════

class TestSQLParser:
    def test_simple_select(self):
        r = parse_sql('SELECT * FROM nodes WHERE packets > 100')
        assert r["target"] == "nodes"
        assert r["conditions"][0] == {"field": "packets", "op": ">", "value": "100"}

    def test_edges_table(self):
        r = parse_sql('SELECT * FROM edges WHERE packets > 50')
        assert r["target"] == "edges"

    def test_and_conditions(self):
        r = parse_sql('SELECT * FROM nodes WHERE packets > 100 AND bytes > 5000')
        assert r["logic"] == "AND"
        assert len(r["conditions"]) == 2

    def test_or_conditions(self):
        r = parse_sql('SELECT * FROM nodes WHERE packets > 100 OR bytes > 5000')
        assert r["logic"] == "OR"
        assert len(r["conditions"]) == 2

    def test_like_starts_with(self):
        r = parse_sql("SELECT * FROM nodes WHERE os_guess LIKE 'Win%'")
        assert r["conditions"][0] == {"field": "os_guess", "op": "starts_with", "value": "Win"}

    def test_like_contains(self):
        r = parse_sql("SELECT * FROM nodes WHERE label LIKE '%Server%'")
        assert r["conditions"][0]["op"] == "matches"
        assert r["conditions"][0]["value"] == "Server"

    def test_is_true(self):
        r = parse_sql('SELECT * FROM nodes WHERE is_private IS TRUE')
        assert r["conditions"][0] == {"field": "is_private", "op": "is_true"}

    def test_is_false(self):
        r = parse_sql('SELECT * FROM nodes WHERE is_private IS FALSE')
        assert r["conditions"][0] == {"field": "is_private", "op": "is_false"}

    def test_is_null(self):
        r = parse_sql('SELECT * FROM nodes WHERE os_guess IS NULL')
        assert r["conditions"][0] == {"field": "os_guess", "op": "is_empty"}

    def test_string_equals(self):
        r = parse_sql('SELECT * FROM nodes WHERE label = "192.168.1.1"')
        assert r["conditions"][0] == {"field": "label", "op": "equals", "value": "192.168.1.1"}

    def test_in_list(self):
        r = parse_sql('SELECT * FROM edges WHERE protocol IN ("TCP", "UDP")')
        c = r["conditions"][0]
        assert c["field"] == "protocol"
        assert c["op"] == "contains_any"
        assert set(c["value"]) == {"TCP", "UDP"}

    def test_array_contains(self):
        r = parse_sql('SELECT * FROM edges WHERE ARRAY_CONTAINS(protocols, "DNS")')
        assert r["conditions"][0]["op"] == "contains"
        assert r["conditions"][0]["field"] == "protocols"
        assert r["conditions"][0]["value"] == "DNS"

    def test_action_comment(self):
        r = parse_sql('SELECT * FROM nodes WHERE packets > 100 -- highlight')
        assert r["action"] == "highlight"

    def test_bad_table(self):
        r = parse_sql('SELECT * FROM foobar WHERE x > 1')
        assert "error" in r
        assert "foobar" in r["error"]

    def test_no_from(self):
        r = parse_sql('SELECT 1')
        assert "error" in r

    def test_parse_error(self):
        r = parse_sql('NOT VALID SQL AT ALL ???')
        assert "error" in r

    def test_multi_condition(self):
        r = parse_sql("SELECT * FROM nodes WHERE os_guess LIKE 'Win%' AND packets >= 500 AND is_private IS TRUE")
        assert len(r["conditions"]) == 3
        assert r["conditions"][0]["op"] == "starts_with"
        assert r["conditions"][1]["op"] == ">="
        assert r["conditions"][2]["op"] == "is_true"

    def test_count_gt(self):
        r = parse_sql('SELECT * FROM nodes WHERE COUNT(macs) > 1')
        assert r["conditions"][0] == {"field": "macs", "op": "count_gt", "value": "1"}

    def test_count_lt(self):
        r = parse_sql('SELECT * FROM nodes WHERE COUNT(protocols) < 3')
        assert r["conditions"][0] == {"field": "protocols", "op": "count_lt", "value": "3"}

    def test_spark_dialect(self):
        r = parse_sql('SELECT * FROM nodes WHERE packets > 100', dialect='spark')
        assert r["target"] == "nodes"
        assert len(r["conditions"]) == 1


# ═══════════════════════════════════════════════════════════════════════
#  Unified entry point
# ═══════════════════════════════════════════════════════════════════════

class TestParseQueryText:
    def test_auto_detect_cypher(self):
        r = parse_query_text('MATCH (n) WHERE n.packets > 100 RETURN n')
        assert r["syntax"] == "cypher"
        assert "query" in r

    def test_auto_detect_sql(self):
        r = parse_query_text('SELECT * FROM nodes WHERE packets > 100')
        assert r["syntax"] == "sql"
        assert "query" in r

    def test_explicit_dialect(self):
        r = parse_query_text('SELECT * FROM nodes WHERE packets > 100', dialect='spark')
        assert r["syntax"] == "spark"

    def test_empty(self):
        r = parse_query_text('')
        assert "error" in r

    def test_unknown_syntax(self):
        r = parse_query_text('BLAH foo bar')
        assert "error" in r
        assert r["syntax"] is None
