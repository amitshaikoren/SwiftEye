"""Tests for PySpark DataFrame expression translator."""

import sys
sys.path.insert(0, "backend")

import pytest
from data.query.pyspark_translator import parse_pyspark


class TestBasicComparisons:
    def test_greater_than(self):
        r = parse_pyspark('df.filter(col("packets") > 1000)')
        assert "error" not in r
        assert r["target"] == "nodes"
        assert r["conditions"] == [{"field": "packets", "op": ">", "value": 1000}]

    def test_less_than(self):
        r = parse_pyspark('df.filter(col("bytes") < 500)')
        assert r["conditions"][0]["op"] == "<"

    def test_equals_numeric(self):
        r = parse_pyspark('df.filter(col("port") == 80)')
        assert r["conditions"][0] == {"field": "port", "op": "=", "value": 80}

    def test_not_equals(self):
        r = parse_pyspark('df.filter(col("port") != 0)')
        assert r["conditions"][0]["op"] == "!="

    def test_string_equals(self):
        r = parse_pyspark('df.filter(col("protocol") == "HTTP")')
        assert r["conditions"][0] == {"field": "protocol", "op": "=", "value": "HTTP"}

    def test_boolean_true(self):
        r = parse_pyspark('df.filter(col("is_private") == True)')
        assert r["conditions"][0] == {"field": "is_private", "op": "is_true", "value": None}

    def test_boolean_false(self):
        r = parse_pyspark('df.filter(col("is_private") == False)')
        assert r["conditions"][0] == {"field": "is_private", "op": "is_false", "value": None}


class TestMethodCalls:
    def test_contains(self):
        r = parse_pyspark('df.filter(col("protocols").contains("DNS"))')
        assert r["conditions"][0] == {"field": "protocols", "op": "contains", "value": "DNS"}

    def test_startswith(self):
        r = parse_pyspark('df.filter(col("os_guess").startswith("Win"))')
        assert r["conditions"][0] == {"field": "os_guess", "op": "starts_with", "value": "Win"}

    def test_endswith(self):
        r = parse_pyspark('df.filter(col("hostname").endswith(".com"))')
        assert r["conditions"][0] == {"field": "hostname", "op": "ends_with", "value": ".com"}

    def test_isNull(self):
        r = parse_pyspark('df.filter(col("macs").isNull())')
        assert r["conditions"][0] == {"field": "macs", "op": "is_empty", "value": None}

    def test_isNotNull(self):
        r = parse_pyspark('df.filter(col("macs").isNotNull())')
        assert r["conditions"][0] == {"field": "macs", "op": "not_empty", "value": None}

    def test_isin_list(self):
        r = parse_pyspark('df.filter(col("protocols").isin(["DNS", "HTTP"]))')
        assert r["conditions"][0] == {"field": "protocols", "op": "contains_any", "value": ["DNS", "HTTP"]}

    def test_isin_args(self):
        r = parse_pyspark('df.filter(col("protocol").isin("DNS", "HTTP"))')
        assert r["conditions"][0]["value"] == ["DNS", "HTTP"]

    def test_rlike(self):
        r = parse_pyspark('df.filter(col("hostname").rlike(".*corp.*"))')
        assert r["conditions"][0] == {"field": "hostname", "op": "matches", "value": ".*corp.*"}


class TestCompound:
    def test_and(self):
        r = parse_pyspark('df.filter((col("packets") > 100) & (col("bytes") > 5000))')
        assert r["logic"] == "AND"
        assert len(r["conditions"]) == 2

    def test_or(self):
        r = parse_pyspark('df.filter((col("packets") > 100) | (col("protocols").contains("DNS")))')
        assert r["logic"] == "OR"
        assert len(r["conditions"]) == 2


class TestCount:
    def test_count_gt(self):
        r = parse_pyspark('df.filter(count(col("macs")) > 1)')
        assert r["conditions"][0] == {"field": "macs", "op": "count_gt", "value": 1}


class TestTargetDetection:
    def test_default_nodes(self):
        r = parse_pyspark('df.filter(col("packets") > 1000)')
        assert r["target"] == "nodes"

    def test_edges_variable(self):
        r = parse_pyspark('edges.filter(col("has_reset") == True)')
        assert r["target"] == "edges"

    def test_nodes_variable(self):
        r = parse_pyspark('nodes.filter(col("packets") > 100)')
        assert r["target"] == "nodes"


class TestBareExpression:
    def test_bare_col(self):
        r = parse_pyspark('col("packets") > 1000')
        assert r["conditions"][0] == {"field": "packets", "op": ">", "value": 1000}

    def test_bare_compound(self):
        r = parse_pyspark('(col("packets") > 100) & (col("bytes") > 5000)')
        assert len(r["conditions"]) == 2


class TestWhereAlias:
    def test_where(self):
        r = parse_pyspark('df.where(col("protocols").contains("DNS"))')
        assert r["conditions"][0]["field"] == "protocols"


class TestErrors:
    def test_empty(self):
        r = parse_pyspark("")
        assert "error" in r

    def test_garbage(self):
        r = parse_pyspark("hello world")
        assert "error" in r

    def test_unsupported_method(self):
        r = parse_pyspark('df.filter(col("x").foobar())')
        assert "error" in r


class TestLike:
    def test_like(self):
        r = parse_pyspark('df.filter(col("hostname").like("a%b_"))')
        assert r["conditions"][0] == {"field": "hostname", "op": "like", "value": "a%b_"}


class TestNegate:
    def test_negate_comparison(self):
        r = parse_pyspark('df.filter(~(col("packets") > 5))')
        c = r["conditions"][0]
        assert c["field"] == "packets"
        assert c["op"] == ">"
        assert c["value"] == 5
        assert c.get("negate") is True

    def test_negate_method(self):
        r = parse_pyspark('df.filter(~col("protocols").contains("DNS"))')
        c = r["conditions"][0]
        assert c["op"] == "contains"
        assert c["value"] == "DNS"
        assert c.get("negate") is True

    def test_double_negate_cancels(self):
        r = parse_pyspark('df.filter(~~(col("packets") > 5))')
        c = r["conditions"][0]
        assert c["op"] == ">"
        assert "negate" not in c


class TestCaseInsensitive:
    def test_lower_function_form(self):
        r = parse_pyspark('df.filter(lower(col("hostname")).contains("server"))')
        c = r["conditions"][0]
        assert c["field"] == "hostname"
        assert c["op"] == "contains"
        assert c.get("case_insensitive") is True

    def test_upper_method_form(self):
        r = parse_pyspark('df.filter(col("hostname").upper().contains("SERVER"))')
        c = r["conditions"][0]
        assert c["field"] == "hostname"
        assert c.get("case_insensitive") is True

    def test_lower_with_like(self):
        r = parse_pyspark('df.filter(lower(col("hostname")).like("%.corp.%"))')
        c = r["conditions"][0]
        assert c["op"] == "like"
        assert c["value"] == "%.corp.%"
        assert c.get("case_insensitive") is True

    def test_lower_in_comparison(self):
        r = parse_pyspark('df.filter(lower(col("name")) == "alice")')
        c = r["conditions"][0]
        assert c["field"] == "name"
        assert c.get("case_insensitive") is True


class TestEngineEval:
    """End-to-end smoke: translator output + engine eval on a small graph."""

    def setup_method(self):
        import networkx as nx
        from data.query.query_engine import resolve_query
        self.resolve_query = resolve_query
        G = nx.MultiDiGraph()
        G.add_node("a", label="alpha-server", packets=100, protocols={"DNS", "TCP"})
        G.add_node("b", label="BETA-host", packets=5, protocols={"UDP"})
        G.add_node("c", label="gamma", packets=50, protocols=set())
        self.G = G

    def _run(self, expr):
        return self.resolve_query(self.G, parse_pyspark(expr))

    def test_like_anchors_full_match(self):
        # like is anchored (re.fullmatch); 'alpha%' should match 'alpha-server', not partial.
        r = self._run('df.filter(col("label").like("alpha%"))')
        ids = {n["id"] for n in r["matched_nodes"]}
        assert ids == {"a"}

    def test_like_default_case_sensitive(self):
        # like is CS by default — 'beta%' should NOT match 'BETA-host'.
        r = self._run('df.filter(col("label").like("beta%"))')
        assert r["matched_nodes"] == []

    def test_like_case_insensitive_via_lower(self):
        r = self._run('df.filter(lower(col("label")).like("beta%"))')
        ids = {n["id"] for n in r["matched_nodes"]}
        assert ids == {"b"}

    def test_negate_inverts(self):
        r = self._run('df.filter(~(col("packets") > 50))')
        ids = {n["id"] for n in r["matched_nodes"]}
        assert ids == {"b", "c"}

    def test_ends_with_engine(self):
        # Regression: ends_with was emitted by translator but unrecognised by engine.
        r = self._run('df.filter(col("label").endswith("server"))')
        ids = {n["id"] for n in r["matched_nodes"]}
        assert ids == {"a"}
