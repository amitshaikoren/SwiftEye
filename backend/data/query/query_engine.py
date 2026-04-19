"""
Query engine for the SwiftEye analysis graph.

Evaluates structured JSON queries against a persistent NetworkX graph.
Supports numeric, count-of, set, string, and boolean operators with
AND/OR logic combinators. Returns matched node/edge IDs.

Engine-agnostic design: this module resolves queries against NetworkX.
Future backends (Neo4j, SQL, PySpark) would replace this resolver
while keeping the same query contract.

Condition modifiers (optional, on any condition dict):
    negate: bool            — invert the result of this condition
    case_insensitive: bool  — for string/like ops; tristate semantics:
                              omitted   → engine default per op
                              True      → force case-insensitive
                              False     → force case-sensitive
"""

import re
import logging
from typing import Any

logger = logging.getLogger("swifteye.query_engine")


# ── Operator evaluation ──────────────────────────────────────────────────

def _eval_numeric(attr_val: Any, op: str, value: Any) -> bool:
    """Evaluate numeric operators: >, <, =, !=, >=, <=."""
    try:
        a = float(attr_val) if attr_val is not None else 0
        b = float(value)
    except (TypeError, ValueError):
        return False
    if op == ">":  return a > b
    if op == "<":  return a < b
    if op == "=":  return a == b
    if op == "!=": return a != b
    if op == ">=": return a >= b
    if op == "<=": return a <= b
    return False


def _eval_count(attr_val: Any, op: str, value: Any) -> bool:
    """Evaluate count-of operators on set/list fields: count_gt, count_lt, count_eq."""
    try:
        count = len(attr_val) if attr_val is not None else 0
        target = int(value)
    except (TypeError, ValueError):
        return False
    if op == "count_gt": return count > target
    if op == "count_lt": return count < target
    if op == "count_eq": return count == target
    return False


def _eval_set(attr_val: Any, op: str, value: Any) -> bool:
    """Evaluate set operators: contains, contains_all, contains_any, is_empty, not_empty."""
    if attr_val is None:
        attr_val = set()
    if isinstance(attr_val, (list, tuple)):
        attr_val = set(attr_val)
    if not isinstance(attr_val, set):
        attr_val = {attr_val}

    if op == "is_empty":    return len(attr_val) == 0
    if op == "not_empty":   return len(attr_val) > 0

    if isinstance(value, (list, tuple)):
        target = set(str(v) for v in value)
    else:
        target = {str(value)}

    attr_strs = set(str(v) for v in attr_val)

    if op == "contains":     return target.issubset(attr_strs)
    if op == "contains_all": return target.issubset(attr_strs)
    if op == "contains_any": return bool(target & attr_strs)
    return False


def _like_to_regex(pattern: str) -> str:
    """Convert SQL LIKE pattern to anchored regex source.

    % → .*    _ → .    other regex metachars escaped.
    Backslash escapes the next character literally.
    """
    out = []
    i = 0
    n = len(pattern)
    while i < n:
        c = pattern[i]
        if c == "\\" and i + 1 < n:
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        if c == "%":
            out.append(".*")
        elif c == "_":
            out.append(".")
        else:
            out.append(re.escape(c))
        i += 1
    return "".join(out)


def _eval_string(attr_val: Any, op: str, value: Any, case_insensitive: Any = None) -> bool:
    """Evaluate string operators: equals, starts_with, ends_with, matches (regex), like.

    case_insensitive tristate:
        None   → engine default: like=CS, others=CI (preserves prior behavior)
        True   → force CI
        False  → force CS
    """
    if attr_val is None:
        return False

    if isinstance(attr_val, (set, list, tuple)):
        return any(_eval_string(item, op, value, case_insensitive) for item in attr_val)

    a_raw = str(attr_val)
    b_raw = str(value)

    if case_insensitive is None:
        ci = (op != "like")
    else:
        ci = bool(case_insensitive)

    if op == "like":
        regex = _like_to_regex(b_raw)
        flags = re.IGNORECASE if ci else 0
        try:
            return bool(re.fullmatch(regex, a_raw, flags))
        except re.error:
            return False

    if op == "matches":
        flags = re.IGNORECASE if ci else 0
        try:
            return bool(re.search(b_raw, a_raw, flags))
        except re.error:
            return False

    if ci:
        a, b = a_raw.lower(), b_raw.lower()
    else:
        a, b = a_raw, b_raw

    if op == "equals":      return a == b
    if op == "starts_with": return a.startswith(b)
    if op == "ends_with":   return a.endswith(b)
    return False


def _eval_boolean(attr_val: Any, op: str, _value: Any) -> bool:
    """Evaluate boolean operators: is_true, is_false."""
    if op == "is_true":  return bool(attr_val)
    if op == "is_false": return not bool(attr_val)
    return False


# ── Operator dispatch ────────────────────────────────────────────────────

NUMERIC_OPS = {">", "<", "=", "!=", ">=", "<="}
COUNT_OPS   = {"count_gt", "count_lt", "count_eq"}
SET_OPS     = {"contains", "contains_all", "contains_any", "is_empty", "not_empty"}
STRING_OPS  = {"equals", "starts_with", "ends_with", "matches", "like"}
BOOL_OPS    = {"is_true", "is_false"}


def _eval_condition(attrs: dict, condition: dict) -> bool:
    """Evaluate a single condition against a node/edge attribute dict.

    Honors `negate` (inverts result) and `case_insensitive` (passed to string ops).
    """
    field = condition.get("field", "")
    op = condition.get("op", "")
    value = condition.get("value")
    negate = condition.get("negate", False)
    case_insensitive = condition.get("case_insensitive")

    attr_val = attrs.get(field)

    if op in NUMERIC_OPS:
        result = _eval_numeric(attr_val, op, value)
    elif op in COUNT_OPS:
        result = _eval_count(attr_val, op, value)
    elif op in SET_OPS:
        result = _eval_set(attr_val, op, value)
    elif op in STRING_OPS:
        result = _eval_string(attr_val, op, value, case_insensitive)
    elif op in BOOL_OPS:
        result = _eval_boolean(attr_val, op, value)
    else:
        logger.warning("Unknown operator: %s", op)
        result = False

    return (not result) if negate else result


# ── Main query resolver ──────────────────────────────────────────────────

def resolve_query(G, query: dict) -> dict:
    """
    Resolve a structured query against a NetworkX analysis graph.

    Args:
        G: NetworkX graph (from build_analysis_graph)
        query: {
            "target": "nodes" | "edges",
            "conditions": [{"field": str, "op": str, "value": any,
                            "negate"?: bool, "case_insensitive"?: bool}, ...],
            "logic": "AND" | "OR",
            "action": "highlight" | "select"
        }

    Returns: {
        "matched_nodes": [{"id": str, "match_details": dict}, ...],
        "matched_edges": [{"id": str, "source": str, "target": str, "match_details": dict}, ...],
        "action": str,
        "total_matched": int,
        "total_searched": int,
        "summary": str
    }
    """
    if G is None:
        return {
            "matched_nodes": [], "matched_edges": [],
            "action": query.get("action", "highlight"),
            "total_matched": 0, "total_searched": 0,
            "summary": "No capture loaded"
        }

    target = query.get("target", "nodes")
    conditions = query.get("conditions", [])
    logic = query.get("logic", "AND").upper()
    action = query.get("action", "highlight")

    if not conditions:
        return {
            "matched_nodes": [], "matched_edges": [],
            "action": action,
            "total_matched": 0, "total_searched": 0,
            "summary": "No conditions specified"
        }

    matched_nodes = []
    matched_edges = []

    if target == "nodes":
        total = G.number_of_nodes()
        for node_id, attrs in G.nodes(data=True):
            results = [_eval_condition(attrs, c) for c in conditions]
            match = all(results) if logic == "AND" else any(results)
            if match:
                details = {}
                for c, passed in zip(conditions, results):
                    if passed:
                        val = attrs.get(c["field"])
                        if isinstance(val, set):
                            val = sorted(str(v) for v in val)
                        details[c["field"]] = val
                matched_nodes.append({"id": node_id, "match_details": details})

    elif target == "edges":
        total = G.number_of_edges()
        for u, v, attrs in G.edges(data=True):
            results = [_eval_condition(attrs, c) for c in conditions]
            match = all(results) if logic == "AND" else any(results)
            if match:
                details = {}
                for c, passed in zip(conditions, results):
                    if passed:
                        val = attrs.get(c["field"])
                        if isinstance(val, set):
                            val = sorted(str(v) for v in val)
                        details[c["field"]] = val
                edge_id = f"{u}|{v}"
                matched_edges.append({"id": edge_id, "source": u, "target": v, "match_details": details})
    else:
        total = 0

    total_matched = len(matched_nodes) + len(matched_edges)
    summary = f"{total_matched} of {total} {target} matching query"

    return {
        "matched_nodes": matched_nodes,
        "matched_edges": matched_edges,
        "action": action,
        "total_matched": total_matched,
        "total_searched": total,
        "summary": summary,
    }


def get_graph_schema(G) -> dict:
    """
    Inspect the analysis graph and return available fields with their types.

    Used by the frontend to build the dynamic query dropdown. Fields are
    categorized by Python type: set → "set", int/float → "numeric",
    bool → "boolean", str → "string".
    """
    if G is None:
        return {"node_fields": {}, "edge_fields": {}}

    def _infer_fields(items):
        fields = {}
        for item in items:
            attrs = item[-1]
            for key, val in attrs.items():
                if key in fields:
                    continue
                if isinstance(val, set):
                    fields[key] = "set"
                elif isinstance(val, bool):
                    fields[key] = "boolean"
                elif isinstance(val, (int, float)):
                    fields[key] = "numeric"
                elif isinstance(val, str):
                    fields[key] = "string"
        return fields

    return {
        "node_fields": _infer_fields(G.nodes(data=True)),
        "edge_fields": _infer_fields(G.edges(data=True)),
    }
