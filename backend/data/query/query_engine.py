"""
Query engine for the SwiftEye analysis graph.

Evaluates structured JSON queries against a persistent NetworkX graph.
Supports numeric, count-of, set, string, boolean, and in_set (named-group
membership) operators with AND/OR logic combinators. Returns matched
node/edge IDs plus verb/scope/group metadata for the pipeline executor.

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
from typing import Any, Optional

from data.aggregator import NODE_FIELD_CATALOG, EDGE_CORE_FIELD_CATALOG
from data.edge_fields import EDGE_FIELD_CATALOG
from data.protocol_fields import all_protocol_catalogs

logger = logging.getLogger("swifteye.query_engine")


# ── Action / scope vocabulary ────────────────────────────────────────────
# Seven verbs, plus scope. Pipeline executor consumes these; resolve_query
# itself is verb-agnostic — it just produces match sets and passes metadata
# through for the pipeline to act on.

ACTIONS_VIEW  = {"highlight", "show_only", "hide"}
ACTIONS_GROUP = {"tag", "color", "cluster", "save_as_set"}
ACTIONS = ACTIONS_VIEW | ACTIONS_GROUP | {"select"}  # "select" kept as legacy alias
SCOPES  = {"viz", "global"}

# Group-expression verbs require a name (tag/color/cluster/save_as_set).
ACTIONS_REQUIRE_GROUP = {"tag", "color", "cluster", "save_as_set"}


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
IN_SET_OPS  = {"in_set"}


def _eval_in_set(item_id: Any, value: Any, named_sets: Optional[dict]) -> bool:
    """Evaluate in_set membership: is `item_id` in the named set `value`?

    Unknown set → False (logged once). `named_sets` shape: {name: {"target": str, "members": [ids]}}.
    """
    if named_sets is None:
        logger.warning("in_set op requires named_sets context; got None")
        return False
    name = str(value) if value is not None else ""
    entry = named_sets.get(name)
    if entry is None:
        logger.debug("in_set: unknown named set '%s'", name)
        return False
    members = entry.get("members", ()) if isinstance(entry, dict) else entry
    return item_id in set(members)


def _eval_condition(attrs: dict, condition: dict,
                    item_id: Any = None,
                    named_sets: Optional[dict] = None) -> bool:
    """Evaluate a single condition against a node/edge attribute dict.

    Honors `negate` (inverts result) and `case_insensitive` (passed to string ops).
    `item_id` and `named_sets` are only consulted by the `in_set` op.
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
    elif op in IN_SET_OPS:
        result = _eval_in_set(item_id, value, named_sets)
    else:
        logger.warning("Unknown operator: %s", op)
        result = False

    return (not result) if negate else result


# ── Main query resolver ──────────────────────────────────────────────────

def resolve_query(G, query: dict, named_sets: Optional[dict] = None) -> dict:
    """
    Resolve a structured query against a NetworkX analysis graph.

    Args:
        G: NetworkX graph (from build_analysis_graph)
        query: {
            "target": "nodes" | "edges",
            "conditions": [{"field": str, "op": str, "value": any,
                            "negate"?: bool, "case_insensitive"?: bool}, ...],
            "logic": "AND" | "OR",
            "action": one of ACTIONS (default "highlight"),
            "scope": "viz" | "global" (default "viz"),
            "group_name": str (required when action ∈ ACTIONS_REQUIRE_GROUP),
            "group_args": dict (verb-specific extras, e.g. {"color": "#ff0"})
        }
        named_sets: optional dict of {name: {"target", "members"}}; required
            only if any condition uses the `in_set` op.

    Returns (envelope, extends the legacy shape with pipeline-friendly keys):
        {
            "action": str, "scope": str, "target": str,
            "matches": [ids],                        # flat list (pipeline-primary)
            "group": {"name": str, "members": [ids]}?,  # only for group verbs
            "matched_nodes": [...],                  # legacy, kept for frontend compat
            "matched_edges": [...],                  # legacy
            "total_matched": int, "total_searched": int,
            "summary": str,
            "warnings": [str]                        # contract validation issues
        }
    """
    action = query.get("action") or "highlight"
    scope = (query.get("scope") or "viz").lower()
    group_name = query.get("group_name")
    group_args = query.get("group_args") or {}

    warnings: list[str] = []
    if action not in ACTIONS:
        warnings.append(f"Unknown action '{action}' — accepted but not one of {sorted(ACTIONS)}")
    if scope not in SCOPES:
        warnings.append(f"Unknown scope '{scope}' — falling back to 'viz'")
        scope = "viz"
    if action in ACTIONS_REQUIRE_GROUP and not group_name:
        warnings.append(f"action '{action}' requires group_name; ignoring group for this run")

    def _envelope(matched_nodes, matched_edges, total, total_matched, summary):
        flat_ids = [m["id"] for m in matched_nodes] + [m["id"] for m in matched_edges]
        env = {
            "action": action,
            "scope": scope,
            "target": query.get("target", "nodes"),
            "matches": flat_ids,
            "matched_nodes": matched_nodes,
            "matched_edges": matched_edges,
            "total_matched": total_matched,
            "total_searched": total,
            "summary": summary,
        }
        if action in ACTIONS_REQUIRE_GROUP and group_name:
            env["group"] = {
                "name": group_name,
                "members": list(flat_ids),
                "args": dict(group_args),
            }
        if warnings:
            env["warnings"] = warnings
        return env

    if G is None:
        return _envelope([], [], 0, 0, "No capture loaded")

    target = query.get("target", "nodes")
    conditions = query.get("conditions", [])
    logic = query.get("logic", "AND").upper()

    if not conditions:
        return _envelope([], [], 0, 0, "No conditions specified")

    matched_nodes = []
    matched_edges = []

    if target == "nodes":
        total = G.number_of_nodes()
        for node_id, attrs in G.nodes(data=True):
            results = [_eval_condition(attrs, c, item_id=node_id, named_sets=named_sets) for c in conditions]
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
            edge_id = f"{u}|{v}"
            results = [_eval_condition(attrs, c, item_id=edge_id, named_sets=named_sets) for c in conditions]
            match = all(results) if logic == "AND" else any(results)
            if match:
                details = {}
                for c, passed in zip(conditions, results):
                    if passed:
                        val = attrs.get(c["field"])
                        if isinstance(val, set):
                            val = sorted(str(v) for v in val)
                        details[c["field"]] = val
                matched_edges.append({"id": edge_id, "source": u, "target": v, "match_details": details})
    else:
        total = 0

    total_matched = len(matched_nodes) + len(matched_edges)
    summary = f"{total_matched} of {total} {target} matching query"

    return _envelope(matched_nodes, matched_edges, total, total_matched, summary)


def get_graph_schema(G) -> dict:
    """
    Return available fields with their types for all three query primitives.

    Always returns the declarative catalog (no capture needed).
    When G is provided, also merges in any plugin-emitted fields not in the catalog.
    """
    all_edge_groups = EDGE_CORE_FIELD_CATALOG + EDGE_FIELD_CATALOG

    # Flat maps from catalogs (backward compat: QueryBuilder dropdown uses these)
    node_fields = {f["name"]: f["type"] for g in NODE_FIELD_CATALOG for f in g["fields"]}
    edge_fields = {f["name"]: f["type"] for g in all_edge_groups  for f in g["fields"]}

    # Runtime: merge in plugin-emitted fields not covered by the catalog
    plugin_node: dict = {}
    plugin_edge: dict = {}
    if G is not None:
        def _t(v):
            if isinstance(v, set):            return "set"
            if isinstance(v, bool):           return "boolean"
            if isinstance(v, (int, float)):   return "numeric"
            return "string"
        for _, attrs in G.nodes(data=True):
            for k, v in attrs.items():
                if k not in node_fields and k not in plugin_node:
                    plugin_node[k] = _t(v)
        for _, _, attrs in G.edges(data=True):
            for k, v in attrs.items():
                if k not in edge_fields and k not in plugin_edge and k != "session_ids":
                    plugin_edge[k] = _t(v)

    return {
        # Flat maps — backward compat for QueryBuilder dropdown
        "node_fields":        {**node_fields, **plugin_node},
        "edge_fields":        {**edge_fields, **plugin_edge},
        # Structured groups — for Guide panel
        "node_groups":        NODE_FIELD_CATALOG,
        "edge_groups":        all_edge_groups,
        "session_groups":     all_protocol_catalogs(),
        # Plugin enrichment (non-empty only when capture loaded + plugins ran)
        "plugin_node_fields": plugin_node,
        "plugin_edge_fields": plugin_edge,
    }
