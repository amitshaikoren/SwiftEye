"""
Query text parser — converts Cypher / SQL / Spark SQL text into the
JSON query contract that resolve_query() accepts.

Architecture:
    Frontend sends raw query text → POST /api/query/parse
    This module parses with proper libraries → returns JSON contract
    JSON contract → resolve_query() (existing, unchanged)

Libraries:
    - SQL / Spark SQL: sqlglot (pure Python, 31+ dialects, full AST)
    - Cypher: custom tokenizer + recursive-descent parser (subset)

Why not graphglot for Cypher?
    graphglot (tested v0.5.0) is a GQL/ISO parser, not a practical
    openCypher parser. It fails on basic Cypher features: AND/OR in
    WHERE, CONTAINS, STARTS WITH, regex (=~). A custom parser for
    the WHERE-clause subset we need is more reliable.

    If a mature openCypher parser emerges in the Python ecosystem,
    swap in the Cypher section only — the JSON contract is stable.

Future (Phase 3):
    When the backend migrates to Neo4j/Postgres/PySpark, this module
    becomes a thin validation + transpilation layer:
    - Cypher → pass directly to Neo4j (no parsing needed)
    - SQL → pass directly to Postgres
    - Spark SQL → pass directly to PySpark
    - Cross-dialect: sqlglot transpiles SQL↔Spark SQL
    The JSON contract remains as a universal fallback for the visual builder.

JSON contract (consumed by resolve_query()):
    {
        "target": "nodes" | "edges",
        "conditions": [{"field": str, "op": str, "value": any}, ...],
        "logic": "AND" | "OR",
        "action": "highlight"
    }

Supported ops (must match query_engine.py):
    Numeric:  >, <, =, !=, >=, <=
    Count:    count_gt, count_lt, count_eq
    Set:      contains, contains_all, contains_any, is_empty, not_empty
    String:   equals, starts_with, ends_with, matches, like
    Boolean:  is_true, is_false

Modifiers (optional on any condition):
    negate: True            — Cypher NOT, SQL NOT (...)
    case_insensitive: bool  — currently only acted on for `like`
"""

import logging
import re
from .pyspark_translator import parse_pyspark
from typing import Optional, List, Tuple

logger = logging.getLogger("swifteye.query_parser")

# ── Dependency availability ─────────────────────────────────────────────

_HAS_SQLGLOT = False

try:
    import sqlglot
    from sqlglot import exp
    _HAS_SQLGLOT = True
except ImportError:
    logger.info("sqlglot not installed — SQL/Spark SQL parsing unavailable. pip install sqlglot")


# ── Syntax detection ────────────────────────────────────────────────────

def detect_syntax(text: str) -> Optional[str]:
    """Auto-detect query syntax from leading keywords.

    Returns 'cypher', 'sql', 'spark', 'pyspark', or None if unrecognised.
    """
    t = text.strip()
    tu = t.upper()
    if tu.startswith("MATCH"):
        return "cypher"
    if tu.startswith("SELECT"):
        return "sql"
    # PySpark detection: df.filter, df.where, col(), .filter(, .where(
    if any(kw in t for kw in ("df.filter", "df.where", ".filter(col(", ".where(col(", "col(")):
        return "pyspark"
    return None


# ═══════════════════════════════════════════════════════════════════════
#  CYPHER PARSER — custom tokenizer + recursive-descent
#  Handles the subset needed for SwiftEye graph queries:
#    MATCH (n) WHERE ... RETURN n              → target = nodes
#    MATCH (n)-[r]->(m) WHERE ... RETURN r     → target = edges
#    WHERE clause: field comparisons, AND/OR, CONTAINS, STARTS WITH,
#                  ENDS WITH, IS NULL, =~ regex, boolean literals
# ═══════════════════════════════════════════════════════════════════════

# ── Cypher tokenizer ───────────────────────────────────────────────────

_CYPHER_KEYWORDS = {
    "MATCH", "WHERE", "RETURN", "AND", "OR", "NOT",
    "CONTAINS", "STARTS", "WITH", "ENDS", "IS", "NULL",
    "TRUE", "FALSE", "IN", "AS", "ORDER", "BY",
    "LIMIT", "SKIP", "DESC", "ASC",
}

_CYPHER_TOKEN_RE = re.compile(r"""
    (?P<STRING>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')  |  # quoted string
    (?P<NUMBER>-?\d+(?:\.\d+)?)                       |  # number
    (?P<REGEX_OP>=~)                                   |  # regex operator
    (?P<CMP><>|>=|<=|!=|>|<|=)                         |  # comparison
    (?P<DOT>\.)                                        |  # dot
    (?P<LPAREN>\()                                     |  # (
    (?P<RPAREN>\))                                     |  # )
    (?P<LBRACKET>\[)                                   |  # [
    (?P<RBRACKET>\])                                   |  # ]
    (?P<DASH>-)                                        |  # -
    (?P<ARROW>>)                                       |  # > (arrow tip, only after dash)
    (?P<COMMA>,)                                       |  # ,
    (?P<IDENT>[A-Za-z_][A-Za-z0-9_]*)                 |  # identifier/keyword
    (?P<WS>\s+)                                           # whitespace
""", re.VERBOSE)


def _tokenize_cypher(text: str) -> List[Tuple[str, str]]:
    """Tokenize Cypher text into (type, value) pairs."""
    tokens = []
    for m in _CYPHER_TOKEN_RE.finditer(text):
        kind = m.lastgroup
        value = m.group()
        if kind == "WS":
            continue
        if kind == "IDENT" and value.upper() in _CYPHER_KEYWORDS:
            kind = value.upper()  # promote to keyword token
        if kind == "STRING":
            value = value[1:-1]  # strip quotes
        tokens.append((kind, value))
    return tokens


# ── Cypher recursive-descent parser ────────────────────────────────────

class _CypherParser:
    """Parse a tokenized Cypher query into the JSON contract."""

    def __init__(self, tokens):
        self.tokens = tokens
        self.pos = 0

    def peek(self, offset=0):
        i = self.pos + offset
        return self.tokens[i] if i < len(self.tokens) else (None, None)

    def advance(self):
        tok = self.tokens[self.pos] if self.pos < len(self.tokens) else (None, None)
        self.pos += 1
        return tok

    def expect(self, kind):
        tok = self.advance()
        if tok[0] != kind:
            raise ValueError(f"Expected {kind}, got {tok[0]} ('{tok[1]}')")
        return tok

    def at_end(self):
        return self.pos >= len(self.tokens)

    # ── MATCH clause ──

    def parse(self):
        self.expect("MATCH")
        target, return_var = self._parse_pattern()

        conditions = []
        logic = "AND"

        # WHERE clause (optional)
        if not self.at_end() and self.peek()[0] == "WHERE":
            self.advance()  # consume WHERE
            conditions, logic = self._parse_where()

        # RETURN clause (optional — extract action hint)
        action = "highlight"
        if not self.at_end() and self.peek()[0] == "RETURN":
            self.advance()  # consume RETURN
            # Skip return items — we don't use them for the contract

        return {
            "target": target,
            "conditions": conditions,
            "logic": logic,
            "action": action,
        }

    # ── Pattern: (n) or (n)-[r]->(m) ──

    def _parse_pattern(self):
        """Parse MATCH pattern, detect nodes vs edges."""
        self.expect("LPAREN")
        node_var = self.expect("IDENT")[1]
        self.expect("RPAREN")

        # Check for edge pattern: -[r]->
        if not self.at_end() and self.peek()[0] == "DASH":
            self.advance()  # -
            self.expect("LBRACKET")
            edge_var = self.expect("IDENT")[1]
            self.expect("RBRACKET")
            self.expect("DASH")
            # Optional arrow direction >
            if not self.at_end() and self.peek()[0] == "ARROW":
                self.advance()
            elif not self.at_end() and self.peek()[0] == "CMP" and self.peek()[1] == ">":
                self.advance()
            self.expect("LPAREN")
            _other_var = self.expect("IDENT")[1]
            self.expect("RPAREN")
            return "edges", edge_var

        return "nodes", node_var

    # ── WHERE clause ──

    def _parse_where(self):
        """Parse WHERE conditions, return (conditions_list, logic)."""
        conditions = []
        logic_ops = []

        cond = self._parse_condition()
        if cond:
            conditions.append(cond)

        while not self.at_end() and self.peek()[0] in ("AND", "OR"):
            op_tok = self.advance()
            logic_ops.append(op_tok[0])
            cond = self._parse_condition()
            if cond:
                conditions.append(cond)

        # Determine logic — if mixed AND/OR, reject
        unique_ops = set(logic_ops)
        if len(unique_ops) > 1:
            raise ValueError("Mixed AND/OR not supported — use parentheses or split into separate queries")
        logic = unique_ops.pop() if unique_ops else "AND"

        return conditions, logic

    def _parse_condition(self):
        """Parse a single condition: field.prop OP value or count(field) OP value.

        A leading NOT applies a `negate: True` modifier to the resulting condition.
        """
        negated = False
        if self.peek()[0] == "NOT":
            self.advance()
            negated = True

        is_count = False
        if self.peek()[0] == "IDENT" and self.peek()[1].lower() == "count":
            if self.peek(1)[0] == "LPAREN":
                self.advance()  # consume 'count'
                self.advance()  # consume '('
                is_count = True

        field_name = self._parse_field_ref()

        if is_count:
            self.expect("RPAREN")

        cond = self._parse_op_and_value(field_name, is_count)
        if negated and cond is not None:
            cond["negate"] = True
        return cond

    def _parse_op_and_value(self, field_name, is_count):
        """Parse the operator + value half of a condition (split out for NOT composition)."""
        tok_type, tok_val = self.peek()

        if tok_type == "IS":
            self.advance()
            next_type, _ = self.peek()
            if next_type == "NULL":
                self.advance()
                return {"field": field_name, "op": "is_empty"}
            if next_type == "TRUE":
                self.advance()
                return {"field": field_name, "op": "is_true"}
            if next_type == "FALSE":
                self.advance()
                return {"field": field_name, "op": "is_false"}
            if next_type == "NOT":
                self.advance()
                nn_type, _ = self.peek()
                if nn_type == "NULL":
                    self.advance()
                    return {"field": field_name, "op": "not_empty"}
                raise ValueError(f"Expected NULL after IS NOT, got {nn_type}")
            raise ValueError(f"Expected NULL/TRUE/FALSE after IS, got {next_type}")

        if tok_type == "CONTAINS":
            self.advance()
            return {"field": field_name, "op": "contains", "value": self._parse_value()}

        if tok_type == "STARTS":
            self.advance()
            self.expect("WITH")
            return {"field": field_name, "op": "starts_with", "value": self._parse_value()}

        if tok_type == "ENDS":
            self.advance()
            self.expect("WITH")
            return {"field": field_name, "op": "ends_with", "value": self._parse_value()}

        if tok_type == "IN":
            self.advance()
            return {"field": field_name, "op": "contains_any", "value": self._parse_list()}

        if tok_type == "REGEX_OP":
            self.advance()
            return {"field": field_name, "op": "matches", "value": self._parse_value()}

        if tok_type == "CMP":
            self.advance()
            op_str = "!=" if tok_val == "<>" else tok_val
            value = self._parse_value()
            if is_count:
                count_op_map = {">": "count_gt", "<": "count_lt", "=": "count_eq",
                                ">=": "count_gt", "<=": "count_lt"}
                return {"field": field_name, "op": count_op_map.get(op_str, "count_gt"), "value": value}
            if op_str == "=" and not _looks_numeric(value):
                return {"field": field_name, "op": "equals", "value": value}
            return {"field": field_name, "op": op_str, "value": value}

        raise ValueError(f"Expected operator after '{field_name}', got {tok_type} ('{tok_val}')")

    def _parse_field_ref(self):
        """Parse var.property or just property → returns the property name."""
        name = self.expect("IDENT")[1]
        if not self.at_end() and self.peek()[0] == "DOT":
            self.advance()  # consume .
            prop = self.expect("IDENT")[1]
            return prop  # strip the variable prefix (n.packets → packets)
        return name

    def _parse_value(self):
        """Parse a literal value (string, number, boolean)."""
        tok_type, tok_val = self.peek()
        if tok_type == "STRING":
            self.advance()
            return tok_val
        if tok_type == "NUMBER":
            self.advance()
            return tok_val
        if tok_type == "TRUE":
            self.advance()
            return "true"
        if tok_type == "FALSE":
            self.advance()
            return "false"
        if tok_type == "IDENT":
            # Bare identifier used as value (e.g. TCP without quotes)
            self.advance()
            return tok_val
        raise ValueError(f"Expected value, got {tok_type} ('{tok_val}')")

    def _parse_list(self):
        """Parse [val1, val2, ...] → list of strings."""
        self.expect("LBRACKET")
        values = []
        while self.peek()[0] != "RBRACKET":
            values.append(self._parse_value())
            if self.peek()[0] == "COMMA":
                self.advance()
        self.expect("RBRACKET")
        return values


def _looks_numeric(val):
    """Check if a value string looks numeric."""
    try:
        float(val)
        return True
    except (TypeError, ValueError):
        return False


def parse_cypher(text: str) -> dict:
    """Parse a Cypher query string into the JSON query contract.

    Supports: MATCH (n) / MATCH (n)-[r]->(m) patterns
    WHERE: comparisons, AND/OR, CONTAINS, STARTS WITH, ENDS WITH,
           IS NULL/TRUE/FALSE, IN [...], =~ regex

    Returns: { target, conditions, logic, action } or { error: str }
    """
    try:
        tokens = _tokenize_cypher(text)
        if not tokens:
            return {"error": "Empty or unparseable Cypher query"}
        parser = _CypherParser(tokens)
        return parser.parse()
    except (ValueError, IndexError) as e:
        return {"error": f"Cypher parse error: {e}"}


# ═══════════════════════════════════════════════════════════════════════
#  SQL / SPARK SQL PARSER — powered by sqlglot
#  Parses: SELECT * FROM nodes|edges WHERE ... [-- action]
#  Walks the sqlglot AST to extract field/op/value conditions.
# ═══════════════════════════════════════════════════════════════════════

def _walk_sql_condition(node) -> Tuple[List[dict], str]:
    """Recursively walk a sqlglot WHERE expression tree.

    Returns (conditions_list, logic_operator).
    """
    if isinstance(node, exp.And):
        left_conds, _ = _walk_sql_condition(node.this)
        right_conds, _ = _walk_sql_condition(node.expression)
        return left_conds + right_conds, "AND"

    if isinstance(node, exp.Or):
        left_conds, _ = _walk_sql_condition(node.this)
        right_conds, _ = _walk_sql_condition(node.expression)
        return left_conds + right_conds, "OR"

    if isinstance(node, exp.Paren):
        return _walk_sql_condition(node.this)

    if isinstance(node, exp.Not):
        inner_conds, logic = _walk_sql_condition(node.this)
        # Toggle the negate modifier on each returned condition (double-NOT cancels).
        for c in inner_conds:
            new_val = not c.get("negate", False)
            if new_val:
                c["negate"] = True
            else:
                c.pop("negate", None)
        return inner_conds, logic

    # ── Leaf conditions ──

    # Comparison: >, <, =, !=, >=, <=
    _CMP_MAP = {
        exp.GT: ">", exp.LT: "<", exp.EQ: "=", exp.NEQ: "!=",
        exp.GTE: ">=", exp.LTE: "<=",
    }
    _COUNT_OP_MAP = {">": "count_gt", "<": "count_lt", "=": "count_eq",
                     ">=": "count_gt", "<=": "count_lt"}
    for exp_type, op_str in _CMP_MAP.items():
        if isinstance(node, exp_type):
            field = _sql_field_name(node.this)
            value = _sql_literal_value(node.expression)
            if field and value is not None:
                # COUNT(field) > N → count_gt/count_lt/count_eq
                if isinstance(node.this, exp.Count):
                    cop = _COUNT_OP_MAP.get(op_str, "count_gt")
                    return [{"field": field, "op": cop, "value": value}], "AND"
                if op_str == "=" and not _looks_numeric(value):
                    return [{"field": field, "op": "equals", "value": value}], "AND"
                return [{"field": field, "op": op_str, "value": value}], "AND"

    # LIKE / NOT LIKE → unified `like` op (engine handles % and _ properly).
    # Some sqlglot versions expose NOT LIKE as exp.NotLike; normalize both.
    is_like = isinstance(node, exp.Like)
    is_not_like = hasattr(exp, "NotLike") and isinstance(node, getattr(exp, "NotLike"))
    if is_like or is_not_like:
        field = _sql_field_name(node.this)
        pattern = _sql_literal_value(node.expression)
        if field and pattern is not None:
            cond = {"field": field, "op": "like", "value": str(pattern)}
            if is_not_like:
                cond["negate"] = True
            return [cond], "AND"

    # IS (NULL / TRUE / FALSE)
    if isinstance(node, exp.Is):
        field = _sql_field_name(node.this)
        right = node.expression
        if isinstance(right, exp.Null):
            return [{"field": field, "op": "is_empty"}], "AND"
        if isinstance(right, exp.Boolean):
            if right.this:
                return [{"field": field, "op": "is_true"}], "AND"
            else:
                return [{"field": field, "op": "is_false"}], "AND"

    # IN (value_list)
    if isinstance(node, exp.In):
        field = _sql_field_name(node.this)
        values = []
        for child in node.expressions:
            v = _sql_literal_value(child)
            if v is not None:
                values.append(v)
        if field and values:
            return [{"field": field, "op": "contains_any", "value": values}], "AND"

    # ARRAY_CONTAINS(field, value) → contains
    if isinstance(node, exp.ArrayContains):
        field = _sql_field_name(node.this)
        value = _sql_literal_value(node.expression)
        if field and value is not None:
            return [{"field": field, "op": "contains", "value": value}], "AND"

    # COUNT(field) > N  → wrapped in a comparison, field is inside Count()
    # This is handled by the comparison branch above — the field extraction
    # handles Count() expressions by looking inside.

    # Fallback: unrecognised expression
    logger.warning("Unrecognised SQL condition: %s (%s)", node, type(node).__name__)
    return [], "AND"


def _sql_field_name(node) -> Optional[str]:
    """Extract field name from a sqlglot expression node."""
    if isinstance(node, exp.Column):
        return node.name
    if isinstance(node, exp.Count):
        # COUNT(field) — extract inner field, prefix with count_
        inner = node.this
        if isinstance(inner, exp.Column):
            return inner.name
    if hasattr(node, "name"):
        return node.name
    return str(node) if node else None


def _sql_literal_value(node) -> Optional[str]:
    """Extract literal value from a sqlglot expression node."""
    if isinstance(node, exp.Literal):
        return node.this
    if isinstance(node, exp.Boolean):
        return "true" if node.this else "false"
    if isinstance(node, exp.Null):
        return None
    if isinstance(node, exp.Column):
        # Bare identifier used as value (sqlglot treats unquoted strings as columns)
        return node.name
    if isinstance(node, exp.Neg):
        inner = _sql_literal_value(node.this)
        if inner is not None:
            return f"-{inner}"
    if hasattr(node, "this") and isinstance(node.this, str):
        return node.this
    return str(node) if node else None


def _extract_sql_action(text: str) -> str:
    """Extract action hint from a trailing SQL comment: -- highlight."""
    m = re.search(r"--\s*(\w+)\s*$", text.strip())
    if m:
        action = m.group(1).lower()
        if action in ("highlight", "select", "group", "hide", "isolate"):
            return action
    return "highlight"


def parse_sql(text: str, dialect: str = "sql") -> dict:
    """Parse a SQL or Spark SQL query string into the JSON query contract.

    Syntax: SELECT * FROM nodes|edges WHERE conditions [-- action]

    Args:
        text: Raw SQL string
        dialect: 'sql' for standard SQL, 'spark' for Spark SQL

    Returns: { target, conditions, logic, action } or { error: str }
    """
    if not _HAS_SQLGLOT:
        return {"error": "sqlglot not installed. pip install sqlglot"}

    try:
        read_dialect = "spark" if dialect == "spark" else None
        ast = sqlglot.parse_one(text, read=read_dialect)
    except sqlglot.errors.ParseError as e:
        return {"error": f"SQL parse error: {e}"}

    # Target: FROM clause → 'nodes' or 'edges'
    from_clause = ast.find(exp.From)
    if not from_clause:
        return {"error": "Missing FROM clause — expected SELECT * FROM nodes|edges WHERE ..."}

    table = from_clause.find(exp.Table)
    table_name = table.name.lower() if table else ""
    if table_name in ("nodes", "node", "n"):
        target = "nodes"
    elif table_name in ("edges", "edge", "e", "connections", "links"):
        target = "edges"
    else:
        return {"error": f"Unknown table '{table_name}' — use 'nodes' or 'edges'"}

    # Conditions: WHERE clause
    where_clause = ast.find(exp.Where)
    conditions = []
    logic = "AND"

    if where_clause:
        conditions, logic = _walk_sql_condition(where_clause.this)

    # Detect mixed AND/OR (unsupported by flat contract)
    if conditions:
        # Check if the WHERE tree contains both AND and OR at the top level
        if where_clause:
            has_and = bool(ast.find(exp.And))
            has_or = bool(ast.find(exp.Or))
            if has_and and has_or:
                return {"error": "Mixed AND/OR not supported — use only AND or only OR in your WHERE clause"}

    # Action: trailing comment or default
    action = _extract_sql_action(text)

    return {
        "target": target,
        "conditions": conditions,
        "logic": logic,
        "action": action,
    }


# ── Unified parse entry point ───────────────────────────────────────────

def parse_query_text(text: str, dialect: Optional[str] = None) -> dict:
    """Parse a query string in any supported syntax.

    Auto-detects syntax if dialect is None.

    Returns:
        { syntax: str, query: { target, conditions, logic, action } }
        or { syntax: str|None, error: str }
    """
    if not text or not text.strip():
        return {"syntax": None, "error": "Empty query"}

    syntax = dialect or detect_syntax(text)

    if syntax == "cypher":
        result = parse_cypher(text)
    elif syntax in ("sql", "spark"):
        result = parse_sql(text, dialect=syntax if syntax == "spark" else "sql")
    elif syntax == "pyspark":
        result = parse_pyspark(text)
    else:
        return {"syntax": None, "error": "Unrecognised syntax. Start with MATCH (Cypher), SELECT (SQL), or df.filter (PySpark)."}

    if "error" in result:
        return {"syntax": syntax, "error": result["error"]}

    return {"syntax": syntax, "query": result}


# ── Transpilation (future) ──────────────────────────────────────────────

def transpile(text: str, from_dialect: str, to_dialect: str) -> str:
    """Transpile a query between dialects using sqlglot.

    Future use: user writes SQL, backend is Neo4j → transpile SQL to Cypher.

    TODO: Implement once backend engine selection exists.
    """
    if not _HAS_SQLGLOT:
        raise RuntimeError("sqlglot not installed")

    # sqlglot.transpile(text, read=from_dialect, write=to_dialect)[0]
    raise NotImplementedError("Transpilation not yet implemented")
