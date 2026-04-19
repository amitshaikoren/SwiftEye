"""
PySpark DataFrame expression → query contract translator.

Translates PySpark-style filter expressions into the JSON query contract
that resolve_query() accepts. Uses Python's stdlib `ast` module to parse
PySpark as actual Python code — no new dependencies.

Supported subset:
    df.filter(col("packets") > 1000)
    df.where(col("protocols").contains("DNS"))
    df.filter((col("packets") > 100) & (col("bytes") > 5000))
    df.filter(col("os_guess").startswith("Win"))
    df.filter(col("packets").isNull())
    df.filter(col("protocols").isin(["DNS", "HTTP"]))
    df.filter(col("is_private") == True)
    df.filter(col("hostname").like("%.corp.%"))
    df.filter(~(col("packets") > 1000))
    df.filter(lower(col("hostname")).contains("server"))
    df.filter(col("hostname").lower().contains("server"))

Modifiers attached to conditions:
    negate            — set by `~` (bitwise invert) wrapping a sub-expression
    case_insensitive  — set by `lower()` / `upper()` wrapping the col

Also accepts bare expressions (no df.filter wrapper):
    col("packets") > 1000
    (col("packets") > 100) & (col("bytes") > 5000)

Target detection:
    "nodes" or "edges" from the df variable name, or explicit
    df = spark.table("nodes")  /  df = spark.table("edges")
    Defaults to "nodes" if ambiguous.
"""

import ast
import logging
from typing import Optional

logger = logging.getLogger("swifteye.pyspark_translator")


# ── Method dispatch table ─────────────────────────────────────────────

NO_ARG = "NO_ARG"
ARG_REQUIRED = "ARG_REQUIRED"
LIST_ARG = "LIST_ARG"

# Method name → (engine_op, arg_kind). Adding a method = one line.
METHOD_MAP = {
    "contains":   ("contains",     ARG_REQUIRED),
    "startswith": ("starts_with",  ARG_REQUIRED),
    "endswith":   ("ends_with",    ARG_REQUIRED),
    "isNull":     ("is_empty",     NO_ARG),
    "isNotNull":  ("not_empty",    NO_ARG),
    "isin":       ("contains_any", LIST_ARG),
    "rlike":      ("matches",      ARG_REQUIRED),
    "like":       ("like",         ARG_REQUIRED),
}


def parse_pyspark(text: str) -> dict:
    """Parse PySpark DataFrame filter expression into query contract.

    Returns:
        {"target": str, "conditions": [...], "logic": str, "action": "highlight"}
        or {"error": str}
    """
    text = text.strip()
    if not text:
        return {"error": "Empty expression"}

    # Auto-correct JS-style operators to Python/PySpark equivalents.
    text = text.replace("||", "|").replace("&&", "&")

    target = _detect_target(text)
    expr_text = _extract_filter_expr(text)

    if not expr_text:
        return {"error": "Could not find filter/where expression. Use: df.filter(col(\"field\") > value)"}

    try:
        tree = ast.parse(expr_text, mode="eval")
    except SyntaxError as e:
        return {"error": f"Invalid Python expression: {e.msg}"}

    try:
        conditions, logic = _walk_expr(tree.body)
    except TranslationError as e:
        return {"error": str(e)}

    if not conditions:
        return {"error": "No conditions found in expression"}

    return {
        "target": target,
        "conditions": conditions,
        "logic": logic,
        "action": "highlight",
    }


class TranslationError(Exception):
    pass


# ── Target detection ──────────────────────────────────────────────────

def _detect_target(text: str) -> str:
    """Detect whether query targets nodes or edges from variable names or table refs."""
    t = text.lower()
    if "edges" in t or "edge" in t:
        return "edges"
    if "nodes" in t or "node" in t:
        return "nodes"
    if ".filter(" in t or ".where(" in t:
        before = t.split(".filter(")[0] if ".filter(" in t else t.split(".where(")[0]
        before = before.strip().split("=")[-1].strip() if "=" in before else before.strip()
        if "edge" in before:
            return "edges"
    return "nodes"


# ── Expression extraction ─────────────────────────────────────────────

def _extract_filter_expr(text: str) -> Optional[str]:
    """Extract the inner expression from df.filter(...) or df.where(...)."""
    text = text.strip()

    try:
        tree = ast.parse(text, mode="eval")
        return _find_filter_arg(tree.body)
    except SyntaxError:
        pass

    try:
        tree = ast.parse(text, mode="exec")
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                arg = _find_filter_arg_from_call(node)
                if arg:
                    return arg
    except SyntaxError:
        pass

    return None


def _find_filter_arg(node) -> Optional[str]:
    """Recursively find the innermost filter/where call and return its argument as source."""
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("filter", "where"):
            if node.args:
                return ast.unparse(node.args[0])
        if isinstance(node.func, ast.Attribute):
            inner = _find_filter_arg(node.func.value)
            if inner:
                outer_arg = ast.unparse(node.args[0]) if node.args else None
                if outer_arg:
                    return f"({inner}) & ({outer_arg})"
                return inner
        return _find_filter_arg_from_call(node)

    src = ast.unparse(node)
    if "col(" in src or "column(" in src:
        return src

    return None


def _find_filter_arg_from_call(node) -> Optional[str]:
    """Extract filter arg from a Call node."""
    if not isinstance(node, ast.Call):
        return None
    if isinstance(node.func, ast.Attribute) and node.func.attr in ("filter", "where"):
        if node.args:
            return ast.unparse(node.args[0])
    return None


# ── AST walking ───────────────────────────────────────────────────────

def _walk_expr(node) -> tuple:
    """Walk a Python AST expression and produce (conditions, logic).

    Returns:
        (list of condition dicts, "AND" or "OR")
    """
    # ~X (bitwise invert / PySpark NOT) — recurse on operand, flip negate flag on each cond.
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Invert):
        inner_conds, logic = _walk_expr(node.operand)
        for c in inner_conds:
            _flip_negate(c)
        return inner_conds, logic

    # Boolean operators: 'and' / 'or'
    if isinstance(node, ast.BoolOp):
        if isinstance(node.op, ast.And):
            logic = "AND"
        elif isinstance(node.op, ast.Or):
            logic = "OR"
        else:
            raise TranslationError(f"Unsupported boolean operator: {type(node.op).__name__}")

        all_conds = []
        for v in node.values:
            conds, _ = _walk_expr(v)
            all_conds.extend(conds)
        return all_conds, logic

    # Bitwise & (AND) and | (OR) — PySpark uses these
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.BitAnd):
            logic = "AND"
        elif isinstance(node.op, ast.BitOr):
            logic = "OR"
        else:
            raise TranslationError(f"Unsupported binary operator: {type(node.op).__name__}")

        left_conds, _ = _walk_expr(node.left)
        right_conds, _ = _walk_expr(node.right)
        return left_conds + right_conds, logic

    if isinstance(node, ast.Compare):
        return _parse_comparison(node)

    if isinstance(node, ast.Call):
        return _parse_method_call(node)

    if isinstance(node, ast.Expr):
        return _walk_expr(node.value)

    raise TranslationError(f"Unsupported expression type: {ast.unparse(node)}")


def _parse_comparison(node: ast.Compare) -> tuple:
    """Parse col("field") > value style comparisons."""
    if len(node.ops) != 1 or len(node.comparators) != 1:
        raise TranslationError("Chained comparisons not supported (use & to combine)")

    left = node.left
    op = node.ops[0]
    right = node.comparators[0]

    is_count, count_field = _extract_count_col(left)
    if is_count:
        value = _extract_value(right)
        op_str = _ast_op_to_str(op)
        op_str = f"count_{_op_suffix(op_str)}"
        return [{"field": count_field, "op": op_str, "value": value}], "AND"

    field, mods = _extract_col_with_modifiers(left)
    if field is not None:
        value = _extract_value(right)
        op_str = _ast_op_to_str(op)
    else:
        field, mods = _extract_col_with_modifiers(right)
        if field is None:
            raise TranslationError(f"Expected col(\"field\") in comparison: {ast.unparse(node)}")
        value = _extract_value(left)
        op_str = _reverse_op(_ast_op_to_str(op))

    if isinstance(value, bool):
        cond = {"field": field, "op": "is_true" if value else "is_false", "value": None}
    else:
        cond = {"field": field, "op": op_str, "value": value}

    _apply_modifiers(cond, mods)
    return [cond], "AND"


def _parse_method_call(node: ast.Call) -> tuple:
    """Parse col("field").method() style calls via METHOD_MAP."""
    if not isinstance(node.func, ast.Attribute):
        raise TranslationError(f"Unsupported call: {ast.unparse(node)}")

    method = node.func.attr
    if method not in METHOD_MAP:
        raise TranslationError(f"Unsupported method: .{method}()")

    op_name, arg_kind = METHOD_MAP[method]
    field, mods = _extract_col_with_modifiers(node.func.value)
    if field is None:
        raise TranslationError(f"Expected col() in: {ast.unparse(node)}")

    if arg_kind == NO_ARG:
        cond = {"field": field, "op": op_name, "value": None}
    elif arg_kind == ARG_REQUIRED:
        if not node.args:
            raise TranslationError(f".{method}() requires an argument")
        cond = {"field": field, "op": op_name, "value": _extract_value(node.args[0])}
    elif arg_kind == LIST_ARG:
        if not node.args:
            raise TranslationError(f".{method}() requires arguments")
        values = []
        for arg in node.args:
            if isinstance(arg, ast.List):
                values.extend(_extract_value(elt) for elt in arg.elts)
            else:
                values.append(_extract_value(arg))
        cond = {"field": field, "op": op_name, "value": values}
    else:
        raise TranslationError(f"Bad arg_kind '{arg_kind}' in METHOD_MAP[{method!r}]")

    _apply_modifiers(cond, mods)
    return [cond], "AND"


# ── Helpers ───────────────────────────────────────────────────────────

def _extract_col_name(node) -> Optional[str]:
    """Extract field name from col("field") / column("field") / F.col("field")."""
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id in ("col", "column", "F"):
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                return node.args[0].value
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("col", "column"):
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                return node.args[0].value
    return None


def _extract_col_with_modifiers(node) -> tuple:
    """Unwrap lower()/upper() (function or method form) around a col() and report modifiers.

    Returns (field_name_or_None, modifiers_dict). Nested wrappers collapse.
    """
    mods = {}
    while True:
        # Function form: lower(col("x")) / upper(col("x"))
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in ("lower", "upper")
                and node.args):
            mods["case_insensitive"] = True
            node = node.args[0]
            continue
        # Method form: col("x").lower() / col("x").upper()
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in ("lower", "upper")):
            mods["case_insensitive"] = True
            node = node.func.value
            continue
        break
    field = _extract_col_name(node)
    return field, mods


def _apply_modifiers(cond: dict, mods: dict) -> None:
    """Merge modifier flags onto a condition dict in place."""
    for k, v in mods.items():
        cond[k] = v


def _flip_negate(cond: dict) -> None:
    """Toggle the negate flag on a condition. Drop the key when it returns to False."""
    new_val = not cond.get("negate", False)
    if new_val:
        cond["negate"] = True
    else:
        cond.pop("negate", None)


def _extract_count_col(node) -> tuple:
    """Check if node is count(col("field")) and return (True, field_name) or (False, None)."""
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id == "count":
            if node.args:
                field = _extract_col_name(node.args[0])
                if field:
                    return True, field
    return False, None


def _extract_value(node):
    """Extract a Python literal value from an AST node."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        if isinstance(node.operand, ast.Constant):
            return -node.operand.value
    if isinstance(node, ast.List):
        return [_extract_value(elt) for elt in node.elts]
    if isinstance(node, ast.Tuple):
        return [_extract_value(elt) for elt in node.elts]
    if isinstance(node, ast.Name):
        if node.id == "True":
            return True
        if node.id == "False":
            return False
        if node.id == "None":
            return None
    raise TranslationError(f"Unsupported value: {ast.unparse(node)}")


def _ast_op_to_str(op) -> str:
    """Convert AST comparison operator to string."""
    mapping = {
        ast.Gt: ">",
        ast.Lt: "<",
        ast.GtE: ">=",
        ast.LtE: "<=",
        ast.Eq: "=",
        ast.NotEq: "!=",
    }
    result = mapping.get(type(op))
    if result is None:
        raise TranslationError(f"Unsupported operator: {type(op).__name__}")
    return result


def _reverse_op(op: str) -> str:
    """Reverse a comparison operator (for value < col → col > value)."""
    return {"<": ">", ">": "<", "<=": ">=", ">=": "<=", "=": "=", "!=": "!="}.get(op, op)


def _op_suffix(op: str) -> str:
    """Convert operator to count suffix: > → gt, < → lt, = → eq."""
    return {">": "gt", "<": "lt", ">=": "gt", "<=": "lt", "=": "eq", "!=": "eq"}.get(op, "gt")
