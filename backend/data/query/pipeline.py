"""
Query pipeline executor.

Takes a recipe (ordered list of steps), runs each step top-to-bottom, and
produces the aggregate view/group/set state the frontend renders. Each
step sees the previous step's output — a step's `show_only` restricts
visibility *before* a later `cluster` groups what's left.

Per-step contract (each step dict):
    {
        "verb": one of query_engine.ACTIONS    (alias: "action"),
        "target": "nodes" | "edges",
        "conditions": [...],                   (same shape as resolve_query)
        "logic": "AND" | "OR",
        "scope": "viz" | "global",             (default "viz")
        "group_name": str,                     (required for tag/color/cluster/save_as_set)
        "group_args": dict,                    (verb-specific: {"color": "#ff0"}, ...)
        "enabled": bool                        (default True; disabled steps are recorded but skipped)
    }

Output envelope:
    {
        "steps": [per-step provenance],
        "visible": {"nodes": [...], "edges": [...]},
        "hidden":  {"nodes": [...], "edges": [...]},    # derived complement
        "highlights": [{"step": int, "target": str, "ids": [...]}],
        "groups": {
            "tag":     {name: {"target", "members"}},
            "color":   {name: {"target", "members", "args"}},
            "cluster": {name: {"target", "members"}},
        },
        "saved_sets": {name: {"target", "members"}},    # also reflected in named_sets store
        "pending_global": [{"step", "verb", "target", "matches"}],  # for recompute
        "warnings": [str],
    }

`save_as_set` steps mutate the `named_sets` dict in place so that a later
step's `in_set` op can reference a set saved earlier in the same recipe.
"""

from typing import Optional
import logging

from .query_engine import resolve_query, ACTIONS, ACTIONS_REQUIRE_GROUP, SCOPES

logger = logging.getLogger("swifteye.query_pipeline")


def _edge_endpoints(edge_id: str) -> tuple[str, str]:
    """`"u|v"` → `("u", "v")`. Engine formats edge IDs this way."""
    u, _, v = edge_id.partition("|")
    return u, v


def _build_node_edge_index(G) -> dict[str, set[str]]:
    """node_id → set of edge_ids touching it. Used for hide-edge orphan detection."""
    idx: dict[str, set[str]] = {}
    for u, v in G.edges():
        eid = f"{u}|{v}"
        idx.setdefault(u, set()).add(eid)
        idx.setdefault(v, set()).add(eid)
    return idx


def _step_query(step: dict) -> dict:
    """Build the resolve_query input from a pipeline step."""
    return {
        "target": step.get("target", "nodes"),
        "conditions": step.get("conditions", []),
        "logic": step.get("logic", "AND"),
        "action": step.get("verb") or step.get("action") or "highlight",
        "scope": step.get("scope", "viz"),
        "group_name": step.get("group_name"),
        "group_args": step.get("group_args") or {},
    }


def run_pipeline(G, steps: list[dict], named_sets: Optional[dict] = None) -> dict:
    """Execute `steps` against graph `G`. Returns the pipeline output envelope.

    `named_sets` is a shared dict of {name: {"target", "members"}} — pipeline
    reads it for `in_set` conditions and writes to it for `save_as_set` verbs,
    so callers can share one store across multiple pipeline runs.
    """
    named_sets = named_sets if named_sets is not None else {}
    warnings: list[str] = []

    if G is None:
        return {
            "steps": [],
            "visible": {"nodes": [], "edges": []},
            "hidden":  {"nodes": [], "edges": []},
            "highlights": [],
            "groups": {"tag": {}, "color": {}, "cluster": {}},
            "saved_sets": {},
            "pending_global": [],
            "warnings": ["No capture loaded"],
        }

    all_nodes = set(str(n) for n in G.nodes())
    all_edges = {f"{u}|{v}" for u, v in G.edges()}
    node_edge_idx = _build_node_edge_index(G)

    visible_nodes = set(all_nodes)
    visible_edges = set(all_edges)

    step_records: list[dict] = []
    highlights: list[dict] = []
    groups = {"tag": {}, "color": {}, "cluster": {}}
    saved_sets: dict[str, dict] = {}
    pending_global: list[dict] = []

    for idx, step in enumerate(steps or []):
        verb = (step.get("verb") or step.get("action") or "highlight").lower()
        target = step.get("target", "nodes")
        scope = (step.get("scope") or "viz").lower()
        enabled = step.get("enabled", True)
        group_name = step.get("group_name")

        record = {
            "index": idx, "verb": verb, "target": target, "scope": scope,
            "enabled": bool(enabled), "matches": [],
        }

        if not enabled:
            record["skipped"] = "disabled"
            step_records.append(record)
            continue

        if verb not in ACTIONS:
            warnings.append(f"step {idx}: unknown verb '{verb}' — skipped")
            record["skipped"] = f"unknown verb '{verb}'"
            step_records.append(record)
            continue
        if scope not in SCOPES:
            warnings.append(f"step {idx}: unknown scope '{scope}' → viz")
            scope = "viz"
            record["scope"] = scope
        if verb in ACTIONS_REQUIRE_GROUP and not group_name:
            warnings.append(f"step {idx}: verb '{verb}' requires group_name — skipped")
            record["skipped"] = "missing group_name"
            step_records.append(record)
            continue

        env = resolve_query(G, _step_query(step), named_sets=named_sets)
        matches_all = list(env.get("matches", []))
        record["matches"] = matches_all
        record["total_searched"] = env.get("total_searched", 0)

        # Visibility effects only consider items that are currently visible —
        # prior steps may have narrowed the set.
        current_visible = visible_nodes if target == "nodes" else visible_edges
        effective = [m for m in matches_all if m in current_visible]
        record["effective_matches"] = effective

        before_nodes, before_edges = set(visible_nodes), set(visible_edges)

        if verb == "highlight":
            if effective:
                highlights.append({"step": idx, "target": target, "ids": list(effective)})

        elif verb == "show_only":
            eff_set = set(effective)
            if target == "nodes":
                visible_nodes &= eff_set
                visible_edges = {
                    e for e in visible_edges
                    if (lambda uv: uv[0] in visible_nodes and uv[1] in visible_nodes)(_edge_endpoints(e))
                }
            else:
                visible_edges &= eff_set

        elif verb == "hide":
            eff_set = set(effective)
            if target == "nodes":
                visible_nodes -= eff_set
                visible_edges = {
                    e for e in visible_edges
                    if (lambda uv: uv[0] in visible_nodes and uv[1] in visible_nodes)(_edge_endpoints(e))
                }
            else:
                visible_edges -= eff_set
                # Orphan policy: hide touched nodes with no remaining visible edges.
                touched = set()
                for eid in eff_set:
                    u, v = _edge_endpoints(eid)
                    touched.add(u); touched.add(v)
                for n in touched:
                    if not (node_edge_idx.get(n, set()) & visible_edges):
                        visible_nodes.discard(n)

        elif verb == "tag":
            # Visual decoration — only on currently-visible items.
            groups["tag"][group_name] = {"target": target, "members": list(effective)}

        elif verb == "color":
            groups["color"][group_name] = {
                "target": target,
                "members": list(effective),
                "args": dict(step.get("group_args") or {}),
            }

        elif verb == "cluster":
            # Collapsing into a blob — only makes sense for what's currently visible.
            groups["cluster"][group_name] = {"target": target, "members": list(effective)}

        elif verb == "save_as_set":
            # Data-level save: capture all matches regardless of current visibility.
            # Compose `in_set` with prior filters upstream if visibility-scoped saves are wanted.
            entry = {"target": target, "members": list(matches_all)}
            saved_sets[group_name] = entry
            named_sets[group_name] = entry  # live so later in_set ops can reference it

        elif verb == "select":
            # Legacy alias — treat as highlight for now.
            if effective:
                highlights.append({"step": idx, "target": target, "ids": list(effective)})

        # Record derived visibility delta for this step.
        record["removed"] = {
            "nodes": sorted(before_nodes - visible_nodes),
            "edges": sorted(before_edges - visible_edges),
        }
        if group_name and verb in ACTIONS_REQUIRE_GROUP:
            record["group_name"] = group_name

        if scope == "global" and verb in ("hide", "show_only"):
            pending_global.append({
                "step": idx, "verb": verb, "target": target, "matches": list(matches_all),
            })

        step_records.append(record)

    return {
        "steps": step_records,
        "visible": {"nodes": sorted(visible_nodes), "edges": sorted(visible_edges)},
        "hidden": {
            "nodes": sorted(all_nodes - visible_nodes),
            "edges": sorted(all_edges - visible_edges),
        },
        "highlights": highlights,
        "groups": groups,
        "saved_sets": saved_sets,
        "pending_global": pending_global,
        "warnings": warnings,
    }
