from fastapi import APIRouter, HTTPException
from store import store, _require_capture
from data.query import resolve_query, parse_query_text, get_graph_schema, run_pipeline

router = APIRouter()


@router.post("/api/query")
async def run_query(body: dict):
    """Execute a structured query against the analysis graph."""
    _require_capture()
    if store.analysis_graph is None:
        raise HTTPException(400, "Analysis graph not available")
    return resolve_query(store.analysis_graph, body, named_sets=store.named_sets.as_context())


@router.post("/api/query/parse")
async def parse_query_text_endpoint(body: dict):
    """Parse a freehand query (Cypher/SQL/Spark SQL) into the JSON contract.

    Body: { "text": str, "dialect": optional str }
    Returns: { syntax, query: {target, conditions, logic, action} }
         or: { syntax, error: str }
    """
    text = body.get("text", "")
    dialect = body.get("dialect")
    return parse_query_text(text, dialect=dialect)


@router.get("/api/query/schema")
async def get_query_schema():
    """Return available fields and their types for the query builder dropdown."""
    _require_capture()
    return get_graph_schema(store.analysis_graph)


@router.post("/api/query/pipeline")
async def run_query_pipeline(body: dict):
    """Execute a recipe (list of steps) against the analysis graph.

    Body: { "steps": [ {verb, target, conditions, logic, scope?, group_name?, group_args?, enabled?}, ... ] }
    Returns the pipeline envelope — see data.query.pipeline for shape.
    `save_as_set` steps also persist the named set into the capture store.
    """
    _require_capture()
    if store.analysis_graph is None:
        raise HTTPException(400, "Analysis graph not available")
    steps = body.get("steps", [])
    if not isinstance(steps, list):
        raise HTTPException(400, "steps must be a list")
    result = run_pipeline(store.analysis_graph, steps, named_sets=store.named_sets.as_context())
    return result


@router.get("/api/query/sets")
async def list_named_sets():
    """Return all named sets for the current capture as {name: {target, members}}."""
    _require_capture()
    return store.named_sets.list_all()


@router.put("/api/query/sets/{name}")
async def put_named_set(name: str, body: dict):
    """Create or replace a named set. Body: {target: 'nodes'|'edges', members: [id,...]}."""
    _require_capture()
    target = body.get("target")
    members = body.get("members", [])
    if target not in ("nodes", "edges"):
        raise HTTPException(400, "target must be 'nodes' or 'edges'")
    if not isinstance(members, list):
        raise HTTPException(400, "members must be a list")
    try:
        entry = store.named_sets.set(name, target, members)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"name": name, **entry}


@router.delete("/api/query/sets/{name}")
async def delete_named_set(name: str):
    """Delete a named set. 404 if it doesn't exist."""
    _require_capture()
    if not store.named_sets.delete(name):
        raise HTTPException(404, f"Named set '{name}' not found")
    return {"deleted": name}
