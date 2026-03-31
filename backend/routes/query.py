from fastapi import APIRouter, HTTPException
from store import store, _require_capture
from data.query import resolve_query, parse_query_text, get_graph_schema

router = APIRouter()


@router.post("/api/query")
async def run_query(body: dict):
    """Execute a structured query against the analysis graph."""
    _require_capture()
    if store.analysis_graph is None:
        raise HTTPException(400, "Analysis graph not available")
    return resolve_query(store.analysis_graph, body)


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
