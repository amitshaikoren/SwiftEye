"""
API response models for SwiftEye.
"""

from pydantic import BaseModel
from typing import List, Dict, Any, Optional


class UploadResponse(BaseModel):
    success: bool
    capture_id: str
    file_name: str
    source_files: List[str]
    packet_count: int
    parse_time_ms: int
    file_size_bytes: int
    # Schema negotiation fields — only populated when a mismatch is detected.
    schema_negotiation_required: bool = False
    staging_token: Optional[str] = None
    schema_report: Optional[Dict[str, Any]] = None
    # Type detection failure — populated when no adapter can handle the file.
    detection_failed: bool = False
    available_adapters: List[str] = []


class SchemaNegotiationRequest(BaseModel):
    """Phase 2: user-confirmed column mapping to resume ingestion."""
    staging_token: str
    mapping: Dict[str, str]  # {actual_col_in_file: expected_field_name}


class StatsResponse(BaseModel):
    stats: Dict[str, Any]


class TimelineResponse(BaseModel):
    buckets: List[Dict[str, Any]]
    bucket_seconds: int


class GraphResponse(BaseModel):
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]
    filtered_count: int
    filtered_bytes: int
    clusters: Optional[Dict[str, int]] = None  # node_id -> cluster_id (view metadata, never mutates graph)


class SessionsResponse(BaseModel):
    sessions: List[Dict[str, Any]]
    total: int


class SessionDetailResponse(BaseModel):
    session: Dict[str, Any]
    packets: List[Dict[str, Any]]


class ProtocolsResponse(BaseModel):
    protocols: List[str]
    colors: Dict[str, str]


class SubnetsResponse(BaseModel):
    subnets: Dict[str, List[str]]


class NodeAnimationResponse(BaseModel):
    events: List[Dict[str, Any]]
    nodes: Dict[str, Dict[str, Any]]


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
