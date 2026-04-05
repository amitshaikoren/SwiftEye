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
