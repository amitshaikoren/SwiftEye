"""
Schema negotiation contracts.

These dataclasses define the wire-format for the two-phase upload flow:
  Phase 1 — inspect_schema() returns a SchemaReport describing mismatches.
  Phase 2 — the user confirms a FieldMapping and ingestion resumes.
"""

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class SchemaField:
    """One field declared by an adapter."""
    name: str           # exact column name the adapter expects
    required: bool      # if True, missing this field will block ingestion
    description: str = ""


@dataclass
class SchemaReport:
    """Result of inspecting a file against an adapter's declared schema."""
    adapter_name: str
    detected_columns: List[str]          # columns actually found in the file
    declared_fields: List[SchemaField]   # fields the adapter declared
    missing_required: List[str]          # required fields absent from file
    missing_optional: List[str]          # optional fields absent from file
    unknown_columns: List[str]           # columns in file not declared by adapter
    suggested_mappings: Dict[str, str]   # {detected_col: expected_field} best-guess renames
    is_clean: bool                       # True = no missing required fields


@dataclass
class StagedFile:
    """Metadata for a file waiting in the schema-negotiation staging area."""
    token: str
    adapter_name: str
    original_filename: str
    staged_path: str     # absolute path to the staged temp file


@dataclass
class MappingConfirmation:
    """User-confirmed column mapping — sent back in Phase 2."""
    staging_token: str
    mapping: Dict[str, str]  # {actual_col_in_file: expected_field_name}
