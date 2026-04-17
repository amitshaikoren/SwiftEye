"""
Schema negotiation layer for SwiftEye ingestion adapters.

Sits between file detection and adapter.parse().  Compares a file's actual
columns against what each adapter declares, surfaces mismatches to the
frontend, and lets the user interactively remap columns before ingestion
resumes.

Public API:
  inspect_schema(adapter, path)  → SchemaReport
  stage_file(path, adapter_name, original_filename) → token
  get_staged(token)              → StagedFile | None
  clear_staged(token)            → None

Contracts (dataclasses):
  SchemaField, SchemaReport, StagedFile, MappingConfirmation
"""

from .contracts import SchemaField, SchemaReport, StagedFile, MappingConfirmation
from .inspector import inspect_schema
from .staging import stage_file, get_staged, clear_staged, list_staged

__all__ = [
    "SchemaField",
    "SchemaReport",
    "StagedFile",
    "MappingConfirmation",
    "inspect_schema",
    "stage_file",
    "get_staged",
    "clear_staged",
    "list_staged",
]
