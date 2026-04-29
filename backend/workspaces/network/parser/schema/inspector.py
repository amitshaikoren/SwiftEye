"""
Schema inspector.

inspect_schema(adapter, path) compares the columns actually found in a file
against the fields declared by the adapter. Returns a SchemaReport describing
any mismatches and best-guess rename suggestions.

This layer is independent of the adapters — adapters declare their expected
schema via `declared_fields` and expose `get_header_columns(path)`. The
inspector does the comparison without knowing anything about the file format.
"""

import logging
from pathlib import Path
from typing import List

from .contracts import SchemaField, SchemaReport

logger = logging.getLogger("swifteye.schema.inspector")


def _suggest_mappings(detected: List[str], missing: List[str]) -> dict:
    """Produce best-guess rename suggestions.

    Heuristics (in priority order):
    1. Case-insensitive exact match  (sourceip → sourceIp)
    2. Underscore/dot normalisation  (src_ip / src.ip → sourceIp)
    3. Common Zeek → generic aliases  (id.orig_h → src_ip)
    4. Substring containment          (originatingHost → src_ip)

    Only suggests when there is exactly one plausible candidate to avoid
    noise.  Unmatched missing fields are left for the user to map manually.
    """
    ALIASES = {
        # Zeek canonical → generic
        "id.orig_h":   ["src_ip", "sourceip", "source_ip"],
        "id.resp_h":   ["dst_ip", "destip", "dest_ip", "destination_ip"],
        "id.orig_p":   ["src_port", "sourceport", "source_port"],
        "id.resp_p":   ["dst_port", "destport", "dest_port"],
        "ts":          ["timestamp", "time", "epoch"],
        # tshark canonical → generic
        "sourceIp":    ["src_ip", "source_ip", "orig_ip"],
        "destIp":      ["dst_ip", "dest_ip", "resp_ip"],
        "sourcePort":  ["src_port", "source_port"],
        "destPort":    ["dst_port", "dest_port"],
        "ipProtoType": ["proto", "ip_proto", "protocol"],
    }

    def _norm(s: str) -> str:
        return s.lower().replace("_", "").replace(".", "").replace("-", "")

    suggestions: dict = {}
    detected_norm = {_norm(d): d for d in detected}

    for missing_field in missing:
        candidates = []

        # Check alias table (missing field might BE an alias target)
        for canonical, aliases in ALIASES.items():
            if missing_field == canonical:
                for alias in aliases:
                    if _norm(alias) in detected_norm:
                        candidates.append(detected_norm[_norm(alias)])

        # Case-insensitive / normalised match in detected columns
        if not candidates:
            mf_norm = _norm(missing_field)
            for det_norm, det_orig in detected_norm.items():
                if det_norm == mf_norm:
                    candidates.append(det_orig)

        # Substring containment (last resort)
        if not candidates:
            mf_norm = _norm(missing_field)
            for det_norm, det_orig in detected_norm.items():
                if mf_norm in det_norm or det_norm in mf_norm:
                    candidates.append(det_orig)

        if len(candidates) == 1:
            suggestions[candidates[0]] = missing_field  # {actual_col: expected_field}

    return suggestions


def inspect_schema(adapter, path: Path) -> SchemaReport:
    """Compare a file's detected columns against the adapter's declared schema.

    Returns a SchemaReport. If is_clean is True, ingestion can proceed
    immediately without user intervention.
    """
    declared: List[SchemaField] = getattr(adapter, "declared_fields", [])

    # If adapter declares no schema, nothing to negotiate — always clean.
    if not declared:
        return SchemaReport(
            adapter_name=adapter.name,
            detected_columns=[],
            declared_fields=[],
            missing_required=[],
            missing_optional=[],
            unknown_columns=[],
            suggested_mappings={},
            is_clean=True,
        )

    try:
        detected = adapter.get_header_columns(path)
    except Exception as e:
        logger.warning("Could not read columns from %s: %s", path.name, e)
        detected = []

    detected_set = set(detected)
    required = [f for f in declared if f.required]
    optional = [f for f in declared if not f.required]
    declared_names = {f.name for f in declared}

    missing_required = [f.name for f in required if f.name not in detected_set]
    missing_optional = [f.name for f in optional if f.name not in detected_set]
    unknown_columns  = [c for c in detected if c not in declared_names]

    is_clean = len(missing_required) == 0
    suggested = _suggest_mappings(detected, missing_required + missing_optional) if not is_clean else {}

    logger.info(
        "Schema check %s for %s: clean=%s missing_req=%s",
        adapter.name, path.name, is_clean, missing_required,
    )

    return SchemaReport(
        adapter_name=adapter.name,
        detected_columns=detected,
        declared_fields=declared,
        missing_required=missing_required,
        missing_optional=missing_optional,
        unknown_columns=unknown_columns,
        suggested_mappings=suggested,
        is_clean=is_clean,
    )
