"""
Shared utilities for Zeek log adapters.

Provides common parsing, type conversion, and header detection
used across all Zeek log format adapters (conn, dns, http, ssl, etc.).
"""

import logging
from pathlib import Path
from typing import List, Dict

logger = logging.getLogger("swifteye.adapters.zeek")

ZEEK_HEADER_MARKER = b"#fields"


def parse_zeek_log(path: Path) -> List[Dict[str, str]]:
    """Parse a Zeek tab-separated log file into list of row dicts.

    Handles the #fields header line to get column names.
    Skips comment lines (#) and empty lines.
    """
    fields = None
    rows = []

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n\r")
            if not line:
                continue
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#"):
                continue
            if fields is None:
                logger.warning("No #fields header found before data in %s", path.name)
                return []
            values = line.split("\t")
            if len(values) != len(fields):
                continue
            rows.append(dict(zip(fields, values)))

    return rows


def safe_int(val: str) -> int:
    if not val or val == "-":
        return 0
    try:
        return int(val)
    except ValueError:
        return 0


def safe_float(val: str) -> float:
    if not val or val == "-":
        return 0.0
    try:
        return float(val)
    except ValueError:
        return 0.0


def is_zeek_log(header: bytes, signature_field: str) -> bool:
    """Check if a file header looks like a Zeek log with a specific field."""
    if ZEEK_HEADER_MARKER not in header:
        return False
    try:
        header_str = header.decode("utf-8", errors="replace")
        return signature_field in header_str
    except Exception:
        return False


def get_zeek_columns(path: Path) -> List[str]:
    """Read just the #fields header line and return the column names.

    Much faster than parse_zeek_log() for schema inspection — reads only
    until the #fields line is found.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n\r")
            if line.startswith("#fields"):
                return line.split("\t")[1:]
            if not line.startswith("#") and line:
                # Data line before #fields — malformed, fall back to empty
                break
    return []
