"""
Shared utilities for tshark CSV export adapters.

Tshark CSV exports use tab-separated fields with a header row.
Format: tshark -T fields -e frame.number -e frame.time_epoch -e ... > out.csv
"""

import logging
from pathlib import Path
from typing import List, Dict

logger = logging.getLogger("swifteye.adapters.tshark")

# tshark CSVs are tab-separated with a plain header row (no # prefix)
TSHARK_SEPARATOR = "\t"


def parse_tshark_csv(path: Path) -> List[Dict[str, str]]:
    """Parse a tshark tab-separated CSV export into list of row dicts.

    First line is the header (field names). Subsequent lines are data.
    Handles pandas-style exports where data rows have a leading row-index
    column not present in the header (len(values) == len(fields) + 1).
    """
    rows = []

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        header_line = f.readline().rstrip("\n\r")
        if not header_line:
            return []
        fields = header_line.split(TSHARK_SEPARATOR)
        n_fields = len(fields)

        for line in f:
            line = line.rstrip("\n\r")
            if not line:
                continue
            values = line.split(TSHARK_SEPARATOR)
            if len(values) == n_fields:
                rows.append(dict(zip(fields, values)))
            elif len(values) == n_fields + 1:
                # Leading row index (pandas-style) — skip first value
                rows.append(dict(zip(fields, values[1:])))

    return rows


def safe_int(val: str) -> int:
    if not val or val == "":
        return 0
    try:
        return int(val)
    except ValueError:
        return 0


def safe_float(val: str) -> float:
    if not val or val == "":
        return 0.0
    try:
        return float(val)
    except ValueError:
        return 0.0


def is_tshark_csv(header: bytes, *required_fields: str) -> bool:
    """Check if a file header looks like a tshark CSV with specific fields."""
    try:
        first_line = header.split(b"\n", 1)[0].decode("utf-8", errors="replace")
    except Exception:
        return False
    return all(f in first_line for f in required_fields)
