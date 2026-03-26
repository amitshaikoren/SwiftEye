"""
Shared utilities for tshark CSV export adapters.

Tshark CSV exports use tab-separated fields with a header row.
Format: tshark -T fields -e frame.number -e frame.time_epoch -e ... > out.csv
"""

import logging
from pathlib import Path
from typing import List, Dict, Optional

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


# ── Metadata index for protocol CSV adapters ─────────────────────────────────

# Module-level cache: directory path → {frameNumber → row dict}
_metadata_cache: Dict[str, Dict[str, Dict[str, str]]] = {}


def load_metadata_index(directory: Path) -> Optional[Dict[str, Dict[str, str]]]:
    """Load metadata.csv from a directory and index by frameNumber.

    Returns dict mapping frameNumber (str) → row dict, or None if not found.
    Cached per directory so multiple protocol adapters don't re-read.
    """
    key = str(directory)
    if key in _metadata_cache:
        return _metadata_cache[key]

    meta_path = directory / "metadata.csv"
    if not meta_path.exists():
        logger.warning("No metadata.csv found in %s — protocol CSVs cannot resolve IPs", directory)
        _metadata_cache[key] = None
        return None

    rows = parse_tshark_csv(meta_path)
    if not rows:
        _metadata_cache[key] = None
        return None

    index = {}
    for row in rows:
        fn = row.get("frameNumber", "")
        if fn:
            index[fn] = row

    logger.info("Loaded metadata index: %d frames from %s", len(index), meta_path.name)
    _metadata_cache[key] = index
    return index


def meta_to_network(meta_row: Dict[str, str]) -> Dict[str, any]:
    """Extract network 5-tuple + MACs from a metadata row."""
    ip_proto = int(safe_float(meta_row.get("ipProtoType", "0")))
    transport = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}.get(ip_proto, "")
    return {
        "src_ip": meta_row.get("sourceIp", ""),
        "dst_ip": meta_row.get("destIp", ""),
        "src_port": int(safe_float(meta_row.get("sourcePort", "0"))),
        "dst_port": int(safe_float(meta_row.get("destPort", "0"))),
        "src_mac": meta_row.get("sourceMac", ""),
        "dst_mac": meta_row.get("destMac", ""),
        "transport": transport,
        "ip_proto": ip_proto,
        "timestamp": safe_float(meta_row.get("ts", "0")),
        "ttl": int(safe_float(meta_row.get("ipTtl", "0"))),
    }
