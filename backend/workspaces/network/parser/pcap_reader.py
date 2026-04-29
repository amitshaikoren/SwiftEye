"""
Public entry point for pcap/pcapng reading.

Delegates to parallel_reader.read_pcap_parallel(), which uses dpkt for
L2/L3/L4 parsing and the registered protocol dissectors for L5 enrichment.

Since v0.17.0, all files use the unified dpkt reader — no scapy full-packet
parsing, no threshold constant, no dual-path parity problem.
"""

import logging
from pathlib import Path
from typing import List, Optional, Callable

from .packet import PacketRecord
from .parallel_reader import read_pcap_parallel

logger = logging.getLogger("swifteye.parser")

MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024   # 2 GB (was 500 MB — scapy memory limit removed)
MAX_PACKETS   = 2_000_000
PROGRESS_CALLBACK_INTERVAL = 10_000       # kept for API compatibility


def read_pcap(
    filepath: str,
    max_packets: int = MAX_PACKETS,
    progress_callback: Optional[Callable[[int, float], None]] = None,
    use_parallel: bool = True,
) -> List[PacketRecord]:
    """
    Read a pcap or pcapng file and return normalized PacketRecords.

    Uses dpkt for L2/L3/L4 parsing (all file sizes).
    Uses registered protocol dissectors (parser/protocols/) for L5 enrichment.
    Large pcap files use multiprocessing (N = cpu_count, capped at 8).
    pcapng files use single-threaded dpkt.

    Args:
        filepath: Path to the pcap/pcapng file
        max_packets: Maximum packets to return
        progress_callback: Accepted for API compat, no-op when multiprocessing active
        use_parallel: Set False to disable multiprocessing (debugging/fallback)
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {filepath}")
    if path.stat().st_size > MAX_FILE_SIZE:
        raise ValueError(
            f"File too large: {path.stat().st_size / 1024 / 1024:.1f} MB "
            f"(max {MAX_FILE_SIZE // 1024 // 1024 // 1024} GB)"
        )
    if path.stat().st_size == 0:
        raise ValueError("File is empty")

    return read_pcap_parallel(filepath, max_packets=max_packets, use_parallel=use_parallel)
