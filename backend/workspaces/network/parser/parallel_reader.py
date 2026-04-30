"""
Multiprocessing wrapper for SwiftEye's dpkt reader.

Architecture:
  1. Pre-scan: read only 16-byte pcap packet headers → collect byte offsets (fast, I/O only)
  2. Split offsets into N equal chunks (N = CPU count, capped at 8)
  3. Spawn N workers via 'spawn' context (Windows + Linux compatible)
  4. Each worker: open file, read global header (link type), process its chunk
  5. Merge results, sort by timestamp

pcapng: falls back to single-threaded read_pcap_dpkt. pcapng block format
is variable-width and complex to pre-scan. See roadmap item pcapng-battle-test.

Windows note: 'spawn' context means each worker imports Python fresh (~0.3s
overhead). Acceptable for files large enough to warrant multiprocessing (> 50 MB).

use_parallel=False disables multiprocessing entirely — useful for debugging
or when the system has multiprocessing issues.
"""

import logging
import multiprocessing
import struct
from typing import List, Optional, Tuple

from .packet import PacketRecord
from .dpkt_reader import read_pcap_dpkt

logger = logging.getLogger("swifteye.parser.parallel")

_MAX_WORKERS = 8
_MIN_PACKETS_FOR_PARALLEL = 10_000


def _prescan_pcap(filepath: str) -> Optional[Tuple[int, bool, List[int]]]:
    """
    Read only 16-byte per-packet headers from a pcap file to collect byte offsets.
    Returns (link_type, little_endian, [offset_of_each_packet_header]) or None if
    the file is not a valid pcap (e.g. it is pcapng).

    Does NOT read any packet data — pure I/O over metadata only.
    """
    MAGIC_LE = 0xa1b2c3d4
    MAGIC_BE = 0xd4c3b2a1
    MAGIC_NS_LE = 0xa1b23c4d
    MAGIC_NS_BE = 0x4d3cb2a1

    try:
        with open(filepath, "rb") as f:
            global_hdr = f.read(24)
            if len(global_hdr) < 24:
                return None
            magic = struct.unpack_from("<I", global_hdr, 0)[0]
            if magic in (MAGIC_LE, MAGIC_NS_LE):
                little_endian = True
            elif magic in (MAGIC_BE, MAGIC_NS_BE):
                little_endian = False
            else:
                return None  # pcapng or unknown

            order = "<" if little_endian else ">"
            link_type = struct.unpack_from(f"{order}I", global_hdr, 20)[0]

            offsets: List[int] = []
            while True:
                pos = f.tell()
                pkt_hdr = f.read(16)
                if len(pkt_hdr) < 16:
                    break
                incl_len = struct.unpack_from(f"{order}I", pkt_hdr, 8)[0]
                offsets.append(pos)
                f.seek(incl_len, 1)

        return link_type, little_endian, offsets
    except Exception as e:
        logger.debug("pcap pre-scan failed: %s", e)
        return None


def _worker_read_chunk(args: tuple) -> List[PacketRecord]:
    """
    Worker function. Runs in a spawned child process.
    Opens the pcap file independently and reads only its assigned chunk.
    """
    filepath, start_offset, n_packets = args
    return read_pcap_dpkt(filepath, max_packets=n_packets, start_offset=start_offset)


def read_pcap_parallel(
    filepath: str,
    max_packets: int = 2_000_000,
    use_parallel: bool = True,
) -> List[PacketRecord]:
    """
    Read a pcap or pcapng file using dpkt, with multiprocessing for large pcap files.

    pcap files: pre-scan → split → N worker processes → merge + sort.
    pcapng files: single-threaded read_pcap_dpkt (pcapng-battle-test roadmap item).
    Falls back to single-threaded if pre-scan fails or packet count is small.

    Args:
        filepath: Path to pcap/pcapng file
        max_packets: Maximum packets to return
        use_parallel: Set False to disable multiprocessing (debugging/fallback)
    """
    if not use_parallel:
        logger.info("Parallel reader: disabled by use_parallel=False, using single-threaded")
        return read_pcap_dpkt(filepath, max_packets=max_packets)

    scan = _prescan_pcap(filepath)
    if scan is None:
        logger.info("Parallel reader: falling back to single-threaded (pcapng or scan failed)")
        return read_pcap_dpkt(filepath, max_packets=max_packets)

    _, _, offsets = scan
    n_packets = len(offsets)

    try:
        n_workers = min(multiprocessing.cpu_count(), _MAX_WORKERS)
    except Exception:
        n_workers = 1

    if n_packets < _MIN_PACKETS_FOR_PARALLEL or n_workers <= 1:
        logger.info("Parallel reader: %d packets, using single-threaded", n_packets)
        return read_pcap_dpkt(filepath, max_packets=max_packets)

    logger.info("Parallel reader: %d packets across %d workers", n_packets, n_workers)

    # Split offsets into chunks
    chunk_size = max(1, n_packets // n_workers)
    chunks: List[List[int]] = [
        offsets[i: i + chunk_size] for i in range(0, n_packets, chunk_size)
    ]

    # Each worker: filepath + byte offset of first packet in chunk + count
    worker_args = [
        (filepath, chunk[0], min(len(chunk), max_packets))
        for chunk in chunks
        if chunk
    ]

    ctx = multiprocessing.get_context("spawn")
    try:
        with ctx.Pool(len(worker_args)) as pool:
            results: List[List[PacketRecord]] = pool.map(_worker_read_chunk, worker_args)
    except Exception as e:
        logger.warning("Parallel read failed (%s), falling back to single-threaded", e)
        return read_pcap_dpkt(filepath, max_packets=max_packets)

    # Merge, sort, cap
    all_packets: List[PacketRecord] = []
    for chunk_result in results:
        all_packets.extend(chunk_result)
    all_packets.sort(key=lambda p: p.timestamp)
    return all_packets[:max_packets]
