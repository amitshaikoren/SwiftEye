"""
Pcap/pcapng ingestion adapter.

Wraps the existing read_pcap() function so it fits the adapter interface.
No behavior change — this is the same parser SwiftEye has always used.
"""

from pathlib import Path
from typing import List, Optional, Callable

from parser.packet import PacketRecord
from parser.pcap_reader import read_pcap
from . import IngestionAdapter, register_adapter

# Pcap magic bytes
PCAP_LE = b"\xd4\xc3\xb2\xa1"
PCAP_BE = b"\xa1\xb2\xc3\xd4"
PCAPNG  = b"\x0a\x0d\x0d\x0a"


@register_adapter
class PcapAdapter(IngestionAdapter):
    name = "pcap/pcapng"
    file_extensions = [".pcap", ".pcapng", ".cap"]
    granularity = "packet"
    source_type = "pcap"

    def can_handle(self, path: Path, header: bytes) -> bool:
        # Check extension first
        if path.suffix.lower() in self.file_extensions:
            return True
        # Fall back to magic bytes
        if len(header) >= 4:
            magic = header[:4]
            if magic in (PCAP_LE, PCAP_BE, PCAPNG):
                return True
        return False

    def parse(self, path: Path, **opts) -> List[PacketRecord]:
        max_packets = opts.get("max_packets", 2_000_000)
        progress_callback = opts.get("progress_callback", None)
        return read_pcap(str(path), max_packets=max_packets, progress_callback=progress_callback)
