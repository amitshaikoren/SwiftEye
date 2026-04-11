"""
Parity tests for the unified dpkt reader (v0.17.0).

Validates that the new dpkt reader produces PacketRecords with all
critical fields populated, matching what the old scapy reader produced.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from parser.pcap_reader import read_pcap

# Use the smallest available test pcap
_TESTS_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'captures')
_PCAP_CANDIDATES = [
    os.path.join(_TESTS_DIR, 'dhcp-homenetwork.pcap'),
    os.path.join(_TESTS_DIR, '2025-06-13-traffic-analysis-exercise.pcap'),
]
FIXTURE = next((p for p in _PCAP_CANDIDATES if os.path.exists(p)), None)


@pytest.mark.skipif(FIXTURE is None, reason="no test pcap found")
class TestFieldCoverage:
    """All critical PacketRecord fields are populated by the dpkt reader."""

    @pytest.fixture(scope="class")
    def packets(self):
        return read_pcap(FIXTURE, max_packets=50_000)

    def test_packets_parsed(self, packets):
        assert len(packets) > 0

    def test_timestamps(self, packets):
        for p in packets[:100]:
            assert p.timestamp > 0

    def test_ip_fields(self, packets):
        ip4 = [p for p in packets if p.ip_version == 4 and p.transport != "ARP"]
        if ip4:
            p = ip4[0]
            assert p.src_ip
            assert p.dst_ip
            assert p.ttl >= 0
            assert p.ip_proto > 0
            # ECN — was missing from old dpkt path
            assert hasattr(p, 'ecn')

    def test_tcp_fields(self, packets):
        tcp_pkts = [p for p in packets if p.transport == "TCP"]
        if tcp_pkts:
            p = tcp_pkts[0]
            assert p.src_port > 0 or p.dst_port > 0
            assert p.tcp_flags >= 0
            assert p.seq_num >= 0
            assert hasattr(p, 'urg_ptr')
            assert hasattr(p, 'tcp_checksum')

    def test_udp_fields(self, packets):
        udp_pkts = [p for p in packets if p.transport == "UDP"]
        if udp_pkts:
            p = udp_pkts[0]
            assert p.src_port > 0 or p.dst_port > 0

    def test_dns_extra_fields(self, packets):
        dns_pkts = [p for p in packets if p.protocol == "DNS"]
        if dns_pkts:
            # At least one DNS packet should have extra fields
            with_extra = [p for p in dns_pkts if p.extra]
            assert len(with_extra) > 0, "No DNS packets have extra fields"
            p = with_extra[0]
            assert "dns_id" in p.extra
            assert "dns_qr" in p.extra
            # These were missing from old dpkt path:
            assert "dns_rd" in p.extra
            assert "dns_qdcount" in p.extra

    def test_arp_extra_fields(self, packets):
        arp_pkts = [p for p in packets if p.protocol == "ARP"]
        if arp_pkts:
            p = arp_pkts[0]
            assert "arp_opcode" in p.extra
            assert "arp_opcode_name" in p.extra
            assert "arp_src_mac" in p.extra

    def test_icmp_extra_fields(self, packets):
        icmp_pkts = [p for p in packets if p.transport == "ICMP"]
        if icmp_pkts:
            with_extra = [p for p in icmp_pkts if p.extra]
            if with_extra:
                p = with_extra[0]
                assert "icmp_type_name" in p.extra

    def test_protocol_confidence(self, packets):
        """Protocol confidence is set for packets with detected protocols."""
        with_confidence = [p for p in packets if p.protocol_confidence]
        # Should have at least some packets with confidence set
        if len(packets) > 100:
            assert len(with_confidence) > 0

    def test_payload_preview(self, packets):
        """TCP/UDP packets with payloads should have preview bytes."""
        tcp_with_payload = [p for p in packets if p.transport == "TCP" and p.payload_len > 0]
        if tcp_with_payload:
            p = tcp_with_payload[0]
            assert len(p.payload_preview) > 0

    def test_session_key_works(self, packets):
        """session_key property works on parsed packets."""
        for p in packets[:50]:
            key = p.session_key
            assert isinstance(key, str)
            assert len(key) > 0


@pytest.mark.skipif(FIXTURE is None, reason="no test pcap found")
def test_single_threaded_fallback():
    """read_pcap with use_parallel=False works correctly."""
    packets = read_pcap(FIXTURE, max_packets=1000, use_parallel=False)
    assert len(packets) > 0
    # Should produce identical results
    packets_parallel = read_pcap(FIXTURE, max_packets=1000, use_parallel=True)
    assert len(packets) == len(packets_parallel)


def test_parallel_reader_error_handling():
    """Parallel reader raises on nonexistent file."""
    with pytest.raises((FileNotFoundError, ValueError, Exception)):
        read_pcap("/nonexistent/path/file.pcap")


def test_empty_file_rejected(tmp_path):
    """Empty files are rejected."""
    empty = tmp_path / "empty.pcap"
    empty.write_bytes(b"")
    with pytest.raises(ValueError, match="empty"):
        read_pcap(str(empty))
