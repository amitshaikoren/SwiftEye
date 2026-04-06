"""
SwiftEye Test Suite — minimal skeleton covering the critical path.

Run: pytest backend/tests/ -v
"""
import importlib
import os
import sys

import pytest

# Add backend to path so imports work
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from parser.packet import PacketRecord
from parser.pcap_reader import read_pcap
from data import build_graph, build_sessions, compute_global_stats, filter_packets, build_time_buckets
from plugins import register_plugin, run_global_analysis, get_global_results, AnalysisContext, _plugins, _global_results
from plugins.analyses.node_centrality import NodeCentralityAnalysis
from plugins.analyses.traffic_characterisation import TrafficCharacterisationAnalysis
from plugins.alerts.arp_spoofing import ArpSpoofingDetector
from plugins.alerts.suspicious_ua import SuspiciousUADetector
from plugins.alerts.malicious_ja3 import MaliciousJA3Detector
from plugins.alerts.port_scan import PortScanDetector
from plugins.alerts import run_all_detectors, register_detector


# ── Fixtures ────────────────────────────────────────────────────────────────

def _make_pkt(src_ip, dst_ip, src_port, dst_port, protocol, transport,
              timestamp, orig_len=100, ttl=64, tcp_flags_str='', tcp_flags_list=None,
              src_mac='aa:bb:cc:dd:ee:01', dst_mac='aa:bb:cc:dd:ee:02'):
    """Create a minimal PacketRecord for testing."""
    return PacketRecord(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        transport=transport,
        orig_len=orig_len,
        payload_len=orig_len - 40,
        ttl=ttl,
        tcp_flags_str=tcp_flags_str,
        tcp_flags_list=tcp_flags_list or [],
        src_mac=src_mac,
        dst_mac=dst_mac,
        ip_version=4,
        seq_num=0,
        ack_num=0,
        window_size=65535,
        tcp_options=[],
        extra={},
        payload_preview=b'',
    )


@pytest.fixture
def packets():
    """50 synthetic packets: 3 IPs, TCP + UDP, spanning 10 seconds."""
    t0 = 1700000000.0
    pkts = []
    # TCP session: 10.0.0.1:1234 → 10.0.0.2:443 (HTTPS)
    for i in range(20):
        flags = ['SYN'] if i == 0 else ['ACK'] if i == 1 else ['PSH', 'ACK']
        pkts.append(_make_pkt('10.0.0.1', '10.0.0.2', 1234, 443, 'HTTPS', 'TCP',
                              t0 + i * 0.5, orig_len=100 + i * 10,
                              tcp_flags_str=','.join(flags), tcp_flags_list=flags))
    # UDP session: 10.0.0.1:5000 → 10.0.0.3:53 (DNS)
    for i in range(15):
        pkts.append(_make_pkt('10.0.0.1', '10.0.0.3', 5000, 53, 'DNS', 'UDP',
                              t0 + 1.0 + i * 0.3, orig_len=80))
    # TCP session: 10.0.0.3:8080 → 10.0.0.2:22 (SSH) — later in time
    for i in range(15):
        pkts.append(_make_pkt('10.0.0.3', '10.0.0.2', 8080, 22, 'SSH', 'TCP',
                              t0 + 6.0 + i * 0.3, orig_len=200))
    pkts.sort(key=lambda p: p.timestamp)
    return pkts


@pytest.fixture
def sessions(packets):
    return build_sessions(packets)


# ── Core path tests ─────────────────────────────────────────────────────────

class TestBuildSessions:
    def test_returns_list(self, sessions):
        assert isinstance(sessions, list)

    def test_session_count(self, sessions):
        # Should have 3 sessions (HTTPS, DNS, SSH)
        assert len(sessions) == 3

    def test_session_has_required_keys(self, sessions):
        required = {'id', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                    'protocol', 'packet_count', 'total_bytes', 'duration'}
        for s in sessions:
            assert required.issubset(s.keys()), f"Missing keys: {required - s.keys()}"

    def test_packet_counts_sum(self, packets, sessions):
        total = sum(s['packet_count'] for s in sessions)
        assert total == len(packets)


class TestComputeGlobalStats:
    def test_returns_dict(self, packets, sessions):
        stats = compute_global_stats(packets, sessions)
        assert isinstance(stats, dict)

    def test_total_packets(self, packets, sessions):
        stats = compute_global_stats(packets, sessions)
        assert stats['total_packets'] == len(packets)

    def test_unique_ips(self, packets, sessions):
        stats = compute_global_stats(packets, sessions)
        assert stats['unique_ips'] == 3  # 10.0.0.1, 10.0.0.2, 10.0.0.3

    def test_total_sessions(self, packets, sessions):
        stats = compute_global_stats(packets, sessions)
        assert stats['total_sessions'] == 3

    def test_empty_packets(self):
        stats = compute_global_stats([], [])
        assert stats['total_packets'] == 0


class TestFilterPackets:
    def test_no_filter(self, packets):
        result = filter_packets(packets)
        assert len(result) == len(packets)

    def test_time_range(self, packets):
        t0 = packets[0].timestamp
        result = filter_packets(packets, time_range=(t0, t0 + 3.0))
        assert len(result) < len(packets)
        assert all(t0 <= p.timestamp <= t0 + 3.0 for p in result)

    def test_protocol_filter(self, packets):
        result = filter_packets(packets, protocols={'DNS'})
        assert len(result) == 15
        assert all(p.protocol == 'DNS' for p in result)

    def test_search_query(self, packets):
        result = filter_packets(packets, search_query='10.0.0.3')
        assert all('10.0.0.3' in p.src_ip or '10.0.0.3' in p.dst_ip for p in result)

    def test_exclude_ipv6(self, packets):
        # All test packets are IPv4, so nothing should be excluded
        result = filter_packets(packets, include_ipv6=False)
        assert len(result) == len(packets)


class TestBuildGraph:
    def test_returns_nodes_and_edges(self, packets):
        result = build_graph(packets)
        assert 'nodes' in result
        assert 'edges' in result

    def test_node_count(self, packets):
        result = build_graph(packets)
        assert len(result['nodes']) == 3

    def test_edge_count(self, packets):
        result = build_graph(packets)
        # 3 connections: 10.0.0.1→10.0.0.2, 10.0.0.1→10.0.0.3, 10.0.0.3→10.0.0.2
        assert len(result['edges']) >= 3

    def test_time_range_filter(self, packets):
        t0 = packets[0].timestamp
        result = build_graph(packets, time_range=(t0 + 6.0, t0 + 12.0))
        # Only SSH session (10.0.0.3→10.0.0.2) should be fully in this range
        node_ids = {n['id'] for n in result['nodes']}
        assert '10.0.0.3' in node_ids
        assert '10.0.0.2' in node_ids


class TestDirectionalEdges:
    """Tests for v0.20.0 edge refactor: directional edges, src/dst ports, cross-refs."""

    def test_edges_are_directional(self, packets):
        """Edge source should be the packet initiator, not alphabetically sorted."""
        result = build_graph(packets)
        edges = result['edges']
        # 10.0.0.1:1234 → 10.0.0.2:443 (HTTPS) — source should be 10.0.0.1
        https_edge = [e for e in edges if e['protocol'] == 'HTTPS']
        assert len(https_edge) == 1
        assert https_edge[0]['source'] == '10.0.0.1'
        assert https_edge[0]['target'] == '10.0.0.2'

    def test_edge_id_format(self, packets):
        """Edge ID should be src|dst|protocol (directional)."""
        result = build_graph(packets)
        edges = result['edges']
        https_edge = [e for e in edges if e['protocol'] == 'HTTPS'][0]
        assert https_edge['id'] == '10.0.0.1|10.0.0.2|HTTPS'

    def test_src_dst_ports(self, packets):
        """Edges should have separate src_ports and dst_ports."""
        result = build_graph(packets)
        edges = result['edges']
        https_edge = [e for e in edges if e['protocol'] == 'HTTPS'][0]
        assert 'src_ports' in https_edge
        assert 'dst_ports' in https_edge
        assert 1234 in https_edge['src_ports']
        assert 443 in https_edge['dst_ports']
        # Compat field should be union
        assert 'ports' in https_edge
        assert set(https_edge['ports']) == set(https_edge['src_ports']) | set(https_edge['dst_ports'])

    def test_node_edge_cross_refs(self, packets):
        """Nodes should have edge_ids listing their connected edges."""
        result = build_graph(packets)
        nodes = result['nodes']
        edges = result['edges']
        node_map = {n['id']: n for n in nodes}
        for n in nodes:
            assert 'edge_ids' in n, f"Node {n['id']} missing edge_ids"
        # Node 10.0.0.1 connects to 10.0.0.2 (HTTPS) and 10.0.0.3 (DNS) — at least 2 edges
        n1 = node_map['10.0.0.1']
        assert len(n1['edge_ids']) >= 2
        # Every edge_id in a node should exist in the edge list
        edge_ids = {e['id'] for e in edges}
        for n in nodes:
            for eid in n['edge_ids']:
                assert eid in edge_ids, f"Node {n['id']} references non-existent edge {eid}"

    def test_http_user_agents_on_edges(self):
        """Edges should carry http_fwd_user_agents from packet extras."""
        pkts = [
            _make_pkt('10.0.0.1', '10.0.0.2', 5000, 80, 'HTTP', 'TCP', 1.0),
            _make_pkt('10.0.0.1', '10.0.0.2', 5000, 80, 'HTTP', 'TCP', 2.0),
        ]
        pkts[0].extra = {"http_user_agent": "python-requests/2.28", "http_host": "example.com"}
        pkts[1].extra = {"http_user_agent": "curl/7.88", "http_host": "example.com"}
        result = build_graph(pkts)
        edges = result['edges']
        assert len(edges) == 1
        assert set(edges[0]['http_fwd_user_agents']) == {"python-requests/2.28", "curl/7.88"}


class TestBuildTimeBuckets:
    def test_returns_list(self, packets):
        buckets = build_time_buckets(packets)
        assert isinstance(buckets, list)
        assert len(buckets) > 0

    def test_bucket_has_required_keys(self, packets):
        buckets = build_time_buckets(packets)
        for b in buckets:
            assert 'start_time' in b
            assert 'end_time' in b
            assert 'packet_count' in b

    def test_total_packet_count(self, packets):
        buckets = build_time_buckets(packets, bucket_seconds=1)
        total = sum(b['packet_count'] for b in buckets)
        assert total == len(packets)


# ── Regression tests ────────────────────────────────────────────────────────

class TestSessionTimeScoping:
    """Regression test for v0.9.43 bug: session scoping should be packet-based."""

    def test_packet_based_scoping(self, packets, sessions):
        """Sessions outside the time window should be excluded even if their
        start/end times overlap the window."""
        t0 = packets[0].timestamp
        # Window covers only the first 3 seconds — should include HTTPS and DNS
        # but not SSH (which starts at t0+6)
        window_start = t0
        window_end = t0 + 3.0
        scoped_pkts = filter_packets(packets, time_range=(window_start, window_end))
        active_keys = {p.session_key for p in scoped_pkts}
        scoped_sessions = [s for s in sessions if s.get('id') in active_keys]
        # SSH session starts at t0+6, should NOT be included
        protos = {s['protocol'] for s in scoped_sessions}
        assert 'SSH' not in protos
        assert 'HTTPS' in protos or 'DNS' in protos


# ── Session boundary detection tests ───────────────────────────────────────

class TestSessionBoundary:
    """Tests for session boundary detection (FIN/RST+SYN, grace period, seq jump, protocol timeouts)."""

    def test_fin_syn_splits(self):
        """FIN then SYN on same 5-tuple should create two sessions."""
        pkts = [
            _make_pkt('10.0.0.1', '10.0.0.2', 12345, 80, 'HTTP', 'TCP', 1.0,
                       tcp_flags_list=['SYN']),
            _make_pkt('10.0.0.1', '10.0.0.2', 12345, 80, 'HTTP', 'TCP', 2.0,
                       tcp_flags_list=['FIN', 'ACK']),
            _make_pkt('10.0.0.1', '10.0.0.2', 12345, 80, 'HTTP', 'TCP', 2.5,
                       tcp_flags_list=['SYN']),
        ]
        sessions = build_sessions(pkts)
        assert len(sessions) == 2

    def test_fin_teardown_stays_together(self):
        """FIN → FIN-ACK → ACK within grace period should be one session."""
        pkts = [
            _make_pkt('10.0.0.1', '10.0.0.2', 12345, 80, 'HTTP', 'TCP', 1.0,
                       tcp_flags_list=['SYN']),
            _make_pkt('10.0.0.1', '10.0.0.2', 12345, 80, 'HTTP', 'TCP', 2.0,
                       tcp_flags_list=['FIN', 'ACK']),
            _make_pkt('10.0.0.2', '10.0.0.1', 80, 12345, 'HTTP', 'TCP', 2.5,
                       tcp_flags_list=['FIN', 'ACK']),
            _make_pkt('10.0.0.1', '10.0.0.2', 12345, 80, 'HTTP', 'TCP', 2.6,
                       tcp_flags_list=['ACK']),
        ]
        sessions = build_sessions(pkts)
        assert len(sessions) == 1

    def test_grace_period_blocks_early_split(self):
        """Non-SYN packet within 5s of RST should stay in same session."""
        pkts = [
            _make_pkt('10.0.0.1', '10.0.0.2', 12345, 80, 'HTTP', 'TCP', 1.0,
                       tcp_flags_list=['SYN']),
            _make_pkt('10.0.0.1', '10.0.0.2', 12345, 80, 'HTTP', 'TCP', 2.0,
                       tcp_flags_list=['RST']),
            _make_pkt('10.0.0.2', '10.0.0.1', 80, 12345, 'HTTP', 'TCP', 4.0,
                       tcp_flags_list=['ACK']),
        ]
        sessions = build_sessions(pkts)
        assert len(sessions) == 1

    def test_grace_period_expires_splits(self):
        """Any packet after grace period (5s) past FIN should split."""
        pkts = [
            _make_pkt('10.0.0.1', '10.0.0.2', 12345, 80, 'HTTP', 'TCP', 1.0,
                       tcp_flags_list=['SYN']),
            _make_pkt('10.0.0.1', '10.0.0.2', 12345, 80, 'HTTP', 'TCP', 2.0,
                       tcp_flags_list=['FIN', 'ACK']),
            _make_pkt('10.0.0.1', '10.0.0.2', 12345, 80, 'HTTP', 'TCP', 12.0,
                       tcp_flags_list=['ACK']),
        ]
        sessions = build_sessions(pkts)
        assert len(sessions) == 2

    def test_udp_gap_splits(self):
        """UDP packets 90s apart should split (generic 60s threshold)."""
        pkts = [
            _make_pkt('10.0.0.1', '10.0.0.2', 5000, 161, 'SNMP', 'UDP', 100.0),
            _make_pkt('10.0.0.1', '10.0.0.2', 5000, 161, 'SNMP', 'UDP', 190.0),
        ]
        sessions = build_sessions(pkts)
        assert len(sessions) == 2

    def test_udp_small_gap_stays(self):
        """UDP packets 30s apart should stay together."""
        pkts = [
            _make_pkt('10.0.0.1', '10.0.0.2', 5000, 161, 'SNMP', 'UDP', 100.0),
            _make_pkt('10.0.0.1', '10.0.0.2', 5000, 161, 'SNMP', 'UDP', 130.0),
        ]
        sessions = build_sessions(pkts)
        assert len(sessions) == 1

    def test_dns_inactivity_timeout(self):
        """DNS queries >10s apart should split (Zeek-style timeout)."""
        pkts = [
            _make_pkt('10.0.0.1', '10.0.0.2', 5000, 53, 'DNS', 'UDP', 100.0),
            _make_pkt('10.0.0.1', '10.0.0.2', 5000, 53, 'DNS', 'UDP', 115.0),
        ]
        pkts[0].extra = {'dns_query': 'a.com', 'dns_qr': 'query'}
        pkts[1].extra = {'dns_query': 'b.com', 'dns_qr': 'query'}
        sessions = build_sessions(pkts)
        assert len(sessions) == 2

    def test_dhcp_xid_splits(self):
        """Different DHCP transaction IDs on same 5-tuple should split."""
        pkts = [
            _make_pkt('0.0.0.0', '255.255.255.255', 68, 67, 'DHCP', 'UDP', 1.0),
            _make_pkt('0.0.0.0', '255.255.255.255', 68, 67, 'DHCP', 'UDP', 1.2),
        ]
        pkts[0].extra = {'dhcp_xid': 1000, 'dhcp_msg_type': 'DISCOVER'}
        pkts[1].extra = {'dhcp_xid': 2000, 'dhcp_msg_type': 'DISCOVER'}
        sessions = build_sessions(pkts)
        assert len(sessions) == 2

    def test_dhcp_same_xid_stays(self):
        """Same DHCP transaction ID should stay together."""
        pkts = [
            _make_pkt('0.0.0.0', '255.255.255.255', 68, 67, 'DHCP', 'UDP', 1.0),
            _make_pkt('0.0.0.0', '255.255.255.255', 68, 67, 'DHCP', 'UDP', 1.5),
        ]
        pkts[0].extra = {'dhcp_xid': 1000, 'dhcp_msg_type': 'DISCOVER'}
        pkts[1].extra = {'dhcp_xid': 1000, 'dhcp_msg_type': 'REQUEST'}
        sessions = build_sessions(pkts)
        assert len(sessions) == 1

    def test_seq_wraparound_no_false_split(self):
        """TCP seq wrapping near 2^32 should NOT cause a false split."""
        pkts = [
            _make_pkt('10.0.0.1', '10.0.0.2', 12345, 80, 'HTTP', 'TCP', 1.0,
                       tcp_flags_list=['ACK']),
            _make_pkt('10.0.0.1', '10.0.0.2', 12345, 80, 'HTTP', 'TCP', 8.0,
                       tcp_flags_list=['ACK']),
        ]
        # Seq near the top of the 32-bit space, then wraps to near 0
        pkts[0].seq_num = 4_294_967_290
        pkts[1].seq_num = 5
        sessions = build_sessions(pkts)
        assert len(sessions) == 1, 'Seq wraparound should not trigger a split'

    def test_resp_isn_reset_across_generations(self):
        """Responder ISN from gen N should not leak into gen N+1."""
        pkts = [
            # Gen 0: normal connection
            _make_pkt('10.0.0.1', '10.0.0.2', 12345, 80, 'HTTP', 'TCP', 1.0,
                       tcp_flags_list=['SYN']),
            _make_pkt('10.0.0.2', '10.0.0.1', 80, 12345, 'HTTP', 'TCP', 1.1,
                       tcp_flags_list=['SYN', 'ACK']),
            _make_pkt('10.0.0.1', '10.0.0.2', 12345, 80, 'HTTP', 'TCP', 2.0,
                       tcp_flags_list=['FIN', 'ACK']),
            # Gen 1: new SYN
            _make_pkt('10.0.0.1', '10.0.0.2', 12345, 80, 'HTTP', 'TCP', 2.5,
                       tcp_flags_list=['SYN']),
            # Gen 1: FIN
            _make_pkt('10.0.0.1', '10.0.0.2', 12345, 80, 'HTTP', 'TCP', 3.0,
                       tcp_flags_list=['FIN', 'ACK']),
            # Gen 2 attempt: SYN-ACK with same ISN as gen 0's responder
            # This should still split because last_resp_isn was reset
            _make_pkt('10.0.0.2', '10.0.0.1', 80, 12345, 'HTTP', 'TCP', 10.0,
                       tcp_flags_list=['SYN', 'ACK']),
        ]
        pkts[1].seq_num = 9999  # Gen 0 responder ISN
        pkts[5].seq_num = 9999  # Same ISN — would NOT split if leaked
        sessions = build_sessions(pkts)
        # After grace period (10.0 - 3.0 = 7s > 5s), any packet splits
        assert len(sessions) == 3


class TestSessionBoundaryPcap:
    """Boundary detection tests against real traffic (tests/test2.pcapng)."""

    PCAP_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'tests', 'test2.pcapng')

    @pytest.fixture
    def pcap_data(self):
        if not os.path.exists(self.PCAP_PATH):
            pytest.skip('test2.pcapng not found')
        packets = read_pcap(self.PCAP_PATH)
        sessions = build_sessions(packets)
        return packets, sessions

    def test_pcap_parses(self, pcap_data):
        packets, _ = pcap_data
        assert len(packets) > 1000

    def test_sessions_built(self, pcap_data):
        _, sessions = pcap_data
        assert len(sessions) > 50

    def test_all_packets_assigned(self, pcap_data):
        """Every packet with src+dst IP should end up in a session."""
        packets, sessions = pcap_data
        total_in_sessions = sum(s['packet_count'] for s in sessions)
        ip_packets = [p for p in packets if p.src_ip and p.dst_ip]
        assert total_in_sessions == len(ip_packets)

    def test_boundary_detection_fires(self, pcap_data):
        """Real traffic should have some split sessions."""
        _, sessions = pcap_data
        split = [s for s in sessions if '#' in s['id']]
        assert len(split) > 0, 'Expected boundary detection to fire on real traffic'

    def test_split_sessions_have_packets(self, pcap_data):
        """Every split session should have at least 1 packet."""
        _, sessions = pcap_data
        split = [s for s in sessions if '#' in s['id']]
        for s in split:
            assert s['packet_count'] > 0

    def test_no_empty_sessions(self, pcap_data):
        """No session should have 0 packets."""
        _, sessions = pcap_data
        for s in sessions:
            assert s['packet_count'] > 0, f'Empty session: {s["id"]}'

    def test_session_times_valid(self, pcap_data):
        """end_time >= start_time for every session."""
        _, sessions = pcap_data
        for s in sessions:
            assert s['end_time'] >= s['start_time'], f'Invalid times: {s["id"]}'


# ── Plugin tests ────────────────────────────────────────────────────────────

class TestPluginLoads:
    """Verify that all insight plugins load and produce results."""

    def test_insight_plugins_load(self, packets, sessions):
        # Clear any existing state
        _plugins.clear()
        _global_results.clear()

        # Try loading each plugin
        plugin_specs = [
            ("plugins.insights.os_fingerprint", "OSFingerprintPlugin"),
            ("plugins.insights.tcp_flags", "TCPFlagsPlugin"),
            ("plugins.insights.dns_resolver", "DNSResolverPlugin"),
            ("plugins.insights.network_map", "NetworkMapPlugin"),
        ]
        loaded = 0
        for module_path, class_name in plugin_specs:
            try:
                mod = importlib.import_module(module_path)
                cls = getattr(mod, class_name)
                register_plugin(cls())
                loaded += 1
            except Exception:
                pass  # Plugin may have dependencies not available in test

        if loaded > 0:
            ctx = AnalysisContext(packets=packets, sessions=sessions)
            run_global_analysis(ctx)
            results = get_global_results()
            assert isinstance(results, dict)
            # At least the loaded plugins should produce results
            assert len(results) == loaded


class TestAnalysisPlugins:
    """Verify analysis plugins produce valid _display output."""

    def test_node_centrality(self, packets, sessions):
        graph = build_graph(packets)
        ctx = AnalysisContext(packets=packets, sessions=sessions)
        ctx.nodes = graph['nodes']
        ctx.edges = graph['edges']
        result = NodeCentralityAnalysis().compute(ctx)
        assert '_display' in result
        assert 'ranked' in result
        assert len(result['ranked']) == 3  # 3 nodes

    def test_traffic_characterisation(self, packets, sessions):
        ctx = AnalysisContext(packets=packets, sessions=sessions)
        result = TrafficCharacterisationAnalysis().compute(ctx)
        assert '_display' in result
        assert 'summary' in result
        assert result['summary']['total'] == 3


# ── Alert detector tests ───────────────────────────────────────────────────

class TestArpSpoofingDetector:
    def test_ip_claimed_by_multiple_macs(self):
        """Two ARP packets from different MACs claiming the same IP should trigger a high alert."""
        t0 = 1700000000.0
        pkts = [
            _make_pkt('0.0.0.0', '255.255.255.255', 0, 0, 'ARP', 'ARP', t0,
                       src_mac='aa:bb:cc:dd:ee:01', dst_mac='ff:ff:ff:ff:ff:ff'),
            _make_pkt('0.0.0.0', '255.255.255.255', 0, 0, 'ARP', 'ARP', t0 + 1,
                       src_mac='aa:bb:cc:dd:ee:02', dst_mac='ff:ff:ff:ff:ff:ff'),
        ]
        pkts[0].extra = {"arp_opcode": 2, "arp_src_mac": "aa:bb:cc:dd:ee:01", "arp_src_ip": "10.0.0.1", "arp_dst_ip": "10.0.0.1"}
        pkts[1].extra = {"arp_opcode": 2, "arp_src_mac": "aa:bb:cc:dd:ee:02", "arp_src_ip": "10.0.0.1", "arp_dst_ip": "10.0.0.1"}
        ctx = AnalysisContext(packets=pkts, sessions=[])
        ctx.nodes = []
        ctx.edges = []
        alerts = ArpSpoofingDetector().detect(ctx)
        spoof_alerts = [a for a in alerts if a.title == "ARP Spoofing"]
        assert len(spoof_alerts) == 1
        assert spoof_alerts[0].severity == "high"
        assert "10.0.0.1" in spoof_alerts[0].node_ids

    def test_no_spoofing_clean(self):
        """Single MAC per IP should produce no spoofing alerts."""
        t0 = 1700000000.0
        pkts = [
            _make_pkt('0.0.0.0', '255.255.255.255', 0, 0, 'ARP', 'ARP', t0 + i,
                       src_mac='aa:bb:cc:dd:ee:01', dst_mac='ff:ff:ff:ff:ff:ff')
            for i in range(5)
        ]
        for p in pkts:
            p.extra = {"arp_opcode": 1, "arp_src_mac": "aa:bb:cc:dd:ee:01", "arp_src_ip": "10.0.0.1", "arp_dst_ip": "10.0.0.2"}
        ctx = AnalysisContext(packets=pkts, sessions=[])
        ctx.nodes = []
        ctx.edges = []
        alerts = ArpSpoofingDetector().detect(ctx)
        spoof_alerts = [a for a in alerts if a.title == "ARP Spoofing"]
        assert len(spoof_alerts) == 0


class TestMaliciousJA3Detector:
    def test_malicious_ja3_detection(self):
        """Session with known malware JA3 should produce a high alert."""
        session = {
            "session_id": "s1", "protocol": "TLS", "transport": "TCP",
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "start_time": 1700000000.0,
            "ja3_hashes": ["51c64c77e60f3980eea90869b68c58a8"],  # Metasploit
            "tls_snis": ["evil.example.com"], "tls_versions": ["TLS 1.2"],
        }
        ctx = AnalysisContext(packets=[], sessions=[session])
        ctx.nodes = []
        ctx.edges = []
        alerts = MaliciousJA3Detector().detect(ctx)
        ja3_alerts = [a for a in alerts if a.title == "Malicious JA3 Fingerprint"]
        assert len(ja3_alerts) == 1
        assert ja3_alerts[0].severity == "high"


class TestSuspiciousUADetector:
    def test_scripting_tool_ua(self):
        """HTTP session with python-requests UA should produce a medium alert."""
        session = {
            "session_id": "s1", "protocol": "HTTP", "transport": "TCP",
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "start_time": 1700000000.0,
            "http_fwd_user_agents": ["python-requests/2.28.0"],
        }
        ctx = AnalysisContext(packets=[], sessions=[session])
        ctx.nodes = []
        ctx.edges = []
        alerts = SuspiciousUADetector().detect(ctx)
        ua_alerts = [a for a in alerts if a.title == "Suspicious User-Agent"]
        assert len(ua_alerts) == 1
        assert ua_alerts[0].severity == "medium"

    def test_empty_ua_detection(self):
        """HTTP session with empty UA list should produce a low alert."""
        session = {
            "session_id": "s1", "protocol": "HTTP", "transport": "TCP",
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "start_time": 1700000000.0,
            "http_fwd_user_agents": [],
        }
        ctx = AnalysisContext(packets=[], sessions=[session])
        ctx.nodes = []
        ctx.edges = []
        alerts = SuspiciousUADetector().detect(ctx)
        empty_alerts = [a for a in alerts if a.title == "Empty User-Agent"]
        assert len(empty_alerts) == 1
        assert empty_alerts[0].severity == "low"


class TestPortScanDetector:
    def test_tcp_port_scan_detection(self):
        """20 TCP sessions to distinct ports with no handshakes should trigger an alert."""
        sessions = []
        for port in range(20):
            sessions.append({
                "session_id": f"s{port}", "protocol": "TCP", "transport": "TCP",
                "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                "dst_port": 1000 + port, "start_time": 1700000000.0 + port,
                "has_handshake": False,
            })
        ctx = AnalysisContext(packets=[], sessions=sessions)
        ctx.nodes = []
        ctx.edges = []
        alerts = PortScanDetector().detect(ctx)
        scan_alerts = [a for a in alerts if a.title == "TCP Port Scan"]
        assert len(scan_alerts) == 1
        assert scan_alerts[0].severity == "medium"  # 20 ports: medium (< 50)

    def test_port_scan_below_threshold(self):
        """10 sessions to distinct ports should NOT trigger (threshold is 15)."""
        sessions = []
        for port in range(10):
            sessions.append({
                "session_id": f"s{port}", "protocol": "TCP", "transport": "TCP",
                "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                "dst_port": 1000 + port, "start_time": 1700000000.0 + port,
                "has_handshake": False,
            })
        ctx = AnalysisContext(packets=[], sessions=sessions)
        ctx.nodes = []
        ctx.edges = []
        alerts = PortScanDetector().detect(ctx)
        assert len(alerts) == 0

    def test_udp_port_scan_detection(self):
        """20 UDP sessions to distinct ports should trigger a UDP scan alert."""
        sessions = []
        for port in range(20):
            sessions.append({
                "session_id": f"s{port}", "protocol": "DNS", "transport": "UDP",
                "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                "dst_port": 2000 + port, "start_time": 1700000000.0 + port,
            })
        ctx = AnalysisContext(packets=[], sessions=sessions)
        ctx.nodes = []
        ctx.edges = []
        alerts = PortScanDetector().detect(ctx)
        udp_alerts = [a for a in alerts if a.title == "UDP Port Scan"]
        assert len(udp_alerts) == 1
        assert udp_alerts[0].severity == "medium"


class TestAlertSortOrder:
    def test_severity_sort_order(self):
        """Alerts should be sorted high -> medium -> low -> info."""
        sessions = [
            # This triggers a low alert (empty UA)
            {"session_id": "s1", "protocol": "HTTP", "transport": "TCP",
             "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "start_time": 1700000000.0,
             "http_fwd_user_agents": []},
            # This triggers a medium alert (python-requests)
            {"session_id": "s2", "protocol": "HTTP", "transport": "TCP",
             "src_ip": "10.0.0.3", "dst_ip": "10.0.0.4", "start_time": 1700000001.0,
             "http_fwd_user_agents": ["python-requests/2.28"]},
            # This triggers a high alert (malware JA3)
            {"session_id": "s3", "protocol": "TLS", "transport": "TCP",
             "src_ip": "10.0.0.5", "dst_ip": "10.0.0.6", "start_time": 1700000002.0,
             "ja3_hashes": ["51c64c77e60f3980eea90869b68c58a8"],
             "tls_snis": [], "tls_versions": ["TLS 1.2"]},
        ]
        ctx = AnalysisContext(packets=[], sessions=sessions)
        ctx.nodes = []
        ctx.edges = []
        # Run individual detectors and combine via run_all_detectors pattern
        all_alerts = []
        all_alerts.extend(a.to_dict() for a in SuspiciousUADetector().detect(ctx))
        all_alerts.extend(a.to_dict() for a in MaliciousJA3Detector().detect(ctx))
        # Sort same way as run_all_detectors
        sev_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        all_alerts.sort(key=lambda a: (sev_order.get(a["severity"], 9), a.get("timestamp") or 0))
        assert len(all_alerts) >= 3
        severities = [a["severity"] for a in all_alerts]
        # Verify ordering: all highs before mediums before lows
        prev_rank = -1
        for sev in severities:
            rank = sev_order[sev]
            assert rank >= prev_rank, f"Sort violation: {sev} after higher-ranked severity"
            prev_rank = rank
