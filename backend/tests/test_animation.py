"""
Tests for node animation event builder.

Run: pytest backend/tests/test_animation.py -v
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from workspaces.network.analysis.aggregator import build_node_session_events, build_node_animation_response


# ── Helpers ───────────────────────────────────────────────────────────────────

def _session(sid, src, dst, proto, start, end, total_bytes=1000, packet_count=10):
    return {
        "id": sid,
        "src_ip": src,
        "dst_ip": dst,
        "protocol": proto,
        "start_time": start,
        "end_time": end,
        "total_bytes": total_bytes,
        "packet_count": packet_count,
    }


@pytest.fixture
def sessions():
    """
    4 sessions across 4 IPs:
      s1: A→B  DNS    t=1..3
      s2: A→C  HTTPS  t=2..5
      s3: B→D  SSH    t=4..8
      s4: C→D  HTTP   t=6..9
    """
    return [
        _session("s1", "10.0.0.1", "10.0.0.2", "DNS",   1.0, 3.0, 500, 5),
        _session("s2", "10.0.0.1", "10.0.0.3", "HTTPS", 2.0, 5.0, 2000, 20),
        _session("s3", "10.0.0.2", "10.0.0.4", "SSH",   4.0, 8.0, 3000, 30),
        _session("s4", "10.0.0.3", "10.0.0.4", "HTTP",  6.0, 9.0, 1500, 15),
    ]


# ── build_node_session_events ─────────────────────────────────────────────────

class TestBuildNodeSessionEvents:

    def test_single_spotlight_returns_connected_sessions(self, sessions):
        events = build_node_session_events(sessions, {"10.0.0.1"})
        session_ids = {e["session_id"] for e in events}
        assert session_ids == {"s1", "s2"}
        assert len(events) == 4  # 2 starts + 2 ends

    def test_multi_spotlight_includes_union(self, sessions):
        events = build_node_session_events(sessions, {"10.0.0.1", "10.0.0.4"})
        session_ids = {e["session_id"] for e in events}
        # s1 (A→B, A is spotlight), s2 (A→C, A is spotlight),
        # s3 (B→D, D is spotlight), s4 (C→D, D is spotlight)
        assert session_ids == {"s1", "s2", "s3", "s4"}

    def test_events_sorted_by_time(self, sessions):
        events = build_node_session_events(sessions, {"10.0.0.1", "10.0.0.4"})
        times = [e["time"] for e in events]
        assert times == sorted(times)

    def test_start_before_end_at_same_time(self, sessions):
        # Create two sessions where one ends at the same time another starts
        ss = [
            _session("a", "10.0.0.1", "10.0.0.2", "DNS", 1.0, 3.0),
            _session("b", "10.0.0.1", "10.0.0.3", "TCP", 3.0, 5.0),
        ]
        events = build_node_session_events(ss, {"10.0.0.1"})
        # At t=3.0 we should see: start of b before end of a
        at_3 = [e for e in events if e["time"] == 3.0]
        assert len(at_3) == 2
        assert at_3[0]["type"] == "start"
        assert at_3[1]["type"] == "end"

    def test_protocol_filter(self, sessions):
        events = build_node_session_events(sessions, {"10.0.0.1"}, protocols={"DNS"})
        session_ids = {e["session_id"] for e in events}
        assert session_ids == {"s1"}

    def test_no_matching_nodes_returns_empty(self, sessions):
        events = build_node_session_events(sessions, {"99.99.99.99"})
        assert events == []

    def test_event_fields(self, sessions):
        events = build_node_session_events(sessions, {"10.0.0.1"})
        start_ev = next(e for e in events if e["type"] == "start" and e["session_id"] == "s1")
        assert start_ev["src"] == "10.0.0.1"
        assert start_ev["dst"] == "10.0.0.2"
        assert start_ev["protocol"] == "DNS"
        assert start_ev["bytes"] == 500
        assert start_ev["packets"] == 5
        assert start_ev["time"] == 1.0


# ── build_node_animation_response ─────────────────────────────────────────────

class TestBuildNodeAnimationResponse:

    def test_response_shape(self, sessions):
        resp = build_node_animation_response(sessions, {"10.0.0.1"})
        assert "events" in resp
        assert "nodes" in resp
        assert isinstance(resp["events"], list)
        assert isinstance(resp["nodes"], dict)

    def test_spotlight_flag(self, sessions):
        resp = build_node_animation_response(sessions, {"10.0.0.1"})
        assert resp["nodes"]["10.0.0.1"]["is_spotlight"] is True
        # Neighbours should not be spotlight
        assert resp["nodes"]["10.0.0.2"]["is_spotlight"] is False
        assert resp["nodes"]["10.0.0.3"]["is_spotlight"] is False

    def test_private_detection(self, sessions):
        resp = build_node_animation_response(sessions, {"10.0.0.1"})
        assert resp["nodes"]["10.0.0.1"]["is_private"] is True

    def test_hostname_passthrough(self, sessions):
        hn = {"10.0.0.1": {"host1.local", "host2.local"}}
        resp = build_node_animation_response(sessions, {"10.0.0.1"}, hostname_map=hn)
        node = resp["nodes"]["10.0.0.1"]
        assert node["hostname"] == "host1.local"
        assert "host2.local" in node["hostnames"]

    def test_bytes_and_packets_aggregated(self, sessions):
        resp = build_node_animation_response(sessions, {"10.0.0.1"})
        # 10.0.0.1 is in s1 (500B/5pkt) and s2 (2000B/20pkt)
        node = resp["nodes"]["10.0.0.1"]
        assert node["bytes"] == 2500
        assert node["packets"] == 25

    def test_protocol_filter_propagates(self, sessions):
        resp = build_node_animation_response(sessions, {"10.0.0.1"}, protocols={"DNS"})
        assert len(resp["events"]) == 2  # 1 start + 1 end
        assert set(resp["nodes"].keys()) == {"10.0.0.1", "10.0.0.2"}

    def test_neighbour_nodes_included(self, sessions):
        resp = build_node_animation_response(sessions, {"10.0.0.1"})
        # 10.0.0.1 talks to .2 and .3
        assert "10.0.0.2" in resp["nodes"]
        assert "10.0.0.3" in resp["nodes"]
        # .4 is not connected to .1
        assert "10.0.0.4" not in resp["nodes"]
