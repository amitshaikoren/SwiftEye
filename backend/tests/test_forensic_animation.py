"""
Tests for the forensic animation event builder.

Run: pytest backend/tests/test_forensic_animation.py -v
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from workspaces.forensic.analysis.animation import (
    build_forensic_animation_response,
    _ts_epoch,
)


# ── _ts_epoch ─────────────────────────────────────────────────────────────────

class TestTsEpoch:
    def test_none_returns_none(self):
        assert _ts_epoch(None) is None

    def test_float_passthrough(self):
        assert _ts_epoch(1700000000.0) == 1700000000.0

    def test_int_cast(self):
        assert _ts_epoch(1700000000) == 1700000000.0

    def test_iso_string(self):
        epoch = _ts_epoch("2023-11-14T22:13:20+00:00")
        assert abs(epoch - 1700000000.0) < 2  # within 2s (TZ rounding)

    def test_iso_string_z_suffix(self):
        epoch = _ts_epoch("2023-01-01T00:00:00Z")
        assert isinstance(epoch, float)

    def test_invalid_string_returns_none(self):
        assert _ts_epoch("not-a-date") is None


# ── build_forensic_animation_response ────────────────────────────────────────

def _make_graph(node_ids=None, events_per_edge=2):
    """Minimal graph_cache with two nodes and one edge."""
    if node_ids is None:
        node_ids = ["fx:proc:aaa", "fx:endpoint:1.2.3.4"]
    nodes = [
        {"id": node_ids[0], "label": "proc_a", "color": "#58a6ff", "type": "process"},
        {"id": node_ids[1], "label": "1.2.3.4", "color": "#4fc3f7", "type": "endpoint"},
    ]
    events = [
        {"action_type": "network_connect", "ts": f"2023-01-01T00:00:0{i}Z", "fields": {}, "source": {}}
        for i in range(events_per_edge)
    ]
    edges = [
        {
            "id": f"{node_ids[0]}|{node_ids[1]}",
            "source": node_ids[0],
            "target": node_ids[1],
            "type": "connected",
            "color": "#58a6ff",
            "events": events,
        }
    ]
    return {"nodes": nodes, "edges": edges}


class TestBuildForensicAnimationResponse:

    def test_response_shape(self):
        gc = _make_graph()
        resp = build_forensic_animation_response(gc, set())
        assert "events" in resp
        assert "nodes" in resp

    def test_event_count_matches_edge_events(self):
        gc = _make_graph(events_per_edge=3)
        resp = build_forensic_animation_response(gc, set())
        assert len(resp["events"]) == 3

    def test_all_events_are_start_type(self):
        gc = _make_graph(events_per_edge=4)
        resp = build_forensic_animation_response(gc, set())
        assert all(ev["type"] == "start" for ev in resp["events"])

    def test_events_sorted_by_time(self):
        gc = _make_graph(events_per_edge=5)
        resp = build_forensic_animation_response(gc, set())
        times = [ev["time"] for ev in resp["events"]]
        assert times == sorted(times)

    def test_spotlight_flag(self):
        ids = ["fx:proc:aaa", "fx:endpoint:1.2.3.4"]
        gc = _make_graph(node_ids=ids)
        resp = build_forensic_animation_response(gc, {ids[0]})
        assert resp["nodes"][ids[0]]["is_spotlight"] is True
        assert resp["nodes"][ids[1]]["is_spotlight"] is False

    def test_node_ids_filter_excludes_unrelated_edges(self):
        # Create graph with two edges; spotlight only one node
        n = ["fx:proc:aaa", "fx:proc:bbb", "fx:endpoint:1.1.1.1"]
        nodes = [{"id": x, "label": x, "color": "#aaa", "type": "process"} for x in n]
        edges = [
            {
                "id": f"{n[0]}|{n[2]}", "source": n[0], "target": n[2],
                "type": "connected", "color": "#58a6ff",
                "events": [{"action_type": "network_connect", "ts": "2023-01-01T00:00:01Z", "fields": {}, "source": {}}],
            },
            {
                "id": f"{n[1]}|{n[2]}", "source": n[1], "target": n[2],
                "type": "connected", "color": "#58a6ff",
                "events": [{"action_type": "network_connect", "ts": "2023-01-01T00:00:02Z", "fields": {}, "source": {}}],
            },
        ]
        gc = {"nodes": nodes, "edges": edges}
        resp = build_forensic_animation_response(gc, {n[0]})
        # Only the edge involving n[0] should appear
        assert len(resp["events"]) == 1
        assert resp["events"][0]["src"] == n[0]

    def test_empty_node_ids_includes_all_edges(self):
        n = ["fx:proc:aaa", "fx:proc:bbb", "fx:endpoint:1.1.1.1"]
        nodes = [{"id": x, "label": x, "color": "#aaa", "type": "process"} for x in n]
        edges = [
            {
                "id": f"{n[0]}|{n[2]}", "source": n[0], "target": n[2],
                "type": "connected", "color": "#aaa",
                "events": [{"action_type": "network_connect", "ts": "2023-01-01T00:00:01Z", "fields": {}, "source": {}}],
            },
            {
                "id": f"{n[1]}|{n[2]}", "source": n[1], "target": n[2],
                "type": "connected", "color": "#aaa",
                "events": [{"action_type": "network_connect", "ts": "2023-01-01T00:00:02Z", "fields": {}, "source": {}}],
            },
        ]
        gc = {"nodes": nodes, "edges": edges}
        resp = build_forensic_animation_response(gc, set())
        assert len(resp["events"]) == 2

    def test_edge_color_carried_on_events(self):
        gc = _make_graph()
        gc["edges"][0]["color"] = "#ff6b6b"
        resp = build_forensic_animation_response(gc, set())
        assert all(ev["color"] == "#ff6b6b" for ev in resp["events"])

    def test_node_meta_color_from_graph(self):
        gc = _make_graph()
        gc["nodes"][0]["color"] = "#abcdef"
        resp = build_forensic_animation_response(gc, set())
        nid = gc["nodes"][0]["id"]
        assert resp["nodes"][nid]["color"] == "#abcdef"

    def test_events_with_no_timestamp_get_synthetic_time(self):
        gc = _make_graph(events_per_edge=3)
        for ev in gc["edges"][0]["events"]:
            ev["ts"] = None
        resp = build_forensic_animation_response(gc, set())
        # All times should be distinct non-negative
        times = [ev["time"] for ev in resp["events"]]
        assert all(t >= 0 for t in times)
        assert len(set(times)) == 3  # distinct

    def test_unique_session_ids(self):
        gc = _make_graph(events_per_edge=5)
        resp = build_forensic_animation_response(gc, set())
        sids = [ev["session_id"] for ev in resp["events"]]
        assert len(sids) == len(set(sids))
