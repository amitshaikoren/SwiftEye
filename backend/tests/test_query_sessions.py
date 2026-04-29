"""Tests for resolve_session_query — session query primitive."""
import pytest
from core.data.query.query_engine import resolve_session_query


def _make_sessions():
    return [
        {
            "id": "10.0.0.1|10.0.0.2|443|52345|TCP",
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
            "src_port": 52345, "dst_port": 443,
            "protocol": "TLS", "transport": "TCP",
            "packet_count": 20, "total_bytes": 8000,
            "payload_bytes": 7000, "duration": 1.5,
            "start_time": 0.0, "end_time": 1.5,
            "initiator_ip": "10.0.0.1", "responder_ip": "10.0.0.2",
        },
        {
            "id": "10.0.0.3|10.0.0.4|53|60123|UDP",
            "src_ip": "10.0.0.3", "dst_ip": "10.0.0.4",
            "src_port": 60123, "dst_port": 53,
            "protocol": "DNS", "transport": "UDP",
            "packet_count": 2, "total_bytes": 200,
            "payload_bytes": 180, "duration": 0.01,
            "start_time": 0.0, "end_time": 0.01,
            "initiator_ip": "10.0.0.3", "responder_ip": "10.0.0.4",
        },
        {
            "id": "10.0.0.1|10.0.0.5|80|55000|TCP",
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.5",
            "src_port": 55000, "dst_port": 80,
            "protocol": "HTTP", "transport": "TCP",
            "packet_count": 10, "total_bytes": 15000,
            "payload_bytes": 14000, "duration": 0.5,
            "start_time": 0.0, "end_time": 0.5,
            "initiator_ip": "10.0.0.1", "responder_ip": "10.0.0.5",
        },
    ]


def test_filter_by_protocol_equals():
    sessions = _make_sessions()
    result = resolve_session_query(sessions, {
        "target": "sessions",
        "conditions": [{"field": "protocol", "op": "equals", "value": "TLS"}],
        "logic": "AND",
    })
    assert result["total_matched"] == 1
    assert result["total_searched"] == 3
    assert result["matched_sessions"] == ["10.0.0.1|10.0.0.2|443|52345|TCP"]
    node_ids = {m["id"] for m in result["matched_nodes"]}
    edge_ids = {m["id"] for m in result["matched_edges"]}
    assert "10.0.0.1" in node_ids
    assert "10.0.0.2" in node_ids
    assert "10.0.0.1|10.0.0.2" in edge_ids


def test_filter_by_total_bytes_gt():
    sessions = _make_sessions()
    result = resolve_session_query(sessions, {
        "target": "sessions",
        "conditions": [{"field": "total_bytes", "op": ">", "value": 5000}],
        "logic": "AND",
    })
    assert result["total_matched"] == 2
    ids = set(result["matched_sessions"])
    assert "10.0.0.1|10.0.0.2|443|52345|TCP" in ids
    assert "10.0.0.1|10.0.0.5|80|55000|TCP" in ids


def test_envelope_shape():
    sessions = _make_sessions()
    result = resolve_session_query(sessions, {
        "target": "sessions",
        "conditions": [{"field": "protocol", "op": "equals", "value": "DNS"}],
    })
    assert result["target"] == "sessions"
    assert result["action"] == "highlight"
    assert "session_cards" in result
    assert "matched_nodes" in result
    assert "matched_edges" in result
    assert result["total_matched"] == 1
    card = result["session_cards"][0]
    assert card["protocol"] == "DNS"
    assert card["src_ip"] == "10.0.0.3"


def test_or_logic():
    sessions = _make_sessions()
    result = resolve_session_query(sessions, {
        "target": "sessions",
        "conditions": [
            {"field": "protocol", "op": "equals", "value": "TLS"},
            {"field": "protocol", "op": "equals", "value": "DNS"},
        ],
        "logic": "OR",
    })
    assert result["total_matched"] == 2


def test_empty_sessions():
    result = resolve_session_query([], {
        "target": "sessions",
        "conditions": [{"field": "protocol", "op": "equals", "value": "TLS"}],
    })
    assert result["total_matched"] == 0
    assert result["total_searched"] == 0
    assert result["matched_sessions"] == []


def test_no_conditions_returns_all():
    sessions = _make_sessions()
    result = resolve_session_query(sessions, {
        "target": "sessions",
        "conditions": [],
    })
    assert result["total_matched"] == 3


def test_node_and_edge_ids_populated():
    sessions = _make_sessions()
    result = resolve_session_query(sessions, {
        "target": "sessions",
        "conditions": [{"field": "protocol", "op": "equals", "value": "HTTP"}],
    })
    node_ids = {m["id"] for m in result["matched_nodes"]}
    edge_ids = {m["id"] for m in result["matched_edges"]}
    assert "10.0.0.1" in node_ids
    assert "10.0.0.5" in node_ids
    assert "10.0.0.1|10.0.0.5" in edge_ids
    assert len(result["matched_edges"]) == 1
    edge = result["matched_edges"][0]
    assert edge["id"] == "10.0.0.1|10.0.0.5"
    assert set([edge["source"], edge["target"]]) == {"10.0.0.1", "10.0.0.5"}
