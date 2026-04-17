"""
Tests for backend/llm/context_builder.py

Uses a lightweight mock store so tests don't require a loaded PCAP.
Covers:
- Context packet shape (required sections always present)
- Scope precedence
- Selection context routing
- Retrieval rules by tag
- Limitations section content
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from unittest.mock import patch, MagicMock

from core.llm.contracts import (
    ChatRequest, Message, ScopeSpec, ViewerState, SelectionState,
    ProviderConfig, ChatOptions,
)
from core.llm.question_tags import (
    TAG_BROAD_OVERVIEW, TAG_ENTITY_NODE, TAG_ENTITY_EDGE,
    TAG_ALERT_EVIDENCE, TAG_ATTRIBUTION_RISK, TAG_UNRELATED,
)


# ── Minimal fake store ────────────────────────────────────────────────────────

def _make_store(
    loaded=True,
    packets=None,
    sessions=None,
    alerts=None,
    nodes=None,
    edges=None,
    stats=None,
):
    st = MagicMock()
    st.is_loaded = loaded
    st.capture_id = "cap_test_001"
    st.file_name = "test.pcap"
    st.source_files = ["test.pcap"]
    st.packets = packets or []
    st.sessions = sessions or []
    st.alerts = alerts or []
    st.graph_cache = {
        "nodes": nodes or [],
        "edges": edges or [],
    }
    st.stats = stats or {
        "total_packets": len(packets or []),
        "total_bytes": 0,
        "unique_ips": 0,
        "total_sessions": 0,
        "duration": 0.0,
        "packets_per_second": 0,
        "protocols": {},
        "top_talkers": [],
    }
    return st


def _make_request(
    question="What is happening?",
    scope_mode="full_capture",
    entity_type=None,
    entity_id=None,
    sel_nodes=None,
    sel_edge=None,
    sel_session=None,
    sel_alert=None,
):
    return ChatRequest(
        messages=[Message(role="user", content=question)],
        scope=ScopeSpec(mode=scope_mode, entity_type=entity_type, entity_id=entity_id),
        viewer_state=ViewerState(),
        selection=SelectionState(
            node_ids=sel_nodes or [],
            edge_id=sel_edge,
            session_id=sel_session,
            alert_id=sel_alert,
        ),
        provider=ProviderConfig(kind="ollama", model="test"),
        options=ChatOptions(),
    )


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestContextPacketShape:
    def test_required_sections_always_present(self):
        with patch('llm.context_builder._store') as mock_store_mod:
            mock_store_mod.store = _make_store()
            with patch('llm.context_builder.get_analysis_results', return_value={}):
                from core.llm.context_builder import build_context_packet
                req = _make_request()
                packet = build_context_packet(req, [TAG_BROAD_OVERVIEW])

        assert "scope" in packet
        assert "capture_meta" in packet
        assert "overview" in packet
        assert "retrieval_manifest" in packet
        assert "limitations" in packet

    def test_no_capture_loaded(self):
        with patch('llm.context_builder._store') as mock_store_mod:
            mock_store_mod.store = _make_store(loaded=False)
            with patch('llm.context_builder.get_analysis_results', return_value={}):
                from core.llm.context_builder import build_context_packet
                req = _make_request()
                packet = build_context_packet(req, [TAG_BROAD_OVERVIEW])

        assert packet["capture_meta"]["loaded"] is False
        assert "No capture" in packet["limitations"]["items"][0]


class TestScopeSection:
    def test_scope_mode_preserved(self):
        with patch('llm.context_builder._store') as mock_store_mod:
            mock_store_mod.store = _make_store()
            with patch('llm.context_builder.get_analysis_results', return_value={}):
                from core.llm.context_builder import build_context_packet
                req = _make_request(scope_mode="current_view")
                packet = build_context_packet(req, [TAG_BROAD_OVERVIEW])

        assert packet["scope"]["mode"] == "current_view"

    def test_tags_included_in_scope(self):
        tags = [TAG_ENTITY_NODE, "dns"]
        with patch('llm.context_builder._store') as mock_store_mod:
            mock_store_mod.store = _make_store()
            with patch('llm.context_builder.get_analysis_results', return_value={}):
                from core.llm.context_builder import build_context_packet
                req = _make_request()
                packet = build_context_packet(req, tags)

        assert packet["scope"]["question_tags"] == tags


class TestSelectionContext:
    def test_node_selection_produces_selection_context(self):
        nodes = [{"id": "10.0.0.5", "ips": ["10.0.0.5"], "macs": [], "mac_vendors": [],
                  "protocols": [], "total_bytes": 0, "packet_count": 0,
                  "ttls_out": [], "ttls_in": [], "is_private": True, "hostnames": [],
                  "top_dst_ports": [], "top_src_ports": [], "top_neighbors": [],
                  "top_protocols": [], "edge_ids": []}]
        with patch('llm.context_builder._store') as mock_store_mod:
            mock_store_mod.store = _make_store(nodes=nodes)
            with patch('llm.context_builder.get_analysis_results', return_value={}):
                from core.llm.context_builder import build_context_packet
                req = _make_request(sel_nodes=["10.0.0.5"])
                packet = build_context_packet(req, [TAG_ENTITY_NODE])

        assert "selection_context" in packet
        assert packet["selection_context"]["type"] == "nodes"

    def test_alert_selection_produces_alert_context(self):
        alerts = [{"id": "alert_001", "title": "Port Scan", "subtitle": "test",
                   "severity": "high", "detector": "port_scan",
                   "source": "detector", "source_name": "port_scan",
                   "timestamp": 1000.0, "src_ip": "10.0.0.5", "dst_ip": None,
                   "evidence": [], "node_ids": [], "edge_ids": [], "session_ids": []}]
        with patch('llm.context_builder._store') as mock_store_mod:
            mock_store_mod.store = _make_store(alerts=alerts)
            with patch('llm.context_builder.get_analysis_results', return_value={}):
                from core.llm.context_builder import build_context_packet
                req = _make_request(sel_alert="alert_001")
                packet = build_context_packet(req, [TAG_ALERT_EVIDENCE])

        assert "selection_context" in packet
        assert packet["selection_context"]["type"] == "alert"

    def test_no_selection_no_selection_context(self):
        with patch('llm.context_builder._store') as mock_store_mod:
            mock_store_mod.store = _make_store()
            with patch('llm.context_builder.get_analysis_results', return_value={}):
                from core.llm.context_builder import build_context_packet
                req = _make_request()
                packet = build_context_packet(req, [TAG_BROAD_OVERVIEW])

        assert "selection_context" not in packet


class TestLimitationsSection:
    def test_attribution_risk_adds_disclaimer(self):
        with patch('llm.context_builder._store') as mock_store_mod:
            mock_store_mod.store = _make_store()
            with patch('llm.context_builder.get_analysis_results', return_value={}):
                from core.llm.context_builder import build_context_packet
                req = _make_request(question="Where is the attacker?")
                packet = build_context_packet(req, [TAG_ATTRIBUTION_RISK])

        items = packet["limitations"]["items"]
        assert any("attacker" in item.lower() or "attribution" in item.lower() for item in items)

    def test_payload_bytes_limitation_always_present(self):
        with patch('llm.context_builder._store') as mock_store_mod:
            mock_store_mod.store = _make_store()
            with patch('llm.context_builder.get_analysis_results', return_value={}):
                from core.llm.context_builder import build_context_packet
                req = _make_request()
                packet = build_context_packet(req, [TAG_BROAD_OVERVIEW])

        items = packet["limitations"]["items"]
        assert any("payload" in item.lower() for item in items)


class TestRetrievalManifest:
    def test_manifest_shape(self):
        with patch('llm.context_builder._store') as mock_store_mod:
            mock_store_mod.store = _make_store()
            with patch('llm.context_builder.get_analysis_results', return_value={}):
                from core.llm.context_builder import build_context_packet
                req = _make_request()
                packet = build_context_packet(req, [TAG_BROAD_OVERVIEW])

        manifest = packet["retrieval_manifest"]
        assert "already_retrieved" in manifest
        assert "available_for_expansion" in manifest
