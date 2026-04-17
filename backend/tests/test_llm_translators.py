"""
Tests for backend/llm/translators.py

Covers:
- Field renaming (source→initiator, target→responder, etc.)
- Array capping
- Direction semantics
- Credential hints (boolean only)
- Stats overview shape
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from core.llm.translators import (
    translate_node, translate_edge, translate_session, translate_alert,
    translate_stats_overview, cap_list, _MAX_ARRAY,
)


class TestTranslateNode:
    def _node(self, **kw):
        return {
            "id": "10.0.0.1", "ips": ["10.0.0.1"], "macs": [],
            "mac_vendors": [], "protocols": ["TCP"], "total_bytes": 1000,
            "packet_count": 10, "ttls_out": [64], "ttls_in": [],
            "is_private": True, "hostnames": [], "top_dst_ports": [],
            "top_src_ports": [], "top_neighbors": [], "top_protocols": [],
            **kw,
        }

    def test_renames_id_to_node_id(self):
        out = translate_node(self._node())
        assert "node_id" in out
        assert out["node_id"] == "10.0.0.1"

    def test_renames_ips_to_ip_addresses(self):
        out = translate_node(self._node(ips=["10.0.0.1", "10.0.0.2"]))
        assert "ip_addresses" in out
        assert out["ip_addresses"] == ["10.0.0.1", "10.0.0.2"]

    def test_renames_is_private_to_is_private_address(self):
        out = translate_node(self._node(is_private=True))
        assert out["is_private_address"] is True

    def test_caps_hostnames_at_max_array(self):
        many = [f"host{i}.example.com" for i in range(25)]
        out = translate_node(self._node(hostnames=many))
        assert len(out["hostnames"]) <= _MAX_ARRAY

    def test_empty_node_returns_empty(self):
        out = translate_node({})
        assert out == {}


class TestTranslateEdge:
    def _edge(self, **kw):
        return {
            "id": "10.0.0.1|10.0.0.2|TCP",
            "source": "10.0.0.1",
            "target": "10.0.0.2",
            "protocol": "TCP",
            "total_bytes": 500,
            "packet_count": 5,
            "first_seen": 1000.0,
            "last_seen": 1010.0,
            "ports": [443, 12345],
            "has_tls": True,
            "has_http": False,
            "has_dns": False,
            **kw,
        }

    def test_source_renamed_to_initiator(self):
        out = translate_edge(self._edge())
        assert "initiator" in out
        assert out["initiator"] == "10.0.0.1"
        assert "source" not in out

    def test_target_renamed_to_responder(self):
        out = translate_edge(self._edge())
        assert "responder" in out
        assert out["responder"] == "10.0.0.2"
        assert "target" not in out

    def test_tls_snis_renamed_to_tls_server_names(self):
        out = translate_edge(self._edge(tls_snis=["example.com"]))
        assert "tls_server_names" in out
        assert "tls_snis" not in out

    def test_http_fwd_user_agents_renamed(self):
        out = translate_edge(self._edge(http_fwd_user_agents=["Mozilla/5.0"]))
        assert "forward_http_user_agents" in out
        assert "http_fwd_user_agents" not in out

    def test_http_fwd_hosts_renamed(self):
        out = translate_edge(self._edge(http_fwd_hosts=["example.com"]))
        assert "forward_http_hosts" in out

    def test_caps_tls_snis_at_max_array(self):
        many = [f"host{i}.example.com" for i in range(25)]
        out = translate_edge(self._edge(tls_snis=many))
        assert len(out["tls_server_names"]) <= _MAX_ARRAY

    def test_edge_id_preserved(self):
        out = translate_edge(self._edge())
        assert out["edge_id"] == "10.0.0.1|10.0.0.2|TCP"


class TestTranslateSession:
    def _session(self, **kw):
        return {
            "id": "sess_001",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 12345,
            "dst_port": 443,
            "protocol": "TLS",
            "transport": "TCP",
            "total_bytes": 8000,
            "packet_count": 50,
            "duration": 3.5,
            "start_time": 1000.0,
            "has_handshake": True,
            "has_reset": False,
            "has_fin": True,
            **kw,
        }

    def test_src_ip_renamed_to_initiator(self):
        out = translate_session(self._session())
        assert "initiator" in out
        assert out["initiator"] == "10.0.0.1"

    def test_dst_ip_renamed_to_responder(self):
        out = translate_session(self._session())
        assert "responder" in out
        assert out["responder"] == "10.0.0.2"

    def test_has_handshake_renamed(self):
        out = translate_session(self._session())
        assert "has_tcp_handshake" in out
        assert out["has_tcp_handshake"] is True

    def test_credential_hints_ftp(self):
        out = translate_session(self._session(ftp_has_credentials=True))
        assert "credential_indicators" in out
        assert any("FTP" in h for h in out["credential_indicators"])

    def test_credential_hints_http_auth(self):
        out = translate_session(self._session(http_fwd_has_auth=True))
        assert "credential_indicators" in out
        assert any("HTTP" in h for h in out["credential_indicators"])

    def test_no_credential_hints_when_absent(self):
        out = translate_session(self._session())
        assert "credential_indicators" not in out

    def test_session_id_preserved(self):
        out = translate_session(self._session())
        assert out["session_id"] == "sess_001"


class TestTranslateAlert:
    def _alert(self, **kw):
        return {
            "id": "alert_001",
            "title": "Port Scan",
            "subtitle": "High SYN rate from 10.0.0.5",
            "severity": "high",
            "detector": "port_scan",
            "source": "detector",
            "source_name": "port_scan",
            "timestamp": 1000.0,
            "src_ip": "10.0.0.5",
            "dst_ip": None,
            "evidence": [{"key": "syn_count", "value": "500", "note": "in 10s"}],
            "node_ids": ["10.0.0.5"],
            "edge_ids": [],
            "session_ids": [],
            **kw,
        }

    def test_id_renamed_to_alert_id(self):
        out = translate_alert(self._alert())
        assert "alert_id" in out
        assert out["alert_id"] == "alert_001"

    def test_title_preserved_as_alert_title(self):
        out = translate_alert(self._alert())
        assert out["alert_title"] == "Port Scan"

    def test_subtitle_as_alert_summary(self):
        out = translate_alert(self._alert())
        assert out["alert_summary"] == "High SYN rate from 10.0.0.5"

    def test_evidence_capped(self):
        many_evidence = [{"key": f"k{i}", "value": "v", "note": ""} for i in range(20)]
        out = translate_alert(self._alert(evidence=many_evidence))
        assert len(out["evidence"]) <= 12


class TestTranslateStatsOverview:
    def test_basic_shape(self):
        stats = {
            "total_packets": 1000,
            "total_bytes": 500000,
            "unique_ips": 10,
            "total_sessions": 50,
            "duration": 60.0,
            "packets_per_second": 16.7,
            "protocols": {
                "TCP": {"packets": 800, "bytes": 400000},
                "DNS": {"packets": 200, "bytes": 100000},
            },
            "top_talkers": [{"ip": "10.0.0.1", "bytes": 100000}],
        }
        out = translate_stats_overview(stats)
        assert out["total_packets"] == 1000
        assert out["unique_ip_addresses"] == 10
        assert "top_protocols" in out
        assert len(out["top_protocols"]) <= 8

    def test_empty_stats(self):
        out = translate_stats_overview({})
        assert out == {}


class TestCapList:
    def test_caps_at_limit(self):
        assert len(cap_list(list(range(100)), 10)) == 10

    def test_none_returns_empty(self):
        assert cap_list(None) == []

    def test_short_list_unchanged(self):
        assert cap_list([1, 2, 3], 10) == [1, 2, 3]
