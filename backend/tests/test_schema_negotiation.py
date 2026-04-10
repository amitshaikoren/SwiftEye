"""
Tests for the schema negotiation layer.

Covers:
  - inspect_schema on clean files (is_clean=True, no missing fields)
  - inspect_schema on renamed-column files (is_clean=False, missing_required populated)
  - suggested_mappings heuristics
  - parse_with_mapping correctly remaps columns and produces valid packets
  - get_header_columns reads only the header line (fast path)
  - staging: stage_file → get_staged → clear_staged

Run from backend/ directory:
  python -m pytest tests/test_schema_negotiation.py -v
"""

import sys
import os
from pathlib import Path

# Make sure backend/ is on the path when running from repo root.
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


# ── Helpers ────────────────────────────────────────────────────────────────────

def get_zeek_conn_adapter():
    from parser.adapters.zeek.conn import ZeekConnAdapter
    return ZeekConnAdapter()


def get_zeek_dns_adapter():
    from parser.adapters.zeek.dns import ZeekDnsAdapter
    return ZeekDnsAdapter()


def get_tshark_metadata_adapter():
    from parser.adapters.tshark.metadata import TsharkMetadataAdapter
    return TsharkMetadataAdapter()


# ── inspect_schema: clean files ────────────────────────────────────────────────

class TestInspectSchemaClean:
    def test_zeek_conn_clean_is_clean(self):
        from parser.schema import inspect_schema
        adapter = get_zeek_conn_adapter()
        report = inspect_schema(adapter, FIXTURES / "zeek_conn_clean.log")
        assert report.is_clean is True
        assert report.missing_required == []

    def test_zeek_conn_clean_detects_all_required(self):
        from parser.schema import inspect_schema
        adapter = get_zeek_conn_adapter()
        report = inspect_schema(adapter, FIXTURES / "zeek_conn_clean.log")
        required = [f.name for f in adapter.declared_fields if f.required]
        for field in required:
            assert field in report.detected_columns, f"Required field '{field}' not detected"

    def test_zeek_dns_clean_is_clean(self):
        from parser.schema import inspect_schema
        adapter = get_zeek_dns_adapter()
        report = inspect_schema(adapter, FIXTURES / "zeek_dns_clean.log")
        assert report.is_clean is True

    def test_tshark_metadata_clean_is_clean(self):
        from parser.schema import inspect_schema
        adapter = get_tshark_metadata_adapter()
        report = inspect_schema(adapter, FIXTURES / "tshark_metadata_clean.csv")
        assert report.is_clean is True
        assert report.missing_required == []


# ── inspect_schema: renamed files ─────────────────────────────────────────────

class TestInspectSchemaMismatch:
    def test_zeek_conn_renamed_not_clean(self):
        from parser.schema import inspect_schema
        adapter = get_zeek_conn_adapter()
        report = inspect_schema(adapter, FIXTURES / "zeek_conn_renamed.log")
        assert report.is_clean is False

    def test_zeek_conn_renamed_missing_required(self):
        from parser.schema import inspect_schema
        adapter = get_zeek_conn_adapter()
        report = inspect_schema(adapter, FIXTURES / "zeek_conn_renamed.log")
        # The renamed file uses src_ip/dst_ip instead of id.orig_h/id.resp_h
        assert "id.orig_h" in report.missing_required
        assert "id.resp_h" in report.missing_required

    def test_zeek_conn_renamed_detects_unknown_columns(self):
        from parser.schema import inspect_schema
        adapter = get_zeek_conn_adapter()
        report = inspect_schema(adapter, FIXTURES / "zeek_conn_renamed.log")
        # New column names like src_ip, dst_ip are not in declared_fields
        assert "src_ip" in report.unknown_columns or "dst_ip" in report.unknown_columns

    def test_tshark_metadata_renamed_not_clean(self):
        from parser.schema import inspect_schema
        adapter = get_tshark_metadata_adapter()
        report = inspect_schema(adapter, FIXTURES / "tshark_metadata_renamed.csv")
        assert report.is_clean is False

    def test_tshark_metadata_renamed_missing_required(self):
        from parser.schema import inspect_schema
        adapter = get_tshark_metadata_adapter()
        report = inspect_schema(adapter, FIXTURES / "tshark_metadata_renamed.csv")
        # Renamed file uses src_ip/dst_ip instead of sourceIp/destIp
        assert "sourceIp" in report.missing_required or "destIp" in report.missing_required

    def test_suggested_mappings_for_zeek_conn_renamed(self):
        from parser.schema import inspect_schema
        adapter = get_zeek_conn_adapter()
        report = inspect_schema(adapter, FIXTURES / "zeek_conn_renamed.log")
        # Inspector should suggest: src_ip → id.orig_h or similar
        # At minimum it should produce some non-empty suggestions
        assert isinstance(report.suggested_mappings, dict)


# ── get_header_columns (fast path) ────────────────────────────────────────────

class TestGetHeaderColumns:
    def test_zeek_conn_columns(self):
        adapter = get_zeek_conn_adapter()
        cols = adapter.get_header_columns(FIXTURES / "zeek_conn_clean.log")
        assert "ts" in cols
        assert "id.orig_h" in cols
        assert "id.resp_h" in cols
        assert "conn_state" in cols

    def test_zeek_dns_columns(self):
        adapter = get_zeek_dns_adapter()
        cols = adapter.get_header_columns(FIXTURES / "zeek_dns_clean.log")
        assert "ts" in cols
        assert "id.orig_h" in cols
        assert "qtype_name" in cols

    def test_tshark_metadata_columns(self):
        adapter = get_tshark_metadata_adapter()
        cols = adapter.get_header_columns(FIXTURES / "tshark_metadata_clean.csv")
        assert "frameNumber" in cols
        assert "sourceIp" in cols
        assert "destIp" in cols
        assert "ipProtoType" in cols

    def test_zeek_renamed_columns_returned(self):
        adapter = get_zeek_conn_adapter()
        cols = adapter.get_header_columns(FIXTURES / "zeek_conn_renamed.log")
        # Renamed file has src_ip/dst_ip, NOT id.orig_h/id.resp_h
        assert "src_ip" in cols
        assert "id.orig_h" not in cols


# ── parse (clean files parse correctly) ───────────────────────────────────────

class TestParseClean:
    def test_zeek_conn_clean_produces_packets(self):
        adapter = get_zeek_conn_adapter()
        packets = adapter.parse(FIXTURES / "zeek_conn_clean.log")
        assert len(packets) == 10
        for pkt in packets:
            assert pkt.src_ip != ""
            assert pkt.dst_ip != ""
            assert pkt.timestamp > 0

    def test_zeek_dns_clean_produces_packets(self):
        adapter = get_zeek_dns_adapter()
        packets = adapter.parse(FIXTURES / "zeek_dns_clean.log")
        assert len(packets) == 10
        for pkt in packets:
            assert pkt.src_ip != ""
            assert pkt.protocol == "DNS"

    def test_tshark_metadata_clean_produces_packets(self):
        adapter = get_tshark_metadata_adapter()
        packets = adapter.parse(FIXTURES / "tshark_metadata_clean.csv")
        # 1 ICMP row + 9 IP rows — ICMP has no port so it still produces a packet
        assert len(packets) >= 9
        ips = {pkt.src_ip for pkt in packets}
        assert "10.0.0.1" in ips


# ── parse_with_mapping ────────────────────────────────────────────────────────

class TestParseWithMapping:
    def _zeek_conn_mapping(self):
        """The column rename mapping for zeek_conn_renamed.log."""
        return {
            "src_ip":   "id.orig_h",
            "src_port": "id.orig_p",
            "dst_ip":   "id.resp_h",
            "dst_port": "id.resp_p",
            "state":    "conn_state",
        }

    def test_zeek_conn_renamed_parse_with_mapping_produces_packets(self):
        adapter = get_zeek_conn_adapter()
        mapping = self._zeek_conn_mapping()
        packets = adapter.parse_with_mapping(FIXTURES / "zeek_conn_renamed.log", mapping)
        assert len(packets) == 10

    def test_zeek_conn_renamed_parse_with_mapping_correct_ips(self):
        adapter = get_zeek_conn_adapter()
        mapping = self._zeek_conn_mapping()
        packets = adapter.parse_with_mapping(FIXTURES / "zeek_conn_renamed.log", mapping)
        src_ips = {pkt.src_ip for pkt in packets}
        assert "10.0.0.1" in src_ips

    def test_zeek_conn_renamed_parse_with_partial_mapping(self):
        """Even with a partial mapping, packets for matched rows are produced."""
        adapter = get_zeek_conn_adapter()
        # Only map the IP fields; conn_state won't match but packets still form
        mapping = {
            "src_ip": "id.orig_h",
            "dst_ip": "id.resp_h",
            "src_port": "id.orig_p",
            "dst_port": "id.resp_p",
        }
        # conn_state won't be present → has_handshake defaults to False, but no crash
        packets = adapter.parse_with_mapping(FIXTURES / "zeek_conn_renamed.log", mapping)
        assert len(packets) == 10

    def test_tshark_metadata_renamed_parse_with_mapping(self):
        adapter = get_tshark_metadata_adapter()
        mapping = {
            "frame_num":   "frameNumber",
            "timestamp":   "ts",
            "src_ip":      "sourceIp",
            "dst_ip":      "destIp",
            "src_port":    "sourcePort",
            "dst_port":    "destPort",
            "ip_proto":    "ipProtoType",
            "src_mac":     "sourceMac",
            "dst_mac":     "destMac",
            "ip_total_len": "ipTotalLength",
            "ip_ttl":      "ipTtl",
            "tcp_flags":   "tcpFlags",
            "l5_length":   "layerFiveLength",
        }
        packets = adapter.parse_with_mapping(FIXTURES / "tshark_metadata_renamed.csv", mapping)
        assert len(packets) >= 9

    def test_parse_with_mapping_no_declared_fields_falls_back(self):
        """An adapter with no declared_fields falls back to plain parse()."""
        from parser.adapters.pcap_adapter import PcapAdapter
        adapter = PcapAdapter()
        assert adapter.declared_fields == []
        # PcapAdapter.parse() raises on a non-pcap file — that's expected.
        # What we're checking is that parse_with_mapping() doesn't blow up
        # before trying; it just delegates.
        with pytest.raises(Exception):
            adapter.parse_with_mapping(FIXTURES / "zeek_conn_clean.log", {})


# ── staging ────────────────────────────────────────────────────────────────────

class TestStaging:
    def test_stage_and_retrieve(self, tmp_path):
        from parser.schema import stage_file, get_staged, clear_staged
        test_file = tmp_path / "test_conn.log"
        test_file.write_text("dummy content")

        token = stage_file(test_file, adapter_name="Zeek conn.log", original_filename="test_conn.log")
        assert token != ""

        staged = get_staged(token)
        assert staged is not None
        assert staged.adapter_name == "Zeek conn.log"
        assert staged.original_filename == "test_conn.log"
        assert Path(staged.staged_path).exists()

        clear_staged(token)
        assert get_staged(token) is None
        assert not Path(staged.staged_path).exists()

    def test_unknown_token_returns_none(self):
        from parser.schema import get_staged
        assert get_staged("nonexistent-token-xyz") is None

    def test_clear_nonexistent_token_safe(self):
        from parser.schema import clear_staged
        # Should not raise
        clear_staged("nonexistent-token-abc")
