"""
Tests for the Parquet ingestion adapter.

Covers:
  - can_handle: magic bytes + extension detection
  - get_header_columns: reads schema without loading data
  - parse(): full round-trip → PacketRecord fields
  - parse_with_mapping(): schema negotiation remapping
  - graceful handling of rows with missing required fields
  - datetime timestamp columns are converted to Unix epoch float

Run from backend/ directory:
  python -m pytest tests/test_parquet_adapter.py -v
"""

import sys
import datetime
from pathlib import Path
from io import BytesIO

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

pyarrow = pytest.importorskip("pyarrow")
import pyarrow as pa
import pyarrow.parquet as pq


# ── Fixtures ───────────────────────────────────────────────────────────────────

def _make_parquet_bytes(table: pa.Table) -> bytes:
    buf = BytesIO()
    pq.write_table(table, buf)
    return buf.getvalue()


def _zeek_conn_table() -> pa.Table:
    """Minimal Parquet table with Zeek conn.log column shape."""
    return pa.table({
        "ts":           pa.array([1_700_000_000.0, 1_700_000_001.0]),
        "id.orig_h":    pa.array(["10.0.0.1", "192.168.1.5"]),
        "id.orig_p":    pa.array([54321, 12345]),
        "id.resp_h":    pa.array(["8.8.8.8", "203.0.113.10"]),
        "id.resp_p":    pa.array([443, 80]),
        "proto":        pa.array(["tcp", "tcp"]),
        "service":      pa.array(["ssl", "http"]),
        "duration":     pa.array([1.23, 0.45]),
        "orig_bytes":   pa.array([500, 200]),
        "resp_bytes":   pa.array([1500, 800]),
        "orig_ip_bytes":pa.array([560, 260]),
        "resp_ip_bytes":pa.array([1560, 860]),
        "orig_pkts":    pa.array([5, 3]),
        "resp_pkts":    pa.array([7, 4]),
        "conn_state":   pa.array(["SF", "SF"]),
        "uid":          pa.array(["Cxyz1", "Cabc2"]),
    })


def _renamed_table() -> pa.Table:
    """Same data but columns renamed — requires schema negotiation."""
    return pa.table({
        "timestamp":    pa.array([1_700_000_000.0]),
        "src_ip":       pa.array(["10.0.0.1"]),
        "src_port":     pa.array([54321]),
        "dst_ip":       pa.array(["8.8.8.8"]),
        "dst_port":     pa.array([443]),
        "transport":    pa.array(["tcp"]),
    })


def _datetime_ts_table() -> pa.Table:
    """Table where ts is a datetime column (pyarrow timestamp type)."""
    ts = datetime.datetime(2023, 11, 14, 22, 13, 20, tzinfo=datetime.timezone.utc)
    return pa.table({
        "ts":        pa.array([ts]),
        "id.orig_h": pa.array(["10.0.0.2"]),
        "id.orig_p": pa.array([9999]),
        "id.resp_h": pa.array(["1.2.3.4"]),
        "id.resp_p": pa.array([53]),
        "proto":     pa.array(["udp"]),
    })


# ── Adapter fixture ────────────────────────────────────────────────────────────

@pytest.fixture
def adapter():
    from workspaces.network.parser.adapters.parquet.adapter import ParquetAdapter
    return ParquetAdapter()


# ── can_handle ─────────────────────────────────────────────────────────────────

class TestCanHandle:
    def test_parquet_extension_detected(self, adapter, tmp_path):
        p = tmp_path / "flows.parquet"
        p.write_bytes(_make_parquet_bytes(_zeek_conn_table()))
        with open(p, "rb") as f:
            header = f.read(8192)
        assert adapter.can_handle(p, header)

    def test_magic_bytes_detected_no_extension(self, adapter, tmp_path):
        p = tmp_path / "flows.dat"
        p.write_bytes(_make_parquet_bytes(_zeek_conn_table()))
        with open(p, "rb") as f:
            header = f.read(8192)
        assert adapter.can_handle(p, header)

    def test_non_parquet_rejected(self, adapter, tmp_path):
        p = tmp_path / "flows.log"
        p.write_bytes(b"#fields\tts\tid.orig_h\n")
        assert not adapter.can_handle(p, b"#fields\tts\tid.orig_h\n")


# ── get_header_columns ─────────────────────────────────────────────────────────

class TestGetHeaderColumns:
    def test_returns_column_names(self, adapter, tmp_path):
        p = tmp_path / "conn.parquet"
        p.write_bytes(_make_parquet_bytes(_zeek_conn_table()))
        cols = adapter.get_header_columns(p)
        assert "ts" in cols
        assert "id.orig_h" in cols
        assert "id.resp_p" in cols

    def test_renamed_columns_returned_as_is(self, adapter, tmp_path):
        p = tmp_path / "renamed.parquet"
        p.write_bytes(_make_parquet_bytes(_renamed_table()))
        cols = adapter.get_header_columns(p)
        assert "src_ip" in cols
        assert "timestamp" in cols


# ── parse (full round-trip) ────────────────────────────────────────────────────

class TestParse:
    def test_returns_two_packets(self, adapter, tmp_path):
        p = tmp_path / "conn.parquet"
        p.write_bytes(_make_parquet_bytes(_zeek_conn_table()))
        pkts = adapter.parse(p)
        assert len(pkts) == 2

    def test_packet_fields_correct(self, adapter, tmp_path):
        p = tmp_path / "conn.parquet"
        p.write_bytes(_make_parquet_bytes(_zeek_conn_table()))
        pkts = adapter.parse(p)
        # Sorted by timestamp — first row is row 0
        pkt = pkts[0]
        assert pkt.src_ip == "10.0.0.1"
        assert pkt.dst_ip == "8.8.8.8"
        assert pkt.src_port == 54321
        assert pkt.dst_port == 443
        assert pkt.transport == "TCP"
        assert pkt.protocol == "TLS"
        assert pkt.ip_version == 4
        assert pkt.timestamp == pytest.approx(1_700_000_000.0)

    def test_byte_counts_populated(self, adapter, tmp_path):
        p = tmp_path / "conn.parquet"
        p.write_bytes(_make_parquet_bytes(_zeek_conn_table()))
        pkt = adapter.parse(p)[0]
        # orig_ip_bytes + resp_ip_bytes = 560 + 1560 = 2120
        assert pkt.orig_len == 2120

    def test_extra_fields_present(self, adapter, tmp_path):
        p = tmp_path / "conn.parquet"
        p.write_bytes(_make_parquet_bytes(_zeek_conn_table()))
        pkt = adapter.parse(p)[0]
        assert pkt.extra["source_type"] == "parquet"
        assert pkt.extra["orig_bytes"] == 500
        assert pkt.extra["resp_bytes"] == 1500
        assert pkt.extra["duration"] == pytest.approx(1.23)
        assert pkt.extra["has_handshake"] is True  # conn_state = SF

    def test_sorted_by_timestamp(self, adapter, tmp_path):
        p = tmp_path / "conn.parquet"
        p.write_bytes(_make_parquet_bytes(_zeek_conn_table()))
        pkts = adapter.parse(p)
        ts = [pkt.timestamp for pkt in pkts]
        assert ts == sorted(ts)

    def test_missing_required_fields_skipped(self, adapter, tmp_path):
        """Rows without src/dst IP should be silently dropped."""
        table = pa.table({
            "ts":        pa.array([1_700_000_000.0, 1_700_000_001.0]),
            "id.orig_h": pa.array(["", "10.0.0.1"]),
            "id.orig_p": pa.array([1234, 1234]),
            "id.resp_h": pa.array(["8.8.8.8", "8.8.8.8"]),
            "id.resp_p": pa.array([443, 443]),
            "proto":     pa.array(["tcp", "tcp"]),
        })
        p = tmp_path / "partial.parquet"
        p.write_bytes(_make_parquet_bytes(table))
        pkts = adapter.parse(p)
        assert len(pkts) == 1

    def test_datetime_timestamp_converted(self, adapter, tmp_path):
        """datetime ts columns are converted to Unix epoch float."""
        p = tmp_path / "dt.parquet"
        p.write_bytes(_make_parquet_bytes(_datetime_ts_table()))
        pkts = adapter.parse(p)
        assert len(pkts) == 1
        # 2023-11-14 22:13:20 UTC = 1700000000
        assert pkts[0].timestamp == pytest.approx(1_700_000_000.0, abs=1.0)

    def test_ipv6_detected(self, adapter, tmp_path):
        table = pa.table({
            "ts":        pa.array([1_700_000_000.0]),
            "id.orig_h": pa.array(["2001:db8::1"]),
            "id.orig_p": pa.array([12345]),
            "id.resp_h": pa.array(["2001:db8::2"]),
            "id.resp_p": pa.array([443]),
            "proto":     pa.array(["tcp"]),
        })
        p = tmp_path / "ipv6.parquet"
        p.write_bytes(_make_parquet_bytes(table))
        pkts = adapter.parse(p)
        assert pkts[0].ip_version == 6


# ── parse_with_mapping (schema negotiation) ────────────────────────────────────

class TestParseWithMapping:
    def test_remapped_columns_produce_valid_packets(self, adapter, tmp_path):
        p = tmp_path / "renamed.parquet"
        p.write_bytes(_make_parquet_bytes(_renamed_table()))
        mapping = {
            "timestamp": "ts",
            "src_ip":    "id.orig_h",
            "src_port":  "id.orig_p",
            "dst_ip":    "id.resp_h",
            "dst_port":  "id.resp_p",
            "transport": "proto",
        }
        pkts = adapter.parse_with_mapping(p, mapping)
        assert len(pkts) == 1
        assert pkts[0].src_ip == "10.0.0.1"
        assert pkts[0].dst_port == 443
        assert pkts[0].transport == "TCP"
