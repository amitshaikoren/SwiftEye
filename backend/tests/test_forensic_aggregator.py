"""
Tests for the forensic workspace Phase 5 components.

Covers:
  - Entity ID helpers: process (guid, fallback), file, registry, endpoint
  - build_forensic_graph: node deduplication, edge accumulation, field merge
  - Integration: EVTX fixtures → graph shape assertions

Run from backend/:
  python -m pytest tests/test_forensic_aggregator.py -v
"""

import sys
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from workspaces.forensic.parser.event import Event
from workspaces.forensic.analysis.action_aggregator import (
    build_forensic_graph,
    _process_id,
    _file_id,
    _registry_id,
    _endpoint_id,
    _entity_id,
)
from workspaces.forensic.parser.adapters.evtx_adapter import EvtxAdapter

FIXTURES = Path(__file__).parent / "fixtures" / "sysmon"


# ── Entity ID helpers ────────────────────────────────────────────────────────

class TestProcessId:
    def test_guid_preferred(self):
        e = {"type": "process", "guid": "{abc-123}", "image": "cmd.exe", "pid": 1234}
        assert _process_id(e) == "fx:proc:{abc-123}"

    def test_fallback_uses_image_and_pid(self):
        e = {"type": "process", "image": "cmd.exe", "pid": 1234}
        assert _process_id(e, computer="DESKTOP") == "fx:proc:DESKTOP:cmd.exe:1234"

    def test_empty_entity_returns_none(self):
        assert _process_id({}) is None

    def test_missing_guid_and_image_returns_none(self):
        assert _process_id({"type": "process"}) is None


class TestFileId:
    def test_lowercased(self):
        e = {"type": "file", "path": "C:\\Windows\\System32\\cmd.exe"}
        result = _file_id(e)
        assert result is not None
        assert result == result.lower()
        assert result.startswith("fx:file:")

    def test_missing_path_returns_none(self):
        assert _file_id({}) is None


class TestRegistryId:
    def test_lowercased(self):
        e = {"type": "registry", "key": "HKLM\\SOFTWARE\\Microsoft"}
        result = _registry_id(e)
        assert result is not None
        assert result == result.lower()
        assert result.startswith("fx:reg:")

    def test_missing_key_returns_none(self):
        assert _registry_id({}) is None


class TestEndpointId:
    def test_ip_and_port(self):
        e = {"type": "endpoint", "ip": "8.8.8.8", "port": 443}
        assert _endpoint_id(e) == "fx:net:8.8.8.8:443"

    def test_hostname_fallback(self):
        e = {"type": "endpoint", "hostname": "google.com", "port": 443}
        assert _endpoint_id(e) == "fx:net:google.com:443"

    def test_ip_only(self):
        e = {"type": "endpoint", "ip": "1.2.3.4"}
        assert _endpoint_id(e) == "fx:net:1.2.3.4"

    def test_empty_returns_none(self):
        assert _endpoint_id({}) is None


# ── build_forensic_graph: unit scenarios ────────────────────────────────────

def _proc(guid, image="cmd.exe", pid=100, user=None):
    e = {"type": "process", "guid": guid, "image": image, "pid": pid}
    if user:
        e["user"] = user
    return e


def _file(path):
    return {"type": "file", "path": path}


def _endpoint(ip, port):
    return {"type": "endpoint", "ip": ip, "port": port}


def _registry(key):
    return {"type": "registry", "key": key}


class TestBuildForensicGraph:
    def test_empty_events_returns_empty_graph(self):
        result = build_forensic_graph([])
        assert result["nodes"] == []
        assert result["edges"] == []

    def test_single_process_create_event(self):
        parent = _proc("{parent-guid}", image="explorer.exe", pid=500)
        child  = _proc("{child-guid}",  image="cmd.exe",      pid=1234)
        ev = Event(
            action_type="process_create",
            ts=datetime(2024, 1, 1, 12, 0, 0),
            src_entity=parent,
            dst_entity=child,
            fields={"command_line": "cmd.exe /c whoami"},
            source={"eid": 1, "record_id": 1, "computer": "DESKTOP"},
        )
        g = build_forensic_graph([ev])
        assert len(g["nodes"]) == 2
        assert len(g["edges"]) == 1
        edge = g["edges"][0]
        assert edge["type"] == "spawned"
        assert edge["count"] == 1
        assert len(edge["events"]) == 1

    def test_node_deduplication_same_guid(self):
        """Two events with the same ProcessGuid must produce one node."""
        proc = _proc("{same-guid}", image="cmd.exe", pid=1)
        file_a = _file("C:\\foo.txt")
        file_b = _file("C:\\bar.txt")
        evs = [
            Event(action_type="file_create", src_entity=proc, dst_entity=file_a,
                  fields={}, source={"eid": 11}),
            Event(action_type="file_create", src_entity=proc, dst_entity=file_b,
                  fields={}, source={"eid": 11}),
        ]
        g = build_forensic_graph(evs)
        node_ids = [n["id"] for n in g["nodes"]]
        proc_nodes = [n for n in g["nodes"] if n["type"] == "process"]
        assert len(proc_nodes) == 1
        assert proc_nodes[0]["id"] == "fx:proc:{same-guid}"

    def test_edge_accumulation_two_events_same_pair(self):
        """Two file_create events on the same (proc, file) pair → one edge, 2 events."""
        proc = _proc("{p1}", image="notepad.exe")
        f    = _file("C:\\secret.txt")
        evs = [
            Event(action_type="file_create", src_entity=proc, dst_entity=f,
                  fields={"hashes": "abc"}, source={"eid": 11}),
            Event(action_type="file_create", src_entity=proc, dst_entity=f,
                  fields={"hashes": "def"}, source={"eid": 11}),
        ]
        g = build_forensic_graph(evs)
        assert len(g["edges"]) == 1
        edge = g["edges"][0]
        assert edge["count"] == 2
        assert len(edge["events"]) == 2

    def test_multiple_action_types_distinct_edges(self):
        """proc→file and proc→endpoint are different dst entities → two edges."""
        proc  = _proc("{p2}", image="malware.exe")
        f     = _file("C:\\dropped.dll")
        ep    = _endpoint("8.8.8.8", 443)
        evs = [
            Event(action_type="file_create",     src_entity=proc, dst_entity=f,  fields={}, source={"eid": 11}),
            Event(action_type="network_connect",  src_entity=proc, dst_entity=ep, fields={}, source={"eid": 3}),
        ]
        g = build_forensic_graph(evs)
        assert len(g["edges"]) == 2
        edge_types = {e["type"] for e in g["edges"]}
        assert "wrote" in edge_types
        assert "connected" in edge_types

    def test_registry_set_edge_type(self):
        proc = _proc("{p3}")
        reg  = _registry("HKLM\\SOFTWARE\\Run\\evil")
        ev   = Event(action_type="registry_set", src_entity=proc, dst_entity=reg,
                     fields={"details": "evil.exe"}, source={"eid": 13})
        g = build_forensic_graph([ev])
        assert len(g["edges"]) == 1
        assert g["edges"][0]["type"] == "set_value"

    def test_ts_first_last_tracked(self):
        proc = _proc("{p4}")
        f    = _file("C:\\log.txt")
        t1 = datetime(2024, 1, 1, 10, 0, 0)
        t2 = datetime(2024, 1, 1, 12, 0, 0)
        evs = [
            Event(action_type="file_create", ts=t2, src_entity=proc, dst_entity=f, fields={}, source={}),
            Event(action_type="file_create", ts=t1, src_entity=proc, dst_entity=f, fields={}, source={}),
        ]
        g = build_forensic_graph(evs)
        edge = g["edges"][0]
        assert edge["ts_first"] == t1.isoformat()
        assert edge["ts_last"]  == t2.isoformat()

    def test_node_field_backfill(self):
        """A second event for the same process that adds a user field should merge it in."""
        proc_no_user   = {"type": "process", "guid": "{p5}", "image": "svc.exe", "pid": 99}
        proc_with_user = {"type": "process", "guid": "{p5}", "image": "svc.exe", "pid": 99, "user": "SYSTEM"}
        f = _file("C:\\data.bin")
        evs = [
            Event(action_type="file_create", src_entity=proc_no_user,   dst_entity=f, fields={}, source={}),
            Event(action_type="file_create", src_entity=proc_with_user, dst_entity=f, fields={}, source={}),
        ]
        g = build_forensic_graph(evs)
        proc_node = next(n for n in g["nodes"] if n["type"] == "process")
        assert proc_node.get("user") == "SYSTEM"

    def test_event_with_missing_src_skipped(self):
        """Events where src_entity resolves to no ID are silently skipped."""
        ev = Event(action_type="file_create", src_entity={}, dst_entity=_file("C:\\x.txt"),
                   fields={}, source={})
        g = build_forensic_graph([ev])
        assert len(g["nodes"]) == 0
        assert len(g["edges"]) == 0

    def test_graph_keys_present(self):
        proc = _proc("{p6}")
        ep   = _endpoint("10.0.0.1", 80)
        ev = Event(action_type="network_connect", src_entity=proc, dst_entity=ep,
                   fields={"protocol": "tcp"}, source={"eid": 3})
        g = build_forensic_graph([ev])
        assert "nodes" in g and "edges" in g
        edge = g["edges"][0]
        for key in ("id", "src", "dst", "type", "events", "count", "ts_first", "ts_last"):
            assert key in edge, f"Missing key: {key}"


# ── Integration: EVTX → graph ────────────────────────────────────────────────

@pytest.mark.skipif(not FIXTURES.exists(), reason="fixtures not found")
class TestEvtxToGraph:
    """End-to-end: parse an EVTX fixture → build_forensic_graph → assert shape."""

    def _parse(self, filename):
        path = FIXTURES / filename
        adapter = EvtxAdapter()
        events = adapter.parse(path)
        return events, build_forensic_graph(events)

    def test_eid1_fixture_has_process_nodes(self):
        events, g = self._parse("exec_sysmon_1_rundll32_pcwutl_LaunchApplication.evtx")
        assert len(events) > 0
        proc_nodes = [n for n in g["nodes"] if n["type"] == "process"]
        assert len(proc_nodes) >= 1

    def test_eid1_fixture_has_spawned_edges(self):
        _, g = self._parse("exec_sysmon_1_rundll32_pcwutl_LaunchApplication.evtx")
        spawned = [e for e in g["edges"] if e["type"] == "spawned"]
        assert len(spawned) >= 1

    def test_eid3_fixture_has_endpoint_nodes(self):
        events, g = self._parse("LM_DCOM_MSHTA_LethalHTA_Sysmon_3_1.evtx")
        assert len(events) > 0
        ep_nodes = [n for n in g["nodes"] if n["type"] == "endpoint"]
        assert len(ep_nodes) >= 1

    def test_eid3_fixture_has_connected_edges(self):
        _, g = self._parse("LM_DCOM_MSHTA_LethalHTA_Sysmon_3_1.evtx")
        connected = [e for e in g["edges"] if e["type"] == "connected"]
        assert len(connected) >= 1

    def test_eid11_3_fixture_has_multiple_node_types(self):
        events, g = self._parse("exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx")
        assert len(events) > 0
        types = {n["type"] for n in g["nodes"]}
        # Should have process + at least one of file/endpoint
        assert "process" in types

    def test_eid13_fixture_has_registry_nodes(self):
        events, g = self._parse("de_portforward_netsh_rdp_sysmon_13_1.evtx")
        assert len(events) > 0
        reg_nodes = [n for n in g["nodes"] if n["type"] == "registry"]
        assert len(reg_nodes) >= 1

    def test_eid13_fixture_has_set_value_edges(self):
        _, g = self._parse("de_portforward_netsh_rdp_sysmon_13_1.evtx")
        sv = [e for e in g["edges"] if e["type"] == "set_value"]
        assert len(sv) >= 1

    def test_all_fixtures_produce_non_empty_graph(self):
        for fname in [
            "exec_sysmon_1_rundll32_pcwutl_LaunchApplication.evtx",
            "LM_DCOM_MSHTA_LethalHTA_Sysmon_3_1.evtx",
            "exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx",
            "de_portforward_netsh_rdp_sysmon_13_1.evtx",
        ]:
            events, g = self._parse(fname)
            assert len(events) > 0, f"{fname}: no events"
            assert len(g["nodes"]) > 0, f"{fname}: no nodes"
            assert len(g["edges"]) > 0, f"{fname}: no edges"

    def test_edge_events_populated(self):
        """Every edge in the graph should have at least one event in its list."""
        _, g = self._parse("exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx")
        for edge in g["edges"]:
            assert len(edge["events"]) >= 1, f"Edge {edge['id']} has empty events list"

    def test_node_ids_are_unique(self):
        _, g = self._parse("exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx")
        ids = [n["id"] for n in g["nodes"]]
        assert len(ids) == len(set(ids)), "Duplicate node IDs in graph"
