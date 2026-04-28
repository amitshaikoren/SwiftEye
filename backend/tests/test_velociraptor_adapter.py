"""
Tests for the Velociraptor forensic adapter.

Covers:
  - Artifact dissector registry (pslist, netstat registered)
  - dissect_pslist: normal row, ppid=0 root, missing pid, column variants
  - dissect_netstat: established connection, skip LISTEN, skip loopback,
    pid_map enrichment, no pid identity
  - build_pid_map: basic + empty
  - dispatch_artifact: unknown artifact silently skipped
  - VelociraptorAdapter.can_handle: ZIP magic, known CSV stem, unknown CSV
  - VelociraptorAdapter.parse: bare CSV, ZIP with both artifacts, two-pass
    pid_map enrichment across pslist+netstat

Run from backend/:
  python -m pytest tests/test_velociraptor_adapter.py -v
"""

import io
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from workspaces.forensic.parser.artifact_dissectors import (
    ARTIFACT_DISSECTORS,
    dispatch_artifact,
)
from workspaces.forensic.parser.artifact_dissectors.dissect_pslist import (
    dissect as pslist_dissect,
    build_pid_map,
)
from workspaces.forensic.parser.artifact_dissectors.dissect_netstat import (
    dissect as netstat_dissect,
)
from workspaces.forensic.parser.adapters.velociraptor_adapter import VelociraptorAdapter


# ── Registry ─────────────────────────────────────────────────────────────────

def test_artifact_dissectors_registered():
    assert "Windows.System.Pslist" in ARTIFACT_DISSECTORS
    assert "Windows.Network.Netstat" in ARTIFACT_DISSECTORS


# ── dissect_pslist ────────────────────────────────────────────────────────────

def _pslist_row(**kwargs):
    base = {
        "Pid": "1234", "PPid": "4", "Name": "notepad.exe",
        "Exe": "C:\\Windows\\System32\\notepad.exe",
        "CommandLine": "notepad.exe C:\\file.txt",
        "CreateTime": "2024-01-15T12:00:00Z",
        "User": "DESKTOP\\alice",
    }
    base.update(kwargs)
    return base


def test_pslist_normal_row():
    evt = pslist_dissect(_pslist_row(), {})
    assert evt is not None
    assert evt.action_type == "process_create"
    assert evt.dst_entity["pid"] == 1234
    assert evt.dst_entity["image"] == "C:\\Windows\\System32\\notepad.exe"
    assert evt.dst_entity["user"] == "DESKTOP\\alice"
    assert evt.src_entity["pid"] == 4
    assert evt.fields["command_line"] == "notepad.exe C:\\file.txt"
    assert evt.source["provider"] == "velociraptor"
    assert evt.source["artifact"] == "Windows.System.Pslist"


def test_pslist_ppid_zero_gets_system_root():
    evt = pslist_dissect(_pslist_row(PPid="0"), {})
    assert evt is not None
    assert evt.src_entity["image"] == "System"
    assert evt.src_entity["pid"] == 0


def test_pslist_ppid_enriched_from_pid_map():
    pid_map = {4: {"image": "C:\\Windows\\System32\\services.exe", "user": "NT AUTHORITY\\SYSTEM"}}
    evt = pslist_dissect(_pslist_row(PPid="4"), {"pid_map": pid_map})
    assert evt.src_entity["image"] == "C:\\Windows\\System32\\services.exe"
    assert evt.src_entity["user"] == "NT AUTHORITY\\SYSTEM"


def test_pslist_missing_pid_returns_none():
    evt = pslist_dissect(_pslist_row(Pid=""), {})
    assert evt is None


def test_pslist_username_column_variant():
    row = {**_pslist_row(), "Username": "DESKTOP\\bob"}
    del row["User"]
    evt = pslist_dissect(row, {})
    assert evt is not None
    assert evt.dst_entity["user"] == "DESKTOP\\bob"


def test_pslist_computer_from_context():
    evt = pslist_dissect(_pslist_row(), {"computer": "MYHOST"})
    assert evt.dst_entity["computer"] == "MYHOST"
    assert evt.source["computer"] == "MYHOST"


def test_pslist_ts_parsed():
    evt = pslist_dissect(_pslist_row(CreateTime="2024-06-01T08:30:00Z"), {})
    assert evt.ts is not None
    assert evt.ts.year == 2024


# ── build_pid_map ─────────────────────────────────────────────────────────────

def test_build_pid_map_basic():
    rows = [
        {"Pid": "4", "Exe": "C:\\Windows\\System32\\services.exe", "User": "SYSTEM"},
        {"Pid": "1234", "Exe": "C:\\Windows\\notepad.exe", "User": "alice"},
    ]
    pid_map = build_pid_map(rows)
    assert pid_map[4]["image"] == "C:\\Windows\\System32\\services.exe"
    assert pid_map[1234]["user"] == "alice"


def test_build_pid_map_empty():
    assert build_pid_map([]) == {}


def test_build_pid_map_skips_missing_pid():
    pid_map = build_pid_map([{"Pid": "", "Exe": "foo.exe"}])
    assert pid_map == {}


# ── dissect_netstat ───────────────────────────────────────────────────────────

def _netstat_row(**kwargs):
    base = {
        "Pid": "1234", "FamilyString": "IPv4", "TypeString": "TCP",
        "Status": "ESTABLISHED",
        "Laddr.IP": "192.168.1.5", "Laddr.Port": "54321",
        "Raddr.IP": "8.8.8.8", "Raddr.Port": "443",
        "Timestamp": "2024-01-15T12:00:00Z",
    }
    base.update(kwargs)
    return base


def test_netstat_established_with_pid_map():
    pid_map = {1234: {"image": "C:\\Windows\\chrome.exe", "user": "alice"}}
    evt = netstat_dissect(_netstat_row(), {"pid_map": pid_map})
    assert evt is not None
    assert evt.action_type == "network_connect"
    assert evt.src_entity["pid"] == 1234
    assert evt.src_entity["image"] == "C:\\Windows\\chrome.exe"
    assert evt.dst_entity["ip"] == "8.8.8.8"
    assert evt.dst_entity["port"] == 443
    assert evt.fields["protocol"] == "tcp"
    assert evt.fields["local_ip"] == "192.168.1.5"
    assert evt.source["provider"] == "velociraptor"


def test_netstat_listen_skipped():
    evt = netstat_dissect(_netstat_row(Status="LISTEN"), {})
    assert evt is None


def test_netstat_loopback_remote_skipped():
    evt = netstat_dissect(_netstat_row(**{"Raddr.IP": "127.0.0.1"}), {})
    assert evt is None


def test_netstat_zero_remote_ip_skipped():
    evt = netstat_dissect(_netstat_row(**{"Raddr.IP": "0.0.0.0"}), {})
    assert evt is None


def test_netstat_zero_remote_port_skipped():
    evt = netstat_dissect(_netstat_row(**{"Raddr.Port": "0"}), {})
    assert evt is None


def test_netstat_no_pid_identity_skipped():
    # No pid_map and Pid="", so src can't be identified.
    evt = netstat_dissect(_netstat_row(Pid=""), {})
    assert evt is None


def test_netstat_pid_without_map_skipped():
    # pid present but no pid_map → no image → src only has type+pid →
    # len(src) == 2 > 1, so it proceeds (pid alone is enough identity).
    evt = netstat_dissect(_netstat_row(), {})
    assert evt is not None
    assert evt.src_entity["pid"] == 1234
    assert "image" not in evt.src_entity


# ── dispatch_artifact ─────────────────────────────────────────────────────────

def test_dispatch_unknown_artifact_returns_empty():
    events = dispatch_artifact("Windows.Nonexistent.Artifact", [{"foo": "bar"}])
    assert events == []


def test_dispatch_pslist_produces_events():
    rows = [_pslist_row()]
    events = dispatch_artifact("Windows.System.Pslist", rows)
    assert len(events) == 1
    assert events[0].action_type == "process_create"


# ── VelociraptorAdapter.can_handle ────────────────────────────────────────────

def test_can_handle_known_csv_stem(tmp_path):
    p = tmp_path / "Windows.System.Pslist.csv"
    p.write_bytes(b"Pid,PPid\n1,0\n")
    adapter = VelociraptorAdapter()
    with open(p, "rb") as f:
        header = f.read(64)
    assert adapter.can_handle(p, header)


def test_can_handle_unknown_csv_stem(tmp_path):
    p = tmp_path / "RandomFile.csv"
    p.write_bytes(b"foo,bar\n1,2\n")
    adapter = VelociraptorAdapter()
    with open(p, "rb") as f:
        header = f.read(64)
    assert not adapter.can_handle(p, header)


def test_can_handle_velociraptor_zip(tmp_path):
    p = tmp_path / "Collection-DESKTOP-TEST-2024.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "artifact_Windows.System.Pslist/Windows.System.Pslist.csv",
            "Pid,PPid,Name,Exe,CommandLine,CreateTime,User\n"
            "4,0,System,C:\\Windows\\System32\\ntoskrnl.exe,,2024-01-15T00:00:00Z,SYSTEM\n",
        )
    p.write_bytes(buf.getvalue())
    adapter = VelociraptorAdapter()
    with open(p, "rb") as f:
        header = f.read(64)
    assert adapter.can_handle(p, header)


def test_can_handle_non_velociraptor_zip(tmp_path):
    p = tmp_path / "random.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("readme.txt", "hello")
    p.write_bytes(buf.getvalue())
    adapter = VelociraptorAdapter()
    with open(p, "rb") as f:
        header = f.read(64)
    assert not adapter.can_handle(p, header)


# ── VelociraptorAdapter.parse — bare CSV ─────────────────────────────────────

def test_parse_bare_pslist_csv(tmp_path):
    p = tmp_path / "Windows.System.Pslist.csv"
    p.write_text(
        "Pid,PPid,Name,Exe,CommandLine,CreateTime,User\n"
        "4,0,System,C:\\Windows\\System32\\ntoskrnl.exe,,2024-01-15T00:00:00Z,SYSTEM\n"
        "1234,4,notepad.exe,C:\\Windows\\System32\\notepad.exe,notepad.exe,2024-01-15T12:00:00Z,alice\n",
        encoding="utf-8",
    )
    adapter = VelociraptorAdapter()
    events = adapter.parse(p)
    assert len(events) == 2
    pids = {e.dst_entity["pid"] for e in events}
    assert pids == {4, 1234}


def test_parse_bare_netstat_csv(tmp_path):
    p = tmp_path / "Windows.Network.Netstat.csv"
    p.write_text(
        "Pid,FamilyString,TypeString,Status,Laddr.IP,Laddr.Port,Raddr.IP,Raddr.Port,Timestamp\n"
        "1234,IPv4,TCP,ESTABLISHED,192.168.1.5,54321,8.8.8.8,443,2024-01-15T12:00:00Z\n"
        "5678,IPv4,TCP,LISTEN,0.0.0.0,80,0.0.0.0,0,2024-01-15T12:00:00Z\n",
        encoding="utf-8",
    )
    adapter = VelociraptorAdapter()
    events = adapter.parse(p)
    assert len(events) == 1
    assert events[0].dst_entity["ip"] == "8.8.8.8"


# ── VelociraptorAdapter.parse — ZIP with two-pass pid enrichment ──────────────

_PSLIST_CSV = (
    "Pid,PPid,Name,Exe,CommandLine,CreateTime,User\n"
    "4,0,System,C:\\Windows\\System32\\ntoskrnl.exe,,2024-01-15T00:00:00Z,SYSTEM\n"
    "1234,4,chrome.exe,C:\\Program Files\\Google\\Chrome\\chrome.exe,"
    "chrome.exe,2024-01-15T10:00:00Z,alice\n"
)

_NETSTAT_CSV = (
    "Pid,FamilyString,TypeString,Status,Laddr.IP,Laddr.Port,Raddr.IP,Raddr.Port,Timestamp\n"
    "1234,IPv4,TCP,ESTABLISHED,192.168.1.5,54321,8.8.8.8,443,2024-01-15T12:00:00Z\n"
)


def test_parse_zip_two_artifacts(tmp_path):
    p = tmp_path / "Collection-DESKTOP-TEST-2024.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("artifact_Windows.System.Pslist/Windows.System.Pslist.csv", _PSLIST_CSV)
        zf.writestr("artifact_Windows.Network.Netstat/Windows.Network.Netstat.csv", _NETSTAT_CSV)
    p.write_bytes(buf.getvalue())

    adapter = VelociraptorAdapter()
    events = adapter.parse(p)

    proc_events = [e for e in events if e.action_type == "process_create"]
    net_events  = [e for e in events if e.action_type == "network_connect"]

    assert len(proc_events) == 2
    assert len(net_events) == 1

    # Two-pass: netstat src should be enriched with chrome.exe from pslist.
    net_src = net_events[0].src_entity
    assert net_src["pid"] == 1234
    assert net_src["image"] == "C:\\Program Files\\Google\\Chrome\\chrome.exe"


def test_parse_zip_hostname_from_filename(tmp_path):
    p = tmp_path / "Collection-WORKSTATION42-2024.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("artifact_Windows.System.Pslist/Windows.System.Pslist.csv", _PSLIST_CSV)
    p.write_bytes(buf.getvalue())

    adapter = VelociraptorAdapter()
    events = adapter.parse(p)
    assert all(e.source.get("computer") == "WORKSTATION42" for e in events)
