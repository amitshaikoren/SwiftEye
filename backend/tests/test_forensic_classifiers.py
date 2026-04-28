"""
Tests for forensic workspace classifier plugins (Phase 8).

Covers:
  - lolbins.py: lookup_lolbin — known binaries, unknown binaries, case-insensitive
  - lolbin_classifier: process nodes flagged, non-process nodes skipped
  - binary_type: path/extension classification rules
  - registry_categories.py: lookup_registry_category — known prefixes, hive stripping
  - registry_key_category: registry nodes classified, process nodes skipped

Run from backend/:
  python -m pytest tests/test_forensic_classifiers.py -v
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from workspaces.forensic.plugins.classifiers.lolbins import lookup_lolbin
from workspaces.forensic.plugins.classifiers.registry_categories import lookup_registry_category
from workspaces.forensic.plugins import ForensicAnalysisContext
from workspaces.forensic.plugins.classifiers.lolbin_classifier import LOLbinClassifier
from workspaces.forensic.plugins.classifiers.binary_type import BinaryTypeClassifier
from workspaces.forensic.plugins.classifiers.registry_key_category import RegistryKeyCategoryClassifier


# ── Helpers ──────────────────────────────────────────────────────────────────

def _ctx(nodes):
    return ForensicAnalysisContext(events=[], nodes=nodes, edges=[])

def _proc(node_id, image):
    return {"id": node_id, "type": "process", "image": image}

def _reg(node_id, key):
    return {"id": node_id, "type": "registry", "key": key}

def _file(node_id, path="C:\\Windows\\Temp\\doc.txt"):
    return {"id": node_id, "type": "file", "path": path}


# ── lolbins.py ───────────────────────────────────────────────────────────────

def test_lookup_lolbin_known():
    entry = lookup_lolbin("powershell.exe")
    assert entry is not None
    assert entry["category"] == "Scripting host"

def test_lookup_lolbin_case_insensitive():
    assert lookup_lolbin("PowerShell.EXE") == lookup_lolbin("powershell.exe")

def test_lookup_lolbin_unknown_returns_none():
    assert lookup_lolbin("notepad.exe") is None
    assert lookup_lolbin("chrome.exe") is None

def test_lookup_lolbin_certutil():
    entry = lookup_lolbin("certutil.exe")
    assert entry is not None
    assert entry["category"] == "Download tool"


# ── LOLbinClassifier ─────────────────────────────────────────────────────────

def test_lolbin_classifier_flags_powershell():
    plugin = LOLbinClassifier()
    nodes = [_proc("p1", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")]
    results = plugin.analyze_global(_ctx(nodes))
    assert "p1" in results
    assert results["p1"]["category"] == "Scripting host"
    assert "_display" in results["p1"]

def test_lolbin_classifier_skips_unknown_binary():
    plugin = LOLbinClassifier()
    nodes = [_proc("p2", r"C:\Users\user\Downloads\legitimate_app.exe")]
    results = plugin.analyze_global(_ctx(nodes))
    assert "p2" not in results

def test_lolbin_classifier_skips_non_process_nodes():
    plugin = LOLbinClassifier()
    nodes = [_reg("r1", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\evil")]
    results = plugin.analyze_global(_ctx(nodes))
    assert "r1" not in results

def test_lolbin_classifier_empty_image():
    plugin = LOLbinClassifier()
    nodes = [_proc("p3", "")]
    results = plugin.analyze_global(_ctx(nodes))
    assert "p3" not in results


# ── BinaryTypeClassifier ─────────────────────────────────────────────────────

def test_binary_type_system32():
    plugin = BinaryTypeClassifier()
    nodes = [_proc("p1", r"C:\Windows\System32\svchost.exe")]
    results = plugin.analyze_global(_ctx(nodes))
    assert "p1" in results
    assert results["p1"]["type"] == "System process"

def test_binary_type_powershell_script():
    plugin = BinaryTypeClassifier()
    nodes = [_proc("p2", r"C:\Users\user\script.ps1")]
    results = plugin.analyze_global(_ctx(nodes))
    assert "p2" in results
    assert results["p2"]["type"] == "PowerShell script"

def test_binary_type_temp_directory():
    plugin = BinaryTypeClassifier()
    nodes = [_proc("p3", r"C:\Temp\malware.exe")]
    results = plugin.analyze_global(_ctx(nodes))
    assert "p3" in results
    assert results["p3"]["type"] == "Temp directory"

def test_binary_type_skips_non_process():
    plugin = BinaryTypeClassifier()
    nodes = [_file("f1")]
    results = plugin.analyze_global(_ctx(nodes))
    assert "f1" not in results


# ── registry_categories.py ───────────────────────────────────────────────────

def test_registry_category_run_key():
    entry = lookup_registry_category(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\myapp")
    assert entry is not None
    assert entry["category"] == "Autostart"

def test_registry_category_service():
    entry = lookup_registry_category(r"HKLM\System\CurrentControlSet\Services\evilsvc")
    assert entry is not None
    assert entry["category"] == "Service"

def test_registry_category_hive_stripped():
    full  = lookup_registry_category(r"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\svc")
    short = lookup_registry_category(r"HKLM\System\CurrentControlSet\Services\svc")
    assert full is not None
    assert full["category"] == short["category"]

def test_registry_category_unknown_returns_none():
    assert lookup_registry_category(r"HKCU\Foo\Bar\Unknown") is None


# ── RegistryKeyCategoryClassifier ────────────────────────────────────────────

def test_registry_key_category_classifies_run_key():
    plugin = RegistryKeyCategoryClassifier()
    nodes = [_reg("r1", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\payload")]
    results = plugin.analyze_global(_ctx(nodes))
    assert "r1" in results
    assert results["r1"]["category"] == "Autostart"

def test_registry_key_category_skips_process_nodes():
    plugin = RegistryKeyCategoryClassifier()
    nodes = [_proc("p1", r"C:\Windows\System32\cmd.exe")]
    results = plugin.analyze_global(_ctx(nodes))
    assert "p1" not in results

def test_registry_key_category_skips_unknown_key():
    plugin = RegistryKeyCategoryClassifier()
    nodes = [_reg("r2", r"HKCU\Foo\Bar\Unknown")]
    results = plugin.analyze_global(_ctx(nodes))
    assert "r2" not in results
