"""
Discovery smoke tests for SwiftEye auto-discovery seams.

These are existence/import tests — they catch "an import broke everything"
regressions before they reach production. They do NOT test behavior.

Discovery surfaces covered:
  - data/protocol_fields/      pkgutil auto-discovery at import time
  - parser/adapters/           @register_adapter decorator on import
  - research/                  manual register_chart (mirrors server.py)
  - plugins/alerts/            manual register_detector (mirrors server.py)
  - plugins/insights/          manual register_plugin (mirrors server.py)
  - plugins/analyses/          manual register_analysis (mirrors server.py)
  - frontend/session_sections/ Vite import.meta.glob — existence check only

To simulate a regression: comment out one import in a module's __init__.py
and confirm the relevant test fails before restoring it.

Run: pytest backend/tests/test_discovery_smoke.py -v
"""
import importlib
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── protocol_fields ──────────────────────────────────────────────────────────

def test_protocol_fields_registry_populated():
    """pkgutil discovery found at least one protocol module on import."""
    from workspaces.network.analysis import protocol_fields
    assert len(protocol_fields._REGISTRY) > 0, (
        "protocol_fields._REGISTRY is empty — pkgutil discovery in __init__.py "
        "may have broken; check data/protocol_fields/__init__.py:_discover()"
    )


def test_protocol_fields_callables():
    """all_accumulate / all_serialize / any_boundary are callable after discovery."""
    from workspaces.network.analysis.protocol_fields import all_accumulate, all_serialize, any_boundary
    assert callable(all_accumulate)
    assert callable(all_serialize)
    assert callable(any_boundary)


@pytest.mark.parametrize("modname", ["dns", "tls", "http", "ssh", "kerberos", "smb"])
def test_protocol_fields_known_modules_importable(modname):
    """Known protocol modules import cleanly and expose the three required functions."""
    mod = importlib.import_module(f"workspaces.network.analysis.protocol_fields.{modname}")
    assert callable(getattr(mod, "init", None)),       f"{modname}: missing init()"
    assert callable(getattr(mod, "accumulate", None)), f"{modname}: missing accumulate()"
    assert callable(getattr(mod, "serialize", None)),  f"{modname}: missing serialize()"


# ── adapters ─────────────────────────────────────────────────────────────────

def test_adapters_registry_populated():
    """@register_adapter populated ADAPTERS on import."""
    from workspaces.network.parser.adapters import ADAPTERS
    assert len(ADAPTERS) > 0, (
        "workspaces.network.parser.adapters.ADAPTERS is empty — adapter imports at the bottom of "
        "parser/adapters/__init__.py may have broken"
    )


def test_adapters_pcap_present():
    """pcap/pcapng adapter is registered."""
    from workspaces.network.parser.adapters import ADAPTERS
    names = [cls.name for cls in ADAPTERS]
    assert any("pcap" in n.lower() for n in names), (
        f"No pcap adapter found in ADAPTERS. Registered: {names}"
    )


def test_adapters_zeek_present():
    """At least one Zeek adapter is registered."""
    from workspaces.network.parser.adapters import ADAPTERS
    names = [cls.name for cls in ADAPTERS]
    assert any("zeek" in n.lower() for n in names), (
        f"No Zeek adapter found in ADAPTERS. Registered: {names}"
    )


def test_adapters_tshark_present():
    """At least one tshark adapter is registered."""
    from workspaces.network.parser.adapters import ADAPTERS
    names = [cls.name for cls in ADAPTERS]
    assert any("tshark" in n.lower() for n in names), (
        f"No tshark adapter found in ADAPTERS. Registered: {names}"
    )


# ── research charts ───────────────────────────────────────────────────────────

_CHART_MODULES = [
    ("workspaces.network.research.conversation_timeline", "ConversationTimeline"),
    ("workspaces.network.research.ttl_over_time",         "TTLOverTime"),
    ("workspaces.network.research.session_gantt",         "SessionGantt"),
    ("workspaces.network.research.seq_ack_timeline",      "SeqAckTimelineChart"),
    ("workspaces.network.research.dns_timeline",          "DNSTimeline"),
    ("workspaces.network.research.ja3_timeline",          "JA3Timeline"),
    ("workspaces.network.research.ja4_timeline",          "JA4Timeline"),
    ("workspaces.network.research.http_ua_timeline",      "HTTPUserAgentTimeline"),
]


@pytest.mark.parametrize("modpath,classname", _CHART_MODULES)
def test_research_chart_importable(modpath, classname):
    """Each research chart module imports cleanly and its class has name + title."""
    mod = importlib.import_module(modpath)
    cls = getattr(mod, classname, None)
    assert cls is not None,  f"{classname} not found in {modpath}"
    assert cls.name,         f"{classname}.name is empty"
    assert cls.title,        f"{classname}.title is empty"


def test_research_charts_register_and_retrieve():
    """register_chart + get_charts round-trip succeeds for all known charts."""
    from workspaces.network.research import register_chart, get_charts
    for modpath, classname in _CHART_MODULES:
        mod = importlib.import_module(modpath)
        cls = getattr(mod, classname)
        register_chart(cls())
    charts = get_charts()
    assert len(charts) >= len(_CHART_MODULES), (
        f"Expected at least {len(_CHART_MODULES)} registered charts, got {len(charts)}"
    )


# ── alert detectors ───────────────────────────────────────────────────────────

_DETECTOR_MODULES = [
    ("workspaces.network.plugins.alerts.arp_spoofing",  "ArpSpoofingDetector"),
    ("workspaces.network.plugins.alerts.suspicious_ua", "SuspiciousUADetector"),
    ("workspaces.network.plugins.alerts.malicious_ja3", "MaliciousJA3Detector"),
    ("workspaces.network.plugins.alerts.port_scan",     "PortScanDetector"),
]


@pytest.mark.parametrize("modpath,classname", _DETECTOR_MODULES)
def test_alert_detector_importable(modpath, classname):
    """Each alert detector module imports cleanly and its class has a name."""
    mod = importlib.import_module(modpath)
    cls = getattr(mod, classname, None)
    assert cls is not None, f"{classname} not found in {modpath}"
    assert cls.name,        f"{classname}.name is empty"


def test_alert_detectors_register_and_retrieve():
    """register_detector + get_detectors round-trip succeeds for all known detectors."""
    from workspaces.network.plugins.alerts import register_detector, get_detectors
    for modpath, classname in _DETECTOR_MODULES:
        mod = importlib.import_module(modpath)
        cls = getattr(mod, classname)
        register_detector(cls())
    detectors = get_detectors()
    assert len(detectors) >= len(_DETECTOR_MODULES), (
        f"Expected at least {len(_DETECTOR_MODULES)} detectors, got {len(detectors)}"
    )


# ── insight plugins ───────────────────────────────────────────────────────────

_INSIGHT_MODULES = [
    ("workspaces.network.plugins.insights.os_fingerprint", "OSFingerprintPlugin"),
    ("workspaces.network.plugins.insights.network_map",    "NetworkMapPlugin"),
    ("workspaces.network.plugins.insights.tcp_flags",      "TCPFlagsPlugin"),
    ("workspaces.network.plugins.insights.dns_resolver",   "DNSResolverPlugin"),
]


@pytest.mark.parametrize("modpath,classname", _INSIGHT_MODULES)
def test_insight_plugin_importable(modpath, classname):
    """Each insight plugin module imports cleanly and its class has a name."""
    mod = importlib.import_module(modpath)
    cls = getattr(mod, classname, None)
    assert cls is not None, f"{classname} not found in {modpath}"
    assert cls.name,        f"{classname}.name is empty"


# ── analysis plugins ──────────────────────────────────────────────────────────

_ANALYSIS_MODULES = [
    ("workspaces.network.plugins.analyses.node_centrality",          "NodeCentralityAnalysis"),
    ("workspaces.network.plugins.analyses.traffic_characterisation",  "TrafficCharacterisationAnalysis"),
]


@pytest.mark.parametrize("modpath,classname", _ANALYSIS_MODULES)
def test_analysis_plugin_importable(modpath, classname):
    """Each analysis plugin module imports cleanly and its class has a name."""
    mod = importlib.import_module(modpath)
    cls = getattr(mod, classname, None)
    assert cls is not None, f"{classname} not found in {modpath}"
    assert cls.name,        f"{classname}.name is empty"


# ── frontend session sections (existence check only) ─────────────────────────

def test_session_sections_dir_non_empty():
    """
    frontend/src/workspaces/network/session_sections/ has at least one .jsx file.

    Vite's import.meta.glob does the real discovery at build time. This test
    catches the case where the directory is accidentally emptied or deleted —
    Vite would silently find nothing and the session detail panel would show
    no protocol sections.
    """
    sections_dir = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "src",
                     "workspaces", "network", "session_sections")
    )
    assert os.path.isdir(sections_dir), (
        f"session_sections directory missing: {sections_dir}"
    )
    jsx_files = [f for f in os.listdir(sections_dir) if f.endswith(".jsx")]
    assert len(jsx_files) > 0, (
        f"No .jsx files in session_sections/ — Vite import.meta.glob would find nothing"
    )
