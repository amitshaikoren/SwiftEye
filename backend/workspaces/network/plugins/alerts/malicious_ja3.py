"""
Malicious JA3 / deprecated TLS detector.

Detection 1 — JA3 hash matches known malware entry in ja3_db.py:
  Uses lookup_ja3() which returns {name, category, is_malware} or None.
  One alert per session (JA3 matches are session-specific).

Detection 2 — Deprecated TLS version (1.0 or 1.1):
  RFC 8996 deprecated TLS 1.0 and 1.1. Sessions negotiating these versions
  may indicate legacy or misconfigured systems. One alert per session.
"""

import uuid
from workspaces.network.parser.ja3_db import lookup_ja3
from workspaces.network.plugins.alerts import AlertPluginBase, AlertRecord

_DEPRECATED_VERSIONS = {"TLS 1.0", "TLS 1.1", "SSLv3", "SSLv2"}


class MaliciousJA3Detector(AlertPluginBase):
    name = "malicious_ja3"
    version = "1.0"

    def detect(self, ctx):
        alerts = []

        for s in ctx.sessions:
            if s.get("protocol") != "TLS":
                continue

            src = s.get("src_ip")
            dst = s.get("dst_ip")
            sid = s.get("session_id", "")

            # -- Detection 1: Malware JA3 --
            for ja3_hash in s.get("ja3_hashes", []):
                info = lookup_ja3(ja3_hash)
                if info and info.get("is_malware"):
                    snis = s.get("tls_snis", [])
                    evidence = [
                        {"key": "JA3", "value": ja3_hash, "note": ""},
                        {"key": "Match", "value": info.get("name", "unknown"), "note": f"category: {info.get('category', 'unknown')}, is_malware: true"},
                    ]
                    if snis:
                        evidence.append({"key": "SNI", "value": ", ".join(snis[:3]), "note": ""})
                    alerts.append(AlertRecord(
                        id=uuid.uuid4().hex[:8],
                        title="Malicious JA3 Fingerprint",
                        subtitle=f"TLS fingerprint matches known malware: {info.get('name', ja3_hash[:16])}",
                        severity="high",
                        detector=self.name,
                        source="detector",
                        source_name=self.name,
                        timestamp=s.get("start_time"),
                        src_ip=src,
                        dst_ip=dst,
                        evidence=evidence,
                        node_ids=[ip for ip in [src, dst] if ip],
                        session_ids=[sid],
                    ))
                    break  # one alert per session for JA3

            # -- Detection 2: Deprecated TLS version --
            versions = s.get("tls_versions", [])
            deprecated = [v for v in versions if v in _DEPRECATED_VERSIONS]
            if deprecated:
                alerts.append(AlertRecord(
                    id=uuid.uuid4().hex[:8],
                    title="Deprecated TLS Version",
                    subtitle=f"Session negotiated {', '.join(deprecated)}",
                    severity="info",
                    detector=self.name,
                    source="detector",
                    source_name=self.name,
                    timestamp=s.get("start_time"),
                    src_ip=src,
                    dst_ip=dst,
                    evidence=[
                        {"key": "Negotiated version", "value": ", ".join(deprecated), "note": "deprecated per RFC 8996"},
                    ],
                    node_ids=[ip for ip in [src, dst] if ip],
                    session_ids=[sid],
                ))

        return alerts
