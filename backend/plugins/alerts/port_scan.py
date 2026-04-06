"""
Port scan detector (TCP + UDP).

TCP detection:
  Groups sessions by (src_ip, dst_ip). If a pair has >= 15 distinct dst ports
  AND >= 60% of sessions lack a completed handshake, flag as port scan.
  Severity: medium if 15-49 ports, high if >= 50.

UDP detection:
  Groups UDP sessions by (src_ip, dst_ip). If a pair has >= 15 distinct dst
  ports, flag as UDP port scan. No handshake check (UDP is connectionless).
  Severity: medium.
"""

import uuid
from plugins.alerts import AlertPluginBase, AlertRecord

_PORT_THRESHOLD = 15
_HIGH_PORT_THRESHOLD = 50
_HANDSHAKE_FAIL_RATIO = 0.6


class PortScanDetector(AlertPluginBase):
    name = "port_scan"
    version = "1.0"

    def detect(self, ctx):
        alerts = []
        alerts.extend(self._detect_tcp(ctx))
        alerts.extend(self._detect_udp(ctx))
        return alerts

    def _detect_tcp(self, ctx):
        alerts = []
        # pair -> {ports: set, no_hs: int, total: int, sessions: [], first_ts, last_ts}
        pairs = {}

        for s in ctx.sessions:
            if s.get("transport") != "TCP":
                continue
            src = s.get("src_ip")
            dst = s.get("dst_ip")
            port = s.get("dst_port")
            if not src or not dst or port is None:
                continue

            key = (src, dst)
            if key not in pairs:
                pairs[key] = {"ports": set(), "no_hs": 0, "total": 0, "sessions": [], "first_ts": None, "last_ts": None}
            p = pairs[key]
            p["ports"].add(port)
            p["total"] += 1
            if not s.get("has_handshake"):
                p["no_hs"] += 1
            p["sessions"].append(s.get("session_id", ""))
            ts = s.get("start_time")
            if ts:
                if p["first_ts"] is None or ts < p["first_ts"]:
                    p["first_ts"] = ts
                if p["last_ts"] is None or ts > p["last_ts"]:
                    p["last_ts"] = ts

        for (src, dst), p in pairs.items():
            n_ports = len(p["ports"])
            if n_ports < _PORT_THRESHOLD:
                continue
            if p["total"] > 0 and (p["no_hs"] / p["total"]) < _HANDSHAKE_FAIL_RATIO:
                continue

            duration = (p["last_ts"] - p["first_ts"]) if p["first_ts"] and p["last_ts"] else 0
            severity = "high" if n_ports >= _HIGH_PORT_THRESHOLD else "medium"
            sorted_ports = sorted(p["ports"])
            port_sample = ", ".join(str(pt) for pt in sorted_ports[:10])
            if n_ports > 10:
                port_sample += "..."

            alerts.append(AlertRecord(
                id=uuid.uuid4().hex[:8],
                title="TCP Port Scan",
                subtitle=f"{src} scanned {n_ports} ports on {dst}",
                severity=severity,
                detector=self.name,
                source="detector",
                source_name=self.name,
                timestamp=p["first_ts"],
                src_ip=src,
                dst_ip=dst,
                evidence=[
                    {"key": "Distinct dst ports", "value": str(n_ports), "note": f"in {duration:.0f}s"},
                    {"key": "Without handshake", "value": f"{p['no_hs']} / {p['total']}", "note": f"{p['no_hs']/p['total']*100:.0f}%" if p["total"] else ""},
                    {"key": "Port sample", "value": port_sample, "note": ""},
                ],
                node_ids=[src, dst],
                session_ids=p["sessions"][:20],
            ))

        return alerts

    def _detect_udp(self, ctx):
        alerts = []
        # pair -> {ports: set, sessions: [], first_ts, last_ts}
        pairs = {}

        for s in ctx.sessions:
            if s.get("transport") != "UDP":
                continue
            src = s.get("src_ip")
            dst = s.get("dst_ip")
            port = s.get("dst_port")
            if not src or not dst or port is None:
                continue

            key = (src, dst)
            if key not in pairs:
                pairs[key] = {"ports": set(), "sessions": [], "first_ts": None, "last_ts": None}
            p = pairs[key]
            p["ports"].add(port)
            p["sessions"].append(s.get("session_id", ""))
            ts = s.get("start_time")
            if ts:
                if p["first_ts"] is None or ts < p["first_ts"]:
                    p["first_ts"] = ts
                if p["last_ts"] is None or ts > p["last_ts"]:
                    p["last_ts"] = ts

        for (src, dst), p in pairs.items():
            n_ports = len(p["ports"])
            if n_ports < _PORT_THRESHOLD:
                continue

            duration = (p["last_ts"] - p["first_ts"]) if p["first_ts"] and p["last_ts"] else 0
            sorted_ports = sorted(p["ports"])
            port_sample = ", ".join(str(pt) for pt in sorted_ports[:10])
            if n_ports > 10:
                port_sample += "..."

            alerts.append(AlertRecord(
                id=uuid.uuid4().hex[:8],
                title="UDP Port Scan",
                subtitle=f"{src} probed {n_ports} UDP ports on {dst}",
                severity="medium",
                detector=self.name,
                source="detector",
                source_name=self.name,
                timestamp=p["first_ts"],
                src_ip=src,
                dst_ip=dst,
                evidence=[
                    {"key": "Distinct UDP dst ports", "value": str(n_ports), "note": f"in {duration:.0f}s"},
                    {"key": "Port sample", "value": port_sample, "note": ""},
                ],
                node_ids=[src, dst],
                session_ids=p["sessions"][:20],
            ))

        return alerts
