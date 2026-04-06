"""
Zeek conn.log ingestion adapter.

Reads Zeek connection logs (tab-separated, with #fields header) and
produces one PacketRecord per row. Each row represents a complete session,
so granularity = "session" — but we still emit PacketRecords so the
existing pipeline (build_sessions, build_graph) works unchanged.

Since each conn.log row IS a session, build_sessions() will create
one-packet sessions. The initiator is always correct because Zeek's
id.orig_h is the connection originator.

Zeek history field is mapped to TCP flag counts so the frontend's
TCP flags breakdown works.
"""

import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

from parser.packet import PacketRecord
from .. import IngestionAdapter, register_adapter
from .common import parse_zeek_log, safe_int, safe_float, is_zeek_log

logger = logging.getLogger("swifteye.adapters.zeek_conn")

# Zeek protocol service → SwiftEye protocol name
SERVICE_MAP = {
    "http": "HTTP",
    "ssl": "TLS",
    "tls": "TLS",
    "dns": "DNS",
    "ssh": "SSH",
    "ftp": "FTP",
    "ftp-data": "FTP-DATA",
    "smtp": "SMTP",
    "smb": "SMB",
    "dhcp": "DHCP",
    "ntp": "NTP",
    "irc": "IRC",
    "rdp": "RDP",
    "sip": "SIP",
    "snmp": "SNMP",
    "ldap": "LDAP",
    "krb": "Kerberos",
    "kerberos": "Kerberos",
    "syslog": "Syslog",
    "mysql": "MySQL",
    "dce_rpc": "DCE/RPC",
}

# Zeek history characters → TCP flag names
# Uppercase = originator, lowercase = responder
HISTORY_FLAG_MAP = {
    "S": "SYN",
    "H": "SYN",  # SYN+ACK from responder (we count it as SYN)
    "A": "ACK",
    "D": "PSH",  # data packet, closest to PSH
    "F": "FIN",
    "R": "RST",
    "C": "RST",  # connection attempt rejected
    "I": "ACK",  # inconsistent (counted as generic)
    "Q": "RST",  # teardown started
}


def _parse_history(history: str) -> Dict[str, int]:
    """Convert Zeek history string to flag_counts dict.

    Zeek history: ShADadFf
      S = originator SYN
      h = responder SYN+ACK
      A/a = ACK (orig/resp)
      D/d = data (orig/resp)
      F/f = FIN (orig/resp)
      R/r = RST (orig/resp)
    """
    counts: Dict[str, int] = {}
    if not history or history == "-":
        return counts
    for ch in history:
        flag = HISTORY_FLAG_MAP.get(ch.upper())
        if flag:
            counts[flag] = counts.get(flag, 0) + 1
    return counts




@register_adapter
class ZeekConnAdapter(IngestionAdapter):
    name = "Zeek conn.log"
    file_extensions = [".log"]
    granularity = "session"
    source_type = "zeek"

    def can_handle(self, path: Path, header: bytes) -> bool:
        if path.suffix.lower() != ".log":
            return False
        # Must have Zeek header with conn.log-specific fields
        # Use "conn_state" to distinguish from other Zeek logs that also have id.orig_h
        return is_zeek_log(header, "conn_state")

    def parse(self, path: Path, **opts) -> List[PacketRecord]:
        rows = parse_zeek_log(path)
        if not rows:
            logger.warning("No data rows in %s", path.name)
            return []

        packets = []
        for row in rows:
            pkt = self._row_to_packet(row)
            if pkt:
                packets.append(pkt)

        packets.sort(key=lambda p: p.timestamp)
        logger.info("Parsed %d sessions from Zeek conn.log (%s)", len(packets), path.name)
        return packets

    def _row_to_packet(self, row: Dict[str, str]) -> Optional[PacketRecord]:
        """Convert one conn.log row to a PacketRecord."""
        src_ip = row.get("id.orig_h", "")
        dst_ip = row.get("id.resp_h", "")
        if not src_ip or not dst_ip:
            return None

        src_port = safe_int(row.get("id.orig_p", "0"))
        dst_port = safe_int(row.get("id.resp_p", "0"))
        timestamp = safe_float(row.get("ts", "0"))
        if timestamp == 0:
            return None

        # Transport protocol
        proto = row.get("proto", "").upper()
        transport = proto if proto in ("TCP", "UDP", "ICMP") else ""

        # Application protocol from Zeek's service field
        service = row.get("service", "-")
        if service and service != "-":
            # Zeek can report multiple services comma-separated
            primary_service = service.split(",")[0].strip()
            protocol = SERVICE_MAP.get(primary_service, primary_service.upper())
        else:
            protocol = transport or "OTHER"

        # Byte counts
        orig_bytes = safe_int(row.get("orig_bytes", "0"))
        resp_bytes = safe_int(row.get("resp_bytes", "0"))
        orig_ip_bytes = safe_int(row.get("orig_ip_bytes", "0"))
        resp_ip_bytes = safe_int(row.get("resp_ip_bytes", "0"))
        total_bytes = orig_ip_bytes + resp_ip_bytes if (orig_ip_bytes or resp_ip_bytes) else orig_bytes + resp_bytes

        # Duration
        duration = safe_float(row.get("duration", "0"))

        # History → flag counts
        history = row.get("history", "-")
        flag_counts = _parse_history(history)

        # Build tcp_flags_str from history for search/filter compatibility
        tcp_flags_str = " ".join(sorted(flag_counts.keys())) if flag_counts else ""

        # Determine IP version
        ip_version = 6 if ":" in src_ip else 4

        # Derive has_handshake from Zeek conn_state
        conn_state = row.get("conn_state", "-")
        # SF=normal, S1=SYN+SYN/ACK, S2/S3=established variants, RSTO/RSTR=reset after established
        has_handshake = conn_state in ("SF", "S1", "S2", "S3", "RSTO", "RSTR")

        # Build extra dict with Zeek-specific fields
        extra: Dict[str, Any] = {
            "source_type": "zeek",
            "has_handshake": has_handshake,
        }
        # Always include these Zeek fields
        for field in ("uid", "conn_state", "history", "duration",
                      "orig_bytes", "resp_bytes", "orig_ip_bytes", "resp_ip_bytes",
                      "orig_pkts", "resp_pkts", "missed_bytes",
                      "local_orig", "local_resp", "tunnel_parents"):
            val = row.get(field, "-")
            if val and val != "-":
                extra[field] = val

        # Store numeric versions for session detail display
        if service and service != "-":
            extra["service"] = service
        extra["orig_bytes"] = orig_bytes
        extra["resp_bytes"] = resp_bytes
        extra["duration"] = duration
        extra["flag_counts"] = flag_counts

        # Expand flag_counts into tcp_flags_list so build_sessions
        # accumulates the correct counts (e.g. SYN:2 → ["SYN","SYN"])
        tcp_flags_list = []
        for flag, count in flag_counts.items():
            tcp_flags_list.extend([flag] * count)

        pkt = PacketRecord(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            transport=transport,
            protocol=protocol,
            ip_version=ip_version,
            orig_len=total_bytes,
            tcp_flags_str=tcp_flags_str,
            tcp_flags_list=tcp_flags_list,
        )
        pkt.extra = extra

        return pkt
