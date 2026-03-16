"""HTTP dissector — uses scapy HTTP layer if available, else manual parsing."""

from typing import Dict, Any
from . import register_dissector

_HAS_SCAPY_HTTP = False
try:
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    _HAS_SCAPY_HTTP = True
except ImportError:
    pass


@register_dissector("HTTP")
def dissect_http(pkt) -> Dict[str, Any]:
    if _HAS_SCAPY_HTTP:
        return _dissect_scapy(pkt)
    return _dissect_manual(pkt)


def _dissect_scapy(pkt) -> Dict[str, Any]:
    info = {}
    if pkt.haslayer(HTTPRequest):
        req = pkt[HTTPRequest]
        info["http_method"] = (req.Method or b"").decode(errors="replace")
        info["http_uri"] = (req.Path or b"").decode(errors="replace")
        info["http_version"] = (req.Http_Version or b"").decode(errors="replace")
        if req.Host:
            info["http_host"] = req.Host.decode(errors="replace")
    elif pkt.haslayer(HTTPResponse):
        resp = pkt[HTTPResponse]
        info["http_version"] = (resp.Http_Version or b"").decode(errors="replace")
        try:
            info["http_status"] = int(resp.Status_Code or 0)
        except (ValueError, TypeError):
            pass
        info["http_reason"] = (resp.Reason_Phrase or b"").decode(errors="replace")
    return info


def _dissect_manual(pkt) -> Dict[str, Any]:
    info = {}
    if pkt.haslayer("Raw"):
        try:
            payload = bytes(pkt["Raw"].load)
            first_line = payload.split(b"\r\n")[0].decode(errors="replace")
            if first_line.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "PATCH ", "OPTIONS ")):
                parts = first_line.split(" ", 2)
                info["http_method"] = parts[0]
                info["http_uri"] = parts[1] if len(parts) > 1 else ""
                info["http_version"] = parts[2] if len(parts) > 2 else ""
            elif first_line.startswith("HTTP/"):
                parts = first_line.split(" ", 2)
                info["http_version"] = parts[0]
                info["http_status"] = int(parts[1]) if len(parts) > 1 else 0
                info["http_reason"] = parts[2] if len(parts) > 2 else ""
            for line in payload.split(b"\r\n")[1:10]:
                if line.lower().startswith(b"host:"):
                    info["http_host"] = line.split(b":", 1)[1].strip().decode(errors="replace")
                    break
        except Exception:
            pass
    return info
