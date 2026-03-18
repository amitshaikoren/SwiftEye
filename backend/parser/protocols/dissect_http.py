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
        if hasattr(req, 'User_Agent') and req.User_Agent:
            info["http_user_agent"] = req.User_Agent.decode(errors="replace")[:500]
        if hasattr(req, 'Referer') and req.Referer:
            info["http_referer"] = req.Referer.decode(errors="replace")[:500]
        if hasattr(req, 'Content_Type') and req.Content_Type:
            info["http_content_type"] = req.Content_Type.decode(errors="replace")
        if hasattr(req, 'Content_Length') and req.Content_Length:
            try: info["http_content_length"] = int(req.Content_Length)
            except (ValueError, TypeError): pass
        if hasattr(req, 'Cookie') and req.Cookie:
            info["http_cookie"] = req.Cookie.decode(errors="replace")[:500]
        if hasattr(req, 'Authorization') and req.Authorization:
            info["http_authorization"] = req.Authorization.decode(errors="replace")[:200]
    elif pkt.haslayer(HTTPResponse):
        resp = pkt[HTTPResponse]
        info["http_version"] = (resp.Http_Version or b"").decode(errors="replace")
        try:
            info["http_status"] = int(resp.Status_Code or 0)
        except (ValueError, TypeError):
            pass
        info["http_reason"] = (resp.Reason_Phrase or b"").decode(errors="replace")
        if hasattr(resp, 'Content_Type') and resp.Content_Type:
            info["http_content_type"] = resp.Content_Type.decode(errors="replace")
        if hasattr(resp, 'Content_Length') and resp.Content_Length:
            try: info["http_content_length"] = int(resp.Content_Length)
            except (ValueError, TypeError): pass
        if hasattr(resp, 'Server') and resp.Server:
            info["http_server"] = resp.Server.decode(errors="replace")[:200]
        if hasattr(resp, 'Set_Cookie') and resp.Set_Cookie:
            info["http_set_cookie"] = resp.Set_Cookie.decode(errors="replace")[:500]
        if hasattr(resp, 'Location') and resp.Location:
            info["http_location"] = resp.Location.decode(errors="replace")[:500]
    return info


def _dissect_manual(pkt) -> Dict[str, Any]:
    info = {}
    if pkt.haslayer("Raw"):
        try:
            payload = bytes(pkt["Raw"].load)
            lines = payload.split(b"\r\n")
            first_line = lines[0].decode(errors="replace")
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
            # Parse headers — same set as the scapy path
            _HEADER_MAP = {
                b"host:": "http_host",
                b"user-agent:": "http_user_agent",
                b"referer:": "http_referer",
                b"content-type:": "http_content_type",
                b"content-length:": "http_content_length",
                b"server:": "http_server",
                b"set-cookie:": "http_set_cookie",
                b"location:": "http_location",
                b"cookie:": "http_cookie",
                b"authorization:": "http_authorization",
            }
            for line in lines[1:30]:
                if not line:
                    break
                lower = line.lower()
                for prefix, key in _HEADER_MAP.items():
                    if lower.startswith(prefix):
                        val = line.split(b":", 1)[1].strip().decode(errors="replace")
                        if key == "http_content_length":
                            try: info[key] = int(val)
                            except ValueError: pass
                        else:
                            info[key] = val[:500]
                        break
        except Exception:
            pass
    return info
