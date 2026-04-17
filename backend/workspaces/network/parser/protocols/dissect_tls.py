"""TLS/HTTPS dissector — uses scapy TLS layer if available, else manual parsing."""

from typing import Dict, Any
from . import register_dissector
from .ports import CIPHER_SUITES

_HAS_SCAPY_TLS = False
_HAS_CRYPTOGRAPHY = False
try:
    from scapy.layers.tls.record import TLS
    from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello, TLSCertificate
    from scapy.layers.tls.extensions import ServerName, TLS_Ext_ServerName
    _HAS_SCAPY_TLS = True
except ImportError:
    pass

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    pass


@register_dissector("HTTPS")
def dissect_https(pkt) -> Dict[str, Any]:
    return _extract(pkt)


@register_dissector("TLS")
def dissect_tls(pkt) -> Dict[str, Any]:
    return _extract(pkt)


def _extract(pkt) -> Dict[str, Any]:
    if _HAS_SCAPY_TLS:
        result = _extract_scapy(pkt)
        if result:
            return result
    return _extract_manual(pkt)


def _extract_scapy(pkt) -> Dict[str, Any]:
    info = {}
    try:
        if not pkt.haslayer(TLS):
            return {}
        tls = pkt[TLS]
        ver = getattr(tls, "version", None)
        if ver:
            info["tls_record_version"] = _ver(ver)

        # Walk all TLS handshake messages in this packet.
        # A single TLS record can contain multiple handshake messages
        # (e.g. ServerHello + Certificate + ServerHelloDone in TLS 1.2).
        # Do NOT break early — walk the full chain.
        layer = tls.payload
        seen_types = set()
        while layer and layer.__class__.__name__ != "NoPayload":
            lname = layer.__class__.__name__
            if lname in seen_types:
                break   # guard against infinite loops on malformed packets
            seen_types.add(lname)

            if isinstance(layer, TLSClientHello):
                info["tls_msg_type"] = "ClientHello"
                if hasattr(layer, "version"):
                    info["tls_hello_version"] = _ver(layer.version)
                if hasattr(layer, "ciphers") and layer.ciphers:
                    suites = []
                    for cs in layer.ciphers[:20]:
                        v = cs.val if hasattr(cs, "val") else cs
                        suites.append(CIPHER_SUITES.get(v, f"0x{v:04x}"))
                    info["tls_cipher_suites"] = suites
                if hasattr(layer, "comp") and layer.comp:
                    info["tls_compression_methods"] = [c if isinstance(c, int) else getattr(c, 'val', 0) for c in layer.comp]
                if hasattr(layer, "ext") and layer.ext:
                    ext_types = []
                    for ext in layer.ext:
                        # Extension type number
                        if hasattr(ext, "type"):
                            ext_types.append(ext.type if isinstance(ext.type, int) else getattr(ext.type, 'val', 0))
                        # SNI
                        if isinstance(ext, TLS_Ext_ServerName):
                            for sn in (ext.servernames or []):
                                if hasattr(sn, "servername"):
                                    info["tls_sni"] = sn.servername.decode(errors="replace")
                                    break
                        # ALPN
                        ename = ext.__class__.__name__
                        if 'ALPN' in ename and hasattr(ext, 'protocols'):
                            try:
                                info["tls_alpn_offered"] = [p.protocol.decode(errors="replace") if isinstance(p.protocol, bytes) else str(p) for p in ext.protocols]
                            except Exception:
                                pass
                        # Supported versions
                        if 'SupportedVersion' in ename and hasattr(ext, 'versions'):
                            try:
                                info["tls_supported_versions"] = [_ver(v.val if hasattr(v, 'val') else v) for v in ext.versions]
                            except Exception:
                                pass
                        # Supported groups / named curves
                        if 'SupportedGroup' in ename and hasattr(ext, 'groups'):
                            try:
                                info["tls_supported_groups"] = [g.val if hasattr(g, 'val') else g for g in ext.groups]
                            except Exception:
                                pass
                    if ext_types:
                        info["tls_extensions"] = ext_types

            elif isinstance(layer, TLSServerHello):
                info["tls_msg_type"] = "ServerHello"
                if hasattr(layer, "version"):
                    info["tls_hello_version"] = _ver(layer.version)
                if hasattr(layer, "cipher"):
                    v = layer.cipher.val if hasattr(layer.cipher, "val") else layer.cipher
                    info["tls_selected_cipher"] = CIPHER_SUITES.get(v, f"0x{v:04x}")
                # Check for session resumption
                if hasattr(layer, "sid") and layer.sid:
                    sid = bytes(layer.sid) if not isinstance(layer.sid, bytes) else layer.sid
                    if len(sid) > 0 and sid != b'\x00' * len(sid):
                        info["tls_session_resumption"] = "session_id"
                if hasattr(layer, "ext") and layer.ext:
                    for ext in layer.ext:
                        ename = ext.__class__.__name__
                        # ALPN selected
                        if 'ALPN' in ename and hasattr(ext, 'protocols'):
                            try:
                                protos = ext.protocols
                                if protos:
                                    p = protos[0]
                                    info["tls_alpn_selected"] = p.protocol.decode(errors="replace") if hasattr(p, 'protocol') and isinstance(p.protocol, bytes) else str(p)
                            except Exception:
                                pass
                        # Supported versions (server selected)
                        if 'SupportedVersion' in ename:
                            try:
                                if hasattr(ext, 'version'):
                                    info["tls_selected_version"] = _ver(ext.version.val if hasattr(ext.version, 'val') else ext.version)
                                elif hasattr(ext, 'versions') and ext.versions:
                                    info["tls_selected_version"] = _ver(ext.versions[0].val if hasattr(ext.versions[0], 'val') else ext.versions[0])
                            except Exception:
                                pass
                        # Key share (tells us the group used)
                        if 'KeyShare' in ename:
                            try:
                                if hasattr(ext, 'server_share') and hasattr(ext.server_share, 'group'):
                                    info["tls_key_exchange_group"] = ext.server_share.group
                            except Exception:
                                pass

            elif isinstance(layer, TLSCertificate):
                try:
                    certs = layer.certs if hasattr(layer, "certs") else []
                    if certs:
                        # Leaf cert (first)
                        raw_cert = bytes(certs[0][1]) if isinstance(certs[0], tuple) else bytes(certs[0])
                        cert_info = _parse_cert(raw_cert)
                        if cert_info:
                            info["tls_cert"] = cert_info
                        # Full chain
                        if len(certs) > 1:
                            chain = []
                            for c in certs[1:5]:  # up to 4 intermediates
                                try:
                                    raw = bytes(c[1]) if isinstance(c, tuple) else bytes(c)
                                    ci = _parse_cert(raw)
                                    if ci:
                                        chain.append({"subject_cn": ci.get("subject_cn", ""), "issuer": ci.get("issuer", ""), "serial": ci.get("serial", "")})
                                except Exception:
                                    pass
                            if chain:
                                info["tls_cert_chain"] = chain
                except Exception:
                    pass

            layer = layer.payload if hasattr(layer, "payload") else None

    except Exception:
        return {}
    return info


def _parse_cert(raw_der: bytes) -> dict:
    """Parse a DER-encoded X.509 certificate and return key fields."""
    if not raw_der or not _HAS_CRYPTOGRAPHY:
        return {}
    try:
        cert = x509.load_der_x509_certificate(raw_der, default_backend())
        info = {}

        # Subject CN
        try:
            cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            if cn:
                info["subject_cn"] = cn[0].value
        except Exception:
            pass

        # Issuer O + CN
        try:
            iss_o  = cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
            iss_cn = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            parts = []
            if iss_o:  parts.append(iss_o[0].value)
            if iss_cn: parts.append(iss_cn[0].value)
            if parts:  info["issuer"] = " / ".join(parts)
        except Exception:
            pass

        # Validity
        try:
            info["not_before"] = cert.not_valid_before_utc.strftime("%Y-%m-%d") if hasattr(cert, "not_valid_before_utc") else str(cert.not_valid_before)[:10]
            info["not_after"]  = cert.not_valid_after_utc.strftime("%Y-%m-%d")  if hasattr(cert, "not_valid_after_utc")  else str(cert.not_valid_after)[:10]
        except Exception:
            pass

        # SANs
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = san_ext.value.get_values_for_type(x509.DNSName)
            if sans:
                info["sans"] = sans[:20]
        except Exception:
            pass

        # Serial (hex)
        try:
            info["serial"] = format(cert.serial_number, "x")
        except Exception:
            pass

        return info
    except Exception:
        return {}


def _extract_manual(pkt) -> Dict[str, Any]:
    info = {}
    if not pkt.haslayer("Raw"):
        return info
    try:
        raw = bytes(pkt["Raw"].load)
        if len(raw) < 6 or raw[0] != 0x16:
            return info
        info["tls_record_version"] = _ver((raw[1] << 8) | raw[2])

        if raw[5] == 0x01 and len(raw) > 43:  # Client Hello
            info["tls_msg_type"] = "ClientHello"
            info["tls_hello_version"] = _ver((raw[9] << 8) | raw[10])
            sid_len = raw[43]
            off = 44 + sid_len
            if off + 2 <= len(raw):
                cs_len = (raw[off] << 8) | raw[off + 1]
                off2 = off + 2
                suites = []
                for i in range(0, min(cs_len, 100), 2):
                    if off2 + i + 1 < len(raw):
                        sid = (raw[off2 + i] << 8) | raw[off2 + i + 1]
                        name = CIPHER_SUITES.get(sid)
                        if name:
                            suites.append(name)
                        elif sid != 0x00ff:
                            suites.append(f"0x{sid:04x}")
                info["tls_cipher_suites"] = suites[:20]
                off3 = off + 2 + cs_len
                if off3 + 1 <= len(raw):
                    comp_len = raw[off3]
                    off3 += 1 + comp_len
                    if off3 + 2 <= len(raw):
                        ext_total = (raw[off3] << 8) | raw[off3 + 1]
                        off3 += 2
                        end = min(off3 + ext_total, len(raw))
                        while off3 + 4 <= end:
                            et = (raw[off3] << 8) | raw[off3 + 1]
                            el = (raw[off3 + 2] << 8) | raw[off3 + 3]
                            if et == 0 and el > 5:
                                sni_off = off3 + 4 + 5
                                sni_len = (raw[off3 + 4 + 3] << 8) | raw[off3 + 4 + 4]
                                if sni_off + sni_len <= len(raw):
                                    info["tls_sni"] = raw[sni_off:sni_off + sni_len].decode(errors="replace")
                                break
                            off3 += 4 + el

        elif raw[5] == 0x02 and len(raw) > 43:  # Server Hello
            info["tls_msg_type"] = "ServerHello"
            info["tls_hello_version"] = _ver((raw[9] << 8) | raw[10])
            sid_len = raw[43]
            off = 44 + sid_len
            if off + 2 <= len(raw):
                sid = (raw[off] << 8) | raw[off + 1]
                info["tls_selected_cipher"] = CIPHER_SUITES.get(sid, f"0x{sid:04x}")
    except Exception:
        pass
    return info


_TLS_VERSIONS = {
    0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
    0x0303: "TLS 1.2", 0x0304: "TLS 1.3",
}

def _ver(v: int) -> str:
    return _TLS_VERSIONS.get(v, f"0x{v:04x}")
