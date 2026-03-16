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
                if hasattr(layer, "ext") and layer.ext:
                    for ext in layer.ext:
                        if isinstance(ext, TLS_Ext_ServerName):
                            for sn in (ext.servernames or []):
                                if hasattr(sn, "servername"):
                                    info["tls_sni"] = sn.servername.decode(errors="replace")
                                    break

            elif isinstance(layer, TLSServerHello):
                info["tls_msg_type"] = "ServerHello"
                if hasattr(layer, "version"):
                    info["tls_hello_version"] = _ver(layer.version)
                if hasattr(layer, "cipher"):
                    v = layer.cipher.val if hasattr(layer.cipher, "val") else layer.cipher
                    info["tls_selected_cipher"] = CIPHER_SUITES.get(v, f"0x{v:04x}")

            elif isinstance(layer, TLSCertificate):
                if "tls_cert" not in info:   # only take the first (leaf) cert
                    try:
                        certs = layer.certs if hasattr(layer, "certs") else []
                        if certs:
                            raw_cert = bytes(certs[0][1]) if isinstance(certs[0], tuple) else bytes(certs[0])
                            cert_info = _parse_cert(raw_cert)
                            if cert_info:
                                info["tls_cert"] = cert_info
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


def _ver(v: int) -> str:
    return {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
            0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}.get(v, f"0x{v:04x}")
