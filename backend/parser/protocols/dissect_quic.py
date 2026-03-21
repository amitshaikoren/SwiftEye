"""
QUIC dissector (Phase 1) -- extracts header fields and SNI from Initial packets.

QUIC runs over UDP (typically port 443). The Initial packet has a cleartext long
header with version + connection IDs. The payload is encrypted, but the keys are
derived from the Destination Connection ID using HKDF (RFC 9001 section 5), so any
observer can decrypt it.

Phase 1 extracts:
  quic_version          -- QUIC version (hex string)
  quic_version_name     -- Human-readable version name
  quic_dcid             -- Destination Connection ID (hex)
  quic_scid             -- Source Connection ID (hex)
  quic_packet_type      -- "Initial", "0-RTT", "Handshake", "Retry"
  quic_sni              -- SNI from TLS ClientHello inside Initial CRYPTO frames
  quic_alpn             -- ALPN protocols from ClientHello
  quic_tls_versions     -- Supported TLS versions from ClientHello
  quic_tls_ciphers      -- Cipher suites from ClientHello

Phase 2 (future): with SSLKEYLOGFILE, decrypt 0-RTT and 1-RTT application data.
"""

import struct
import hashlib
import hmac
from typing import Dict, Any, Optional, Tuple

from . import register_dissector, register_payload_signature
from .ports import CIPHER_SUITES

# ---------------------------------------------------------------------------
# HKDF helpers (RFC 5869) -- needed to derive Initial packet protection keys
# ---------------------------------------------------------------------------

_HAS_CRYPTO = False
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    _HAS_CRYPTO = True
except ImportError:
    pass


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract (RFC 5869) using SHA-256."""
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand_label(secret: bytes, label: bytes, context: bytes, length: int) -> bytes:
    """TLS 1.3 HKDF-Expand-Label (RFC 8446 section 7.1)."""
    # HkdfLabel = length (2) || "tls13 " + label (1+len) || context (1+len)
    full_label = b"tls13 " + label
    hkdf_label = struct.pack(">H", length) + bytes([len(full_label)]) + full_label + bytes([len(context)]) + context
    return _hkdf_expand(secret, hkdf_label, length)


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand (RFC 5869) using SHA-256."""
    hash_len = 32  # SHA-256
    n = (length + hash_len - 1) // hash_len
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


# QUIC v1 (RFC 9001) Initial salt
_QUIC_V1_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
# QUIC v2 (RFC 9369) Initial salt
_QUIC_V2_SALT = bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9")

_QUIC_VERSIONS = {
    0x00000001: "QUIC v1",
    0x6b3343cf: "QUIC v2",
    0xff000000: "QUIC draft",
}


def _version_name(ver: int) -> str:
    if ver in _QUIC_VERSIONS:
        return _QUIC_VERSIONS[ver]
    if (ver & 0xff000000) == 0xff000000:
        draft = ver & 0xff
        return f"QUIC draft-{draft}"
    return f"0x{ver:08x}"


_PACKET_TYPES_V1 = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}


# ---------------------------------------------------------------------------
# Payload signature -- detect QUIC on any UDP port
# ---------------------------------------------------------------------------

@register_payload_signature("QUIC", priority=12)
def _detect_quic(payload: bytes) -> bool:
    """Detect QUIC long-header packets by version field."""
    if len(payload) < 5:
        return False
    # First bit must be 1 (long header form) and second bit 1 (fixed bit)
    if not (payload[0] & 0x80):
        return False
    # Read version at bytes 1-4
    ver = struct.unpack(">I", payload[1:5])[0]
    # Version 0 = Version Negotiation (also QUIC)
    if ver == 0:
        return True
    # Known QUIC versions
    if ver in (0x00000001, 0x6b3343cf):
        return True
    # QUIC draft versions
    if (ver & 0xff000000) == 0xff000000:
        return True
    return False


# ---------------------------------------------------------------------------
# Dissector
# ---------------------------------------------------------------------------

@register_dissector("QUIC")
def dissect_quic(pkt) -> Dict[str, Any]:
    """Extract QUIC header fields and attempt SNI extraction from Initial packets."""
    if pkt.haslayer("Raw"):
        return _extract(bytes(pkt["Raw"].load))
    return {}


def _extract(payload: bytes) -> Dict[str, Any]:
    info: Dict[str, Any] = {}

    if len(payload) < 5:
        return info

    first_byte = payload[0]

    # Must be long header (bit 7 set)
    if not (first_byte & 0x80):
        # Short header -- we can't extract much without connection state
        return info

    # Version (bytes 1-4)
    version = struct.unpack(">I", payload[1:5])[0]
    info["quic_version"] = f"0x{version:08x}"
    info["quic_version_name"] = _version_name(version)

    # Version Negotiation (version = 0)
    if version == 0:
        info["quic_packet_type"] = "Version Negotiation"
        return _parse_long_header_ids(payload, info)

    # Determine packet type from first byte
    if version == 0x6b3343cf:
        # QUIC v2 has different type mapping (RFC 9369 section 3)
        v2_type_map = {0b01: "Initial", 0b10: "0-RTT", 0b11: "Handshake", 0b00: "Retry"}
        ptype_bits = (first_byte & 0x30) >> 4
        info["quic_packet_type"] = v2_type_map.get(ptype_bits, f"Unknown({ptype_bits})")
    else:
        # QUIC v1 and drafts
        ptype_bits = (first_byte & 0x30) >> 4
        info["quic_packet_type"] = _PACKET_TYPES_V1.get(ptype_bits, f"Unknown({ptype_bits})")

    # Parse DCID and SCID
    info = _parse_long_header_ids(payload, info)

    # Attempt Initial packet decryption for SNI extraction
    if info.get("quic_packet_type") == "Initial" and _HAS_CRYPTO:
        try:
            _extract_initial_sni(payload, version, info)
        except Exception:
            pass

    return info


def _parse_long_header_ids(payload: bytes, info: Dict[str, Any]) -> Dict[str, Any]:
    """Parse DCID and SCID from a QUIC long header."""
    if len(payload) < 6:
        return info

    off = 5
    # DCID length
    if off >= len(payload):
        return info
    dcid_len = payload[off]
    off += 1
    if dcid_len > 20 or off + dcid_len > len(payload):
        return info
    dcid = payload[off:off + dcid_len]
    info["quic_dcid"] = dcid.hex()
    off += dcid_len

    # SCID length
    if off >= len(payload):
        return info
    scid_len = payload[off]
    off += 1
    if scid_len > 20 or off + scid_len > len(payload):
        return info
    scid = payload[off:off + scid_len]
    info["quic_scid"] = scid.hex()

    return info


def _extract_initial_sni(payload: bytes, version: int, info: Dict[str, Any]) -> None:
    """
    Decrypt a QUIC Initial packet and extract SNI from the TLS ClientHello.

    QUIC Initial packets are protected with keys derived from the DCID.
    The process:
    1. Derive client Initial secret from DCID using HKDF
    2. Derive key + IV + HP key from the client secret
    3. Remove header protection (to get packet number)
    4. Decrypt payload with AES-128-GCM
    5. Parse CRYPTO frames to find TLS ClientHello
    6. Extract SNI from ClientHello extensions
    """
    first_byte = payload[0]

    # Re-parse header to get offsets
    off = 5
    dcid_len = payload[off]
    off += 1
    dcid = payload[off:off + dcid_len]
    off += dcid_len
    scid_len = payload[off]
    off += 1 + scid_len

    # Token length (variable-length integer)
    token_len, token_len_size = _decode_varint(payload, off)
    if token_len is None:
        return
    off += token_len_size + token_len

    # Payload length (variable-length integer)
    pkt_len, pkt_len_size = _decode_varint(payload, off)
    if pkt_len is None:
        return
    off += pkt_len_size

    # off now points to the packet number (protected)
    pn_offset = off

    if pn_offset + 4 > len(payload):
        return

    # Derive Initial secrets
    salt = _QUIC_V2_SALT if version == 0x6b3343cf else _QUIC_V1_SALT
    initial_secret = _hkdf_extract(salt, dcid)

    if version == 0x6b3343cf:
        # QUIC v2 uses different labels
        client_secret = _hkdf_expand_label(initial_secret, b"quicv2 client in", b"", 32)
    else:
        client_secret = _hkdf_expand_label(initial_secret, b"client in", b"", 32)

    # Derive key, IV, and header protection key
    quic_key = _hkdf_expand_label(client_secret, b"quic key", b"", 16)
    quic_iv = _hkdf_expand_label(client_secret, b"quic iv", b"", 12)
    quic_hp = _hkdf_expand_label(client_secret, b"quic hp", b"", 16)

    # --- Remove header protection ---
    # Sample starts 4 bytes after the packet number offset
    sample_offset = pn_offset + 4
    if sample_offset + 16 > len(payload):
        return

    sample = payload[sample_offset:sample_offset + 16]

    # AES-ECB encrypt the sample to get the mask
    cipher = Cipher(algorithms.AES(quic_hp), modes.ECB())
    encryptor = cipher.encryptor()
    mask = encryptor.update(sample) + encryptor.finalize()

    # Unmask the first byte to get packet number length
    unmasked_first = first_byte ^ (mask[0] & 0x0f)
    pn_length = (unmasked_first & 0x03) + 1

    # Unmask the packet number bytes
    pn_bytes = bytearray(payload[pn_offset:pn_offset + pn_length])
    for i in range(pn_length):
        pn_bytes[i] ^= mask[1 + i]
    packet_number = int.from_bytes(pn_bytes, "big")

    # --- Decrypt payload ---
    # Nonce = IV XOR packet_number (left-padded to 12 bytes)
    nonce = bytearray(quic_iv)
    pn_padded = packet_number.to_bytes(12, "big")
    for i in range(12):
        nonce[i] ^= pn_padded[i]

    # Encrypted payload starts after the packet number
    enc_start = pn_offset + pn_length
    # The encrypted length is payload_length - pn_length
    enc_data = payload[enc_start:pn_offset + pkt_len]

    if len(enc_data) < 16:  # need at least the AES-GCM tag
        return

    # Build AAD: the unprotected header
    aad = bytearray(payload[:enc_start])
    aad[0] = unmasked_first
    for i in range(pn_length):
        aad[pn_offset + i] = pn_bytes[i]

    try:
        aesgcm = AESGCM(quic_key)
        plaintext = aesgcm.decrypt(bytes(nonce), bytes(enc_data), bytes(aad))
    except Exception:
        return

    # --- Parse CRYPTO frames from the decrypted payload ---
    crypto_data = _extract_crypto_frames(plaintext)
    if not crypto_data:
        return

    # Parse TLS ClientHello from the reassembled CRYPTO data
    _parse_client_hello(crypto_data, info)


def _decode_varint(data: bytes, offset: int) -> Tuple[Optional[int], int]:
    """Decode a QUIC variable-length integer (RFC 9000 section 16)."""
    if offset >= len(data):
        return None, 0
    first = data[offset]
    length_bits = first >> 6
    if length_bits == 0:
        return first & 0x3f, 1
    elif length_bits == 1:
        if offset + 2 > len(data):
            return None, 0
        return ((first & 0x3f) << 8) | data[offset + 1], 2
    elif length_bits == 2:
        if offset + 4 > len(data):
            return None, 0
        return struct.unpack(">I", bytes([first & 0x3f]) + data[offset + 1:offset + 4])[0], 4
    else:
        if offset + 8 > len(data):
            return None, 0
        return struct.unpack(">Q", bytes([first & 0x3f]) + data[offset + 1:offset + 8])[0], 8


def _extract_crypto_frames(plaintext: bytes) -> bytes:
    """Extract and reassemble CRYPTO frame data from decrypted QUIC payload."""
    crypto_data = bytearray()
    off = 0
    while off < len(plaintext):
        frame_type, ft_size = _decode_varint(plaintext, off)
        if frame_type is None:
            break
        off += ft_size

        if frame_type == 0x00:
            # PADDING frame -- skip
            continue
        elif frame_type == 0x01:
            # PING frame -- skip
            continue
        elif frame_type == 0x06:
            # CRYPTO frame
            # offset (varint) + length (varint) + data
            crypto_offset, co_size = _decode_varint(plaintext, off)
            if crypto_offset is None:
                break
            off += co_size
            crypto_len, cl_size = _decode_varint(plaintext, off)
            if crypto_len is None:
                break
            off += cl_size
            if off + crypto_len > len(plaintext):
                # Take what we can
                crypto_data.extend(plaintext[off:])
                break
            crypto_data.extend(plaintext[off:off + crypto_len])
            off += crypto_len
        elif frame_type == 0x1c or frame_type == 0x1d:
            # CONNECTION_CLOSE frame -- skip rest
            break
        else:
            # ACK or other frames we can't easily skip without knowing size
            # For Initial packets, CRYPTO + PADDING + ACK are the main frames
            # ACK (0x02/0x03) has variable structure -- bail out
            break

    return bytes(crypto_data)


def _parse_client_hello(data: bytes, info: Dict[str, Any]) -> None:
    """Parse a TLS ClientHello from CRYPTO frame data and extract SNI + other fields."""
    if len(data) < 6:
        return

    # TLS handshake record: type (1) + length (3) + ...
    hs_type = data[0]
    if hs_type != 0x01:  # ClientHello
        return

    hs_len = (data[1] << 16) | (data[2] << 8) | data[3]
    off = 4

    if off + 2 > len(data):
        return

    # Client version (2 bytes)
    off += 2

    # Random (32 bytes)
    off += 32

    if off >= len(data):
        return

    # Session ID length + session ID
    sid_len = data[off]
    off += 1 + sid_len

    if off + 2 > len(data):
        return

    # Cipher suites
    cs_len = (data[off] << 8) | data[off + 1]
    off += 2
    cs_end = off + cs_len
    suites = []
    while off + 1 < cs_end and off + 1 < len(data):
        suite_id = (data[off] << 8) | data[off + 1]
        name = CIPHER_SUITES.get(suite_id, f"0x{suite_id:04x}")
        suites.append(name)
        off += 2
    if suites:
        info["quic_tls_ciphers"] = suites[:20]
    off = cs_end

    if off >= len(data):
        return

    # Compression methods
    comp_len = data[off]
    off += 1 + comp_len

    if off + 2 > len(data):
        return

    # Extensions
    ext_total = (data[off] << 8) | data[off + 1]
    off += 2
    ext_end = min(off + ext_total, len(data))

    while off + 4 <= ext_end:
        ext_type = (data[off] << 8) | data[off + 1]
        ext_len = (data[off + 2] << 8) | data[off + 3]
        ext_data_start = off + 4
        ext_data_end = ext_data_start + ext_len

        if ext_type == 0x0000:
            # Server Name Indication (SNI)
            _parse_sni(data, ext_data_start, ext_data_end, info)

        elif ext_type == 0x0010:
            # ALPN
            _parse_alpn(data, ext_data_start, ext_data_end, info)

        elif ext_type == 0x002b:
            # Supported Versions
            _parse_supported_versions(data, ext_data_start, ext_data_end, info)

        off = ext_data_end

    return


def _parse_sni(data: bytes, start: int, end: int, info: Dict[str, Any]) -> None:
    """Parse SNI extension data."""
    if start + 2 > end:
        return
    sni_list_len = (data[start] << 8) | data[start + 1]
    off = start + 2
    sni_end = min(off + sni_list_len, end)
    while off + 3 <= sni_end:
        name_type = data[off]
        name_len = (data[off + 1] << 8) | data[off + 2]
        off += 3
        if name_type == 0 and off + name_len <= sni_end:
            sni = data[off:off + name_len].decode(errors="replace")
            info["quic_sni"] = sni
            return
        off += name_len


def _parse_alpn(data: bytes, start: int, end: int, info: Dict[str, Any]) -> None:
    """Parse ALPN extension data."""
    if start + 2 > end:
        return
    alpn_list_len = (data[start] << 8) | data[start + 1]
    off = start + 2
    alpn_end = min(off + alpn_list_len, end)
    protocols = []
    while off < alpn_end:
        proto_len = data[off]
        off += 1
        if off + proto_len <= alpn_end:
            protocols.append(data[off:off + proto_len].decode(errors="replace"))
        off += proto_len
    if protocols:
        info["quic_alpn"] = protocols


def _parse_supported_versions(data: bytes, start: int, end: int, info: Dict[str, Any]) -> None:
    """Parse Supported Versions extension from ClientHello."""
    if start >= end:
        return
    list_len = data[start]
    off = start + 1
    versions = []
    ver_end = min(off + list_len, end)
    _TLS_VERSIONS = {0x0304: "TLS 1.3", 0x0303: "TLS 1.2", 0x0302: "TLS 1.1", 0x0301: "TLS 1.0"}
    while off + 1 < ver_end:
        v = (data[off] << 8) | data[off + 1]
        versions.append(_TLS_VERSIONS.get(v, f"0x{v:04x}"))
        off += 2
    if versions:
        info["quic_tls_versions"] = versions
