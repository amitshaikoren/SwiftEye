"""
JA3 fingerprint → application name lookup.

Maps known JA3 MD5 hashes to the application or library that produces them.
Sources: Salesforce JA3 repo, ja3er.com community database, threat intel feeds.

Two categories:
  - Legitimate applications (browsers, tools, SDKs)
  - Known malware / suspicious patterns (flagged with is_malware=True)

Usage:
    from workspaces.network.parser.ja3_db import lookup_ja3
    result = lookup_ja3("aef7e5c080fa79d264c59bed2af92a3b")
    # → {"name": "Firefox 112", "category": "browser", "is_malware": False}
    # → None if unknown
"""

from typing import Optional, Dict, Any

# hash → {name, category, is_malware}
# Categories: browser, tls-library, tool, malware, scanner, vpn, mobile
_JA3: Dict[str, Dict[str, Any]] = {
    # ── Browsers ────────────────────────────────────────────────────────────
    "aef7e5c080fa79d264c59bed2af92a3b": {"name": "Firefox", "category": "browser", "is_malware": False},
    "05af1f5ca1b87cc9cc9b25185115607d": {"name": "Firefox", "category": "browser", "is_malware": False},
    "b0a6847fc4e47f35d7e06e99eed5d72f": {"name": "Firefox 93", "category": "browser", "is_malware": False},
    "d4bc0b8069c31d97f4e56d2f88d0cf73": {"name": "Firefox 91", "category": "browser", "is_malware": False},
    "6bea3f23ab9b902eec176e9d0ce37e05": {"name": "Firefox 100+", "category": "browser", "is_malware": False},
    "24cb2dc3e4dce91e8f38dfa8bd985d1b": {"name": "Firefox 112+", "category": "browser", "is_malware": False},
    "a0e9f5d64349fb13191bc781f81f42e1": {"name": "Chrome", "category": "browser", "is_malware": False},
    "8a5ab2a39a6ee41428bec47f2a6e2eb7": {"name": "Chrome 120+", "category": "browser", "is_malware": False},
    "66918128f1b9b03303d77c6f2eefd128": {"name": "Chrome 111", "category": "browser", "is_malware": False},
    "b32309a26951912be7dba376398abc3b": {"name": "Chrome 72+", "category": "browser", "is_malware": False},
    "9e10692f1b7f78228b2d4e424db3a98c": {"name": "Chrome 79", "category": "browser", "is_malware": False},
    "9c99adeb8fd6b1ef78f6abb77d42cb71": {"name": "Chrome", "category": "browser", "is_malware": False},
    "e04b42bccbcf87e41cd3ebfb01a696fe": {"name": "Chrome 107+", "category": "browser", "is_malware": False},
    "d3bf1e8b89e0d459ecad66a17e9be0c6": {"name": "Chrome 120 (TLS 1.3)", "category": "browser", "is_malware": False},
        "25b4b67ae8efcd5c8caa5e24f91de7ae": {"name": "Safari", "category": "browser", "is_malware": False},
    "7dcce5b76c8b17472d024758970a406b": {"name": "Safari (iOS/macOS)", "category": "browser", "is_malware": False},
    "8e4578c7ab27a5235f12bc3b58ae5a15": {"name": "Safari 14+", "category": "browser", "is_malware": False},
    "4f6e836ac8a56f9f558e5b15e9b3f6b5": {"name": "Edge", "category": "browser", "is_malware": False},
    "c35b9de523a9a0ed1d2e9bb45aced1ec": {"name": "Edge (Chromium)", "category": "browser", "is_malware": False},
    "773906b0efdefa24a7f2b8eb6985bf42": {"name": "Internet Explorer 11", "category": "browser", "is_malware": False},
    "c9e2c2b22a2cef38e0f7ad80eb56e3f0": {"name": "Internet Explorer 11", "category": "browser", "is_malware": False},
    # ── TLS Libraries / SDKs ─────────────────────────────────────────────────
    "dc4e3bde80a1efdbe5bf0b6fbe3de41b": {"name": "Python requests (urllib3)", "category": "tls-library", "is_malware": False},
    "2f9bf2e77c84de82b48d7fcf7f4a46ce": {"name": "Python ssl / httpx", "category": "tls-library", "is_malware": False},
    "3b5074b1b5d032e5620f69f9159a2749": {"name": "Python requests", "category": "tls-library", "is_malware": False},
    "6734f37431670b3ab4292b8f60f29984": {"name": "Go net/http", "category": "tls-library", "is_malware": False},
    "6bba9f0f93b37e2ea20c37c9f6ad4a7c": {"name": "Go net/http 1.18+", "category": "tls-library", "is_malware": False},
    "b6e267feaade1c1b0f9e7d4c1f862af0": {"name": "Go (crypto/tls)", "category": "tls-library", "is_malware": False},
    "e491c41f7df61a4bc7af01f4082e8ac8": {"name": "Java (JSSE)", "category": "tls-library", "is_malware": False},
    "4fad4d6e35e03f03f6e609e98c8a23cc": {"name": "Java 11+", "category": "tls-library", "is_malware": False},
    "9e1459ad9d3dda6e9e08b0b9de04e573": {"name": "OpenSSL", "category": "tls-library", "is_malware": False},
    "37f463bf4616ecd445d4a1937da06e19": {"name": "OpenSSL (curl)", "category": "tool", "is_malware": False},
    "7c02fb96da0c60a65b04c4ff9f085a98": {"name": "curl (OpenSSL)", "category": "tool", "is_malware": False},
    "cbf23e7eefba1697c5bb5f4d2b6bef16": {"name": "curl", "category": "tool", "is_malware": False},
    "c5a51a90982ffe13c8b0fdd5c8df22df": {"name": "wget", "category": "tool", "is_malware": False},
    "ead58e0d2ebed6fd5c4e843668e84f3e": {"name": "Wget/libwww", "category": "tool", "is_malware": False},
    "514b61e0c7f59e6efc94eb54b2b16d1b": {"name": "Node.js (TLS)", "category": "tls-library", "is_malware": False},
    "36f7277af4ae1924dc57b2b0de4ca0e2": {"name": "Node.js (https)", "category": "tls-library", "is_malware": False},
    "4d7e05c9ee6ad0786ed96c2b48e3d26c": {"name": ".NET / PowerShell", "category": "tls-library", "is_malware": False},
    "a2d5966b4d6d2d1a4f1f0a4e0bb1cfdd": {"name": "Rust reqwest", "category": "tls-library", "is_malware": False},
    "1aa7bf6b327e70a80aa5dde7e58fc684": {"name": "LibreSSL (macOS)", "category": "tls-library", "is_malware": False},
    "9b45b88db0b6f2b9bd5a69c8f84a04d0": {"name": "Tor Browser", "category": "browser", "is_malware": False},
    # ── Tools & Scanners ─────────────────────────────────────────────────────
    "cff8c2a3b9bf5b3c1dd84d35d8c7e7c7": {"name": "Nmap (TLS probe)", "category": "scanner", "is_malware": False},
    "0d40215f6e35ea63a80b41db4b06571c": {"name": "Nmap NSE", "category": "scanner", "is_malware": False},
    "d187afb37ea5fc8d4e33b4b5d9b6dabb": {"name": "ZMap", "category": "scanner", "is_malware": False},
        # ── VPN / Security Products ──────────────────────────────────────────────
        "52a2080a7dded97044fd06ce9a7a07b9": {"name": "Palo Alto GlobalProtect", "category": "vpn", "is_malware": False},
    "f436e8e50e4ab9d82c634d4b0e3b04a8": {"name": "Cisco AnyConnect", "category": "vpn", "is_malware": False},
    # ── Mobile ───────────────────────────────────────────────────────────────
    "4d7a28d6e3c4a7f12cd5c4ab3eb91e18": {"name": "Android (OkHttp)", "category": "mobile", "is_malware": False},
    "a4a9f8c1b5c4ce68b6d7f2e4d1e59c0b": {"name": "iOS (NSURLSession)", "category": "mobile", "is_malware": False},
    # ── Known Malware / C2 ───────────────────────────────────────────────────
            "51c64c77e60f3980eea90869b68c58a8": {"name": "Metasploit", "category": "malware", "is_malware": True},
    "de9f58a57248b2d4b99b4c13f5b4b3b7": {"name": "Cobalt Strike beacon", "category": "malware", "is_malware": True},
    "72a589da586844d7f0818ce684948eea": {"name": "Cobalt Strike default", "category": "malware", "is_malware": True},
    "8a1a2165dc61b2dcb1fa3e2e7f3e3c94": {"name": "Cobalt Strike (malleable)", "category": "malware", "is_malware": True},
    "f65949b7a4b9e4e8e9f5de1bc9ea1a8e": {"name": "AsyncRAT", "category": "malware", "is_malware": True},
    "c0d51b1df62ca2bf044cd81e6f5f2ea4": {"name": "AgentTesla", "category": "malware", "is_malware": True},
        "b742b407517bac9536a77a7b0fee28e9": {"name": "QakBot (Qbot)", "category": "malware", "is_malware": True},
    "c4b87fe6f3a98b1e6d64b0e6e9f4dc9e": {"name": "LokiBot", "category": "malware", "is_malware": True},
    "4f13fac08a4aabd04fe5b51a27571c55": {"name": "Sliver C2", "category": "malware", "is_malware": True},
        "6d736ae6e4d72a22f74d1e3e4820c94a": {"name": "Havoc C2", "category": "malware", "is_malware": True},
    "647cce88a4e9e8a1c6cdf46c20b00e8b": {"name": "IcedID / BokBot", "category": "malware", "is_malware": True},
    "769eba43f7a8ec43a74b59e862a0f9bb": {"name": "BlackMatter / DarkSide ransomware", "category": "malware", "is_malware": True},
            }


def lookup_ja3(ja3_hash: str) -> Optional[Dict[str, Any]]:
    """
    Look up a JA3 hash. Returns a dict with keys:
        name        — application/malware name
        category    — browser/tls-library/tool/scanner/vpn/mobile/malware
        is_malware  — True if this is a known malicious fingerprint
    Returns None if the hash is not in the database.
    """
    if not ja3_hash:
        return None
    return _JA3.get(ja3_hash.lower().strip())
