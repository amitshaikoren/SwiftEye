"""
SwiftEye — Backend Constants

Single source of truth for all protocol definitions, colours, and lookup tables
used across the backend. Import from here, not from parser.protocols.ports or
research.__init__.

Usage:
    from constants import PROTOCOL_COLORS, WELL_KNOWN_PORTS, TCP_FLAG_BITS
    from constants import ICMP_TYPES, CIPHER_SUITES, SWIFTEYE_LAYOUT
"""

from typing import Dict

# ── Port → Protocol name ──────────────────────────────────────────────────────
WELL_KNOWN_PORTS: Dict[int, str] = {
    # File transfer
    20: "FTP-DATA", 21: "FTP", 69: "TFTP", 115: "SFTP",
    # Remote access
    22: "SSH", 23: "TELNET", 3389: "RDP", 5900: "VNC", 5901: "VNC",
    # Email
    25: "SMTP", 110: "POP3", 143: "IMAP",
    465: "SMTPS", 587: "SMTP-SUB", 993: "IMAPS", 995: "POP3S",
    # DNS
    53: "DNS", 5353: "mDNS",
    # Web
    80: "HTTP", 443: "HTTPS",
    8080: "HTTP-ALT", 8443: "HTTPS-ALT", 8888: "HTTP-ALT2", 8000: "HTTP-ALT3",
    3000: "HTTP-DEV", 5000: "HTTP-DEV2", 9090: "HTTP-MGMT",
    # DHCP / Network management
    67: "DHCP", 68: "DHCP", 123: "NTP", 161: "SNMP", 162: "SNMP-TRAP",
    514: "SYSLOG", 520: "RIP", 1900: "SSDP/UPnP",
    # Directory services
    88: "Kerberos", 389: "LDAP", 636: "LDAPS",
    137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN",
    # File sharing
    445: "SMB", 111: "RPC", 2049: "NFS",
    # Databases
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 27017: "MongoDB", 11211: "Memcached",
    9200: "Elasticsearch", 9300: "ES-Transport",
    5984: "CouchDB", 7000: "Cassandra", 7001: "Cassandra-SSL",
    # Message queues
    5672: "AMQP", 5671: "AMQPS", 1883: "MQTT", 8883: "MQTTS",
    9092: "Kafka", 6650: "Pulsar",
    # Container / orchestration
    2375: "Docker", 2376: "Docker-TLS", 6443: "K8s-API",
    2379: "etcd", 2380: "etcd-peer", 10250: "Kubelet",
    # Monitoring / logging
    3100: "Loki", 4317: "OTLP-gRPC", 4318: "OTLP-HTTP",
    8125: "StatsD", 9093: "Alertmanager",
    # CI/CD
    8081: "Nexus", 50000: "Jenkins-Agent",
    # Proxy / VPN
    1080: "SOCKS", 3128: "Squid", 8118: "Privoxy",
    1194: "OpenVPN", 500: "IKE", 4500: "IPSec-NAT",
    1701: "L2TP", 1723: "PPTP", 51820: "WireGuard",
    # VoIP
    5060: "SIP", 5061: "SIPS", 3478: "STUN/TURN",
    # Other
    873: "Rsync", 6660: "IRC", 6667: "IRC", 6697: "IRC-TLS",
    9418: "Git",
}

# ── Protocol → Display colour ─────────────────────────────────────────────────
# Used by graph edges, research charts, and the protocols API endpoint.
PROTOCOL_COLORS: Dict[str, str] = {
    # Transport
    "TCP": "#6ee7b7", "UDP": "#f97316", "ICMP": "#fb7185", "ICMPv6": "#f43f5e", "ARP": "#c084fc",
    # Web
    "HTTP": "#22d3ee", "HTTPS": "#38bdf8", "HTTP-ALT": "#22d3ee", "HTTPS-ALT": "#38bdf8",
    "HTTP-ALT2": "#22d3ee", "HTTP-ALT3": "#22d3ee", "HTTP-DEV": "#22d3ee", "HTTP-DEV2": "#22d3ee",
    "HTTP-MGMT": "#22d3ee",
    # TLS
    "TLS": "#2dd4bf",
    # DNS
    "DNS": "#fbbf24", "mDNS": "#fbbf24",
    # Email
    "SMTP": "#60a5fa", "SMTP-SUB": "#60a5fa", "SMTPS": "#60a5fa",
    "POP3": "#60a5fa", "POP3S": "#60a5fa", "IMAP": "#60a5fa", "IMAPS": "#60a5fa",
    # Remote access
    "SSH": "#34d399", "TELNET": "#f472b6", "RDP": "#818cf8", "VNC": "#06b6d4",
    # File transfer
    "FTP": "#fb923c", "FTP-DATA": "#fb923c", "TFTP": "#fb923c", "SFTP": "#fb923c",
    "SMB": "#a78bfa", "NFS": "#a78bfa",
    # Network management
    "NTP": "#94a3b8", "DHCP": "#e879f9", "SNMP": "#a3e635", "SNMP-TRAP": "#a3e635",
    "SYSLOG": "#84cc16", "SSDP/UPnP": "#94a3b8",
    # Directory
    "LDAP": "#818cf8", "LDAPS": "#818cf8", "Kerberos": "#c084fc",
    "NetBIOS-NS": "#94a3b8", "NetBIOS-DGM": "#94a3b8", "NetBIOS-SSN": "#94a3b8",
    # Databases
    "MySQL": "#4ade80", "PostgreSQL": "#22c55e", "Redis": "#ef4444", "MongoDB": "#22c55e",
    "MSSQL": "#0ea5e9", "Oracle": "#dc2626", "Elasticsearch": "#eab308",
    "Memcached": "#94a3b8", "CouchDB": "#ef4444", "Cassandra": "#22c55e", "Cassandra-SSL": "#22c55e",
    # Message queues
    "AMQP": "#f97316", "AMQPS": "#f97316", "MQTT": "#22d3ee", "MQTTS": "#22d3ee",
    "Kafka": "#64748b", "Pulsar": "#818cf8",
    # Container
    "Docker": "#0ea5e9", "Docker-TLS": "#0ea5e9", "K8s-API": "#326ce5",
    "etcd": "#94a3b8", "etcd-peer": "#94a3b8", "Kubelet": "#326ce5",
    # VPN / Proxy
    "OpenVPN": "#34d399", "WireGuard": "#34d399", "IKE": "#94a3b8", "IPSec-NAT": "#94a3b8",
    "SOCKS": "#94a3b8", "Squid": "#94a3b8",
    # VoIP
    "SIP": "#e879f9", "SIPS": "#e879f9", "STUN/TURN": "#94a3b8",
    # Other
    "IRC": "#f472b6", "IRC-TLS": "#f472b6", "Git": "#f97316", "Rsync": "#94a3b8",
    "OTHER": "#64748b",
}

# ── TCP flag definitions ───────────────────────────────────────────────────────
TCP_FLAG_NAMES: Dict[str, str] = {
    "F": "FIN", "S": "SYN", "R": "RST", "P": "PSH",
    "A": "ACK", "U": "URG", "E": "ECE", "C": "CWR",
}

TCP_FLAG_BITS: Dict[str, int] = {
    "FIN": 0x01, "SYN": 0x02, "RST": 0x04, "PSH": 0x08,
    "ACK": 0x10, "URG": 0x20, "ECE": 0x40, "CWR": 0x80,
}

# ── ICMP type → name ──────────────────────────────────────────────────────────
ICMP_TYPES: Dict[int, str] = {
    0: "Echo Reply", 3: "Destination Unreachable", 4: "Source Quench",
    5: "Redirect", 8: "Echo Request", 9: "Router Advertisement",
    10: "Router Solicitation", 11: "Time Exceeded", 12: "Parameter Problem",
    13: "Timestamp Request", 14: "Timestamp Reply", 17: "Address Mask Request",
    18: "Address Mask Reply", 30: "Traceroute",
}

ICMP_DEST_UNREACH_CODES: Dict[int, str] = {
    0: "Network Unreachable", 1: "Host Unreachable", 2: "Protocol Unreachable",
    3: "Port Unreachable", 4: "Fragmentation Needed", 5: "Source Route Failed",
    6: "Destination Network Unknown", 7: "Destination Host Unknown",
    9: "Network Administratively Prohibited", 10: "Host Administratively Prohibited",
    13: "Communication Administratively Prohibited",
}

# ── TLS cipher suite names ────────────────────────────────────────────────────
CIPHER_SUITES: Dict[int, str] = {
    0x1301: "AES_128_GCM_SHA256", 0x1302: "AES_256_GCM_SHA384",
    0x1303: "CHACHA20_POLY1305_SHA256",
    0xc02c: "ECDHE_ECDSA_AES256_GCM", 0xc02b: "ECDHE_ECDSA_AES128_GCM",
    0xc030: "ECDHE_RSA_AES256_GCM", 0xc02f: "ECDHE_RSA_AES128_GCM",
    0xcca9: "ECDHE_ECDSA_CHACHA20", 0xcca8: "ECDHE_RSA_CHACHA20",
    0xc013: "ECDHE_RSA_AES128_CBC", 0xc014: "ECDHE_RSA_AES256_CBC",
    0x009c: "RSA_AES128_GCM", 0x009d: "RSA_AES256_GCM",
    0x002f: "RSA_AES128_CBC", 0x0035: "RSA_AES256_CBC",
}

# ── Plotly dark theme ─────────────────────────────────────────────────────────
# Merge into every research chart figure layout for visual consistency:
#   fig.update_layout(SWIFTEYE_LAYOUT)
SWIFTEYE_LAYOUT: Dict = {
    "paper_bgcolor": "#0e1117",
    "plot_bgcolor":  "#0e1117",
    "font": {
        "family": "JetBrains Mono, Fira Code, monospace",
        "color":  "#8b949e",
        "size":   11,
    },
    "xaxis": {
        "gridcolor":     "#1c2333",
        "linecolor":     "#21262d",
        "tickcolor":     "#21262d",
        "zerolinecolor": "#21262d",
    },
    "yaxis": {
        "gridcolor":     "#1c2333",
        "linecolor":     "#21262d",
        "tickcolor":     "#21262d",
        "zerolinecolor": "#21262d",
    },
    "margin":    {"l": 60, "r": 20, "t": 40, "b": 50},
    "hoverlabel": {
        "bgcolor":    "#1c2333",
        "bordercolor": "#30363d",
        "font": {
            "family": "JetBrains Mono, monospace",
            "color":  "#e6edf3",
            "size":   11,
        },
    },
    "legend": {
        "bgcolor":     "rgba(0,0,0,0)",
        "bordercolor": "#21262d",
        "borderwidth": 1,
        "font": {"color": "#8b949e", "size": 10},
    },
}
