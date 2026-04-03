# SwiftEye — Data Schema Reference

> **Audience:** Researchers writing plugins, analysis scripts, or research charts.  
> This document describes the exact shape of every object you receive through `ctx`, and what fields each protocol contributes to nodes, edges, and sessions.

---

## How data flows

```
pcap/adapter
    └─► PacketRecord  (pkt)            parser layer
            └─► Session dict  (s)      sessions.py + protocol_fields/
            └─► Node dict     (n)      aggregator.py
            └─► Edge dict     (e)      aggregator.py
                    └─► AnalysisContext (ctx)   plugins + research charts
```

All three objects are available in `ctx`:

```python
ctx.packets   # List[PacketRecord]   — raw normalized packets
ctx.sessions  # List[dict]           — reconstructed sessions
ctx.nodes     # List[dict]           — graph nodes (may be empty if chart is packet-only)
ctx.edges     # List[dict]           — graph edges (may be empty if chart is packet-only)
ctx.time_range  # (t_start, t_end) | None
```

---

## PacketRecord (`pkt`)

Every packet is a `PacketRecord` dataclass. Access fields as attributes.

### Base fields (always present)

```python
pkt.timestamp       # float   — Unix epoch seconds (e.g. 1712000000.123)
pkt.src_ip          # str     — "192.168.1.5"
pkt.dst_ip          # str     — "8.8.8.8"
pkt.src_port        # int     — 54321
pkt.dst_port        # int     — 443
pkt.transport       # str     — "TCP" | "UDP" | "ICMP" | ...
pkt.protocol        # str     — resolved app protocol: "HTTP" | "DNS" | "TLS" | ...
pkt.orig_len        # int     — total packet length in bytes
pkt.payload_len     # int     — application payload bytes
pkt.ip_version      # int     — 4 or 6
pkt.ttl             # int     — IP TTL
pkt.src_mac         # str     — "aa:bb:cc:dd:ee:ff"
pkt.dst_mac         # str     — "11:22:33:44:55:66"

# TCP-specific
pkt.tcp_flags       # int     — raw flag byte
pkt.tcp_flags_str   # str     — "SYN ACK"
pkt.tcp_flags_list  # list    — ["SYN", "ACK"]
pkt.seq_num         # int
pkt.ack_num         # int
pkt.window_size     # int

# ICMP
pkt.icmp_type       # int     — -1 if not ICMP
pkt.icmp_code       # int     — -1 if not ICMP

# Protocol detection
pkt.protocol_conflict     # bool  — True if port and payload disagree
pkt.protocol_by_port      # str   — what port-based detection said
pkt.protocol_by_payload   # str   — what payload inspection said
pkt.protocol_confidence   # str   — "port" | "payload" | "port+payload"

# Payload preview (first 128 bytes, raw bytes — serialised to hex+ascii by API)
pkt.payload_preview  # bytes
```

### Protocol-specific fields (`pkt.extra`)

Dissectors write into `pkt.extra` as a dict. Access with `pkt.extra.get("key")`.

> **Note:** `pkt.extra` keys are only present if the dissector fired on that packet. Always use `.get()` with a default.

```python
ex = pkt.extra

# Example: DNS
domain = ex.get("dns_query")       # str | None
qtype  = ex.get("dns_qtype_name")  # "A" | "AAAA" | "MX" | None
qr     = ex.get("dns_qr")          # "query" | "response" | None
answers = ex.get("dns_answers", []) # list[str]

# Example: TLS
sni     = ex.get("tls_sni")            # str | None
version = ex.get("tls_hello_version")  # "TLS 1.3" | None
ciphers = ex.get("tls_cipher_suites", [])  # list[str]
cert    = ex.get("tls_cert")           # dict | None
#   cert["subject_cn"], cert["issuer"], cert["not_after"], cert["sans"]

# Example: HTTP
method = ex.get("http_method")       # "GET" | "POST" | None
uri    = ex.get("http_uri")          # "/api/v2/users" | None
host   = ex.get("http_host")         # "example.com" | None
ua     = ex.get("http_user_agent")   # "Mozilla/5.0 ..." | None
status = ex.get("http_status")       # 200 | 404 | None

# Example: Kerberos
msg_type  = ex.get("krb_msg_type")  # "AS-REQ" | "TGS-REP" | None
realm     = ex.get("krb_realm")     # "CORP.EXAMPLE.COM" | None
cname     = ex.get("krb_cname")     # "alice@CORP.EXAMPLE.COM" | None
sname     = ex.get("krb_sname")     # "cifs/fileserver.corp.example.com" | None
err_name  = ex.get("krb_error_name") # "KDC_ERR_PREAUTH_FAILED" | None
```

Full `pkt.extra` field reference per protocol: see [Protocol extra fields](#protocol-extra-fields-pktextra) below.

### Usage examples

```python
# All DNS queries in ctx
queries = [pkt.extra["dns_query"] for pkt in ctx.packets
           if pkt.protocol == "DNS" and "dns_query" in pkt.extra]

# TLS packets with SNI
tls_snis = {pkt.extra["tls_sni"] for pkt in ctx.packets
            if pkt.extra.get("tls_sni")}

# HTTP POST URIs by source IP
posts = [(pkt.src_ip, pkt.extra["http_uri"])
         for pkt in ctx.packets
         if pkt.extra.get("http_method") == "POST" and pkt.extra.get("http_uri")]

# All Kerberos errors
kerb_errors = [(pkt.src_ip, pkt.extra["krb_error_name"])
               for pkt in ctx.packets
               if pkt.extra.get("krb_error_name")]

# Large packets over 1500 bytes
large = [pkt for pkt in ctx.packets if pkt.orig_len > 1500]
```

---

## Session dict (`s` / `ctx.sessions[i]`)

Sessions are reconstructed from packets and stored as plain dicts. Each session is one bidirectional 5-tuple (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `transport`).

### Base fields (always present)

```python
s["id"]             # str   — "1.2.3.4|5.6.7.8|1234|443|TCP"
s["src_ip"]         # str   — lower IP (sorted for canonical key)
s["dst_ip"]         # str   — higher IP
s["src_port"]       # int
s["dst_port"]       # int
s["protocol"]       # str   — "HTTP" | "DNS" | "TLS" | ...
s["transport"]      # str   — "TCP" | "UDP"
s["packet_count"]   # int
s["total_bytes"]    # int
s["payload_bytes"]  # int
s["start_time"]     # float — Unix epoch
s["end_time"]       # float — Unix epoch
s["duration"]       # float — seconds

# Direction (determined from TCP SYN or first-packet heuristic)
s["initiator_ip"]   # str
s["initiator_port"] # int
s["responder_ip"]   # str
s["responder_port"] # int

# Directional byte/packet counts
s["fwd_packets"]    # int   — initiator → responder
s["fwd_bytes"]      # int
s["rev_packets"]    # int   — responder → initiator
s["rev_bytes"]      # int

# TCP handshake flags
s["has_handshake"]  # bool
s["has_fin"]        # bool
s["has_reset"]      # bool
s["flag_counts"]    # dict  — {"SYN": 3, "ACK": 12, ...}
```

### Protocol-specific session fields

Protocol fields are **lazy** — a session only has them if that protocol was seen. Always use `.get()`.

> Fields are set by `backend/data/protocol_fields/<protocol>.py` and serialised before reaching `ctx.sessions`.

```python
# DNS
s.get("dns_queries", [])       # list[str]   — all queried domains
s.get("dns_qclass_names", [])  # list[str]   — ["IN", ...]

# TLS
s.get("tls_snis", [])                  # list[str]   — SNI hostnames
s.get("tls_versions", [])              # list[str]   — ["TLS 1.3"]
s.get("tls_ciphers", [])               # list[str]   — cipher suites offered
s.get("tls_selected_ciphers", [])      # list[str]   — cipher selected by server
s.get("tls_fwd_alpn_offered", [])      # list[str]   — ["h2", "http/1.1"]
s.get("tls_rev_alpn_selected")         # str | None
s.get("tls_rev_selected_version")      # str | None  — "TLS 1.3"
s.get("tls_cert")                      # dict | None — {subject_cn, issuer, not_before, not_after, sans, serial}
s.get("tls_cert_chain", [])            # list[dict]
s.get("ja3_hashes", [])                # list[str]
s.get("ja4_hashes", [])                # list[str]
s.get("ja3_apps", [])                  # list[dict] — [{hash, name, is_malware}, ...]

# HTTP
s.get("http_hosts", [])                # list[str]
s.get("http_fwd_methods", [])          # list[str]   — ["GET", "POST"]
s.get("http_fwd_uris", [])             # list[str]   — request URIs (capped at 500)
s.get("http_fwd_user_agents", [])      # list[str]
s.get("http_fwd_has_auth")             # bool | None
s.get("http_fwd_auth_types", [])       # list[str]   — ["Bearer", "Basic"]
s.get("http_fwd_usernames", [])        # list[str]   — from Basic auth
s.get("http_rev_status_codes", [])     # list[int]
s.get("http_rev_servers", [])          # list[str]   — Server header values
s.get("http_rev_content_types", [])    # list[str]
s.get("http_rev_redirects", [])        # list[str]   — Location headers

# Kerberos
s.get("krb_msg_types", [])    # list[str]   — ["AS-REQ", "AS-REP", ...]
s.get("krb_realms", [])       # list[str]   — ["CORP.EXAMPLE.COM"]
s.get("krb_cnames", [])       # list[str]   — client principals
s.get("krb_snames", [])       # list[str]   — service principals
s.get("krb_etypes", [])       # list[str]   — encryption types
s.get("krb_error_codes", [])  # list[dict]  — [{code, name, text}, ...]

# SMB
s.get("smb_versions", [])         # list[str]   — ["SMBv2", "SMBv3"]
s.get("smb_fwd_operations", [])   # list[str]   — ["NEGOTIATE", "SESSION_SETUP"]
s.get("smb_tree_paths", [])       # list[str]   — ["\\\\server\\share"]
s.get("smb_filenames", [])        # list[str]   — filenames accessed
s.get("smb_rev_status_codes", []) # list[dict]  — [{code, name}, ...]

# SSH
s.get("ssh_fwd_banners", [])       # list[str]   — "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"
s.get("ssh_rev_banners", [])       # list[str]
s.get("ssh_kex_algorithms", [])    # list[str]
s.get("ssh_encryption_c2s", [])    # list[str]
s.get("ssh_encryption_s2c", [])    # list[str]
s.get("ssh_mac_c2s", [])           # list[str]
s.get("ssh_mac_s2c", [])           # list[str]

# FTP
s.get("ftp_fwd_commands", [])     # list[str]   — ["USER", "RETR", "STOR"]
s.get("ftp_transfer_files", [])   # list[str]   — filenames transferred
s.get("ftp_usernames", [])        # list[str]
s.get("ftp_has_credentials")      # bool | None
s.get("ftp_fwd_transfer_mode")    # "active" | "passive" | None
s.get("ftp_rev_server_banner")    # str | None

# DHCP
s.get("dhcp_hostnames", [])       # list[str]   — Option 12 device names
s.get("dhcp_vendor_classes", [])  # list[str]   — Option 60 vendor class IDs
s.get("dhcp_msg_types", [])       # list[str]   — ["DISCOVER", "OFFER", "ACK"]
s.get("dhcp_dns_servers", [])     # list[str]
s.get("dhcp_routers", [])         # list[str]

# LDAP
s.get("ldap_ops", [])             # list[str]   — ["BindRequest", "SearchRequest"]
s.get("ldap_bind_dns", [])        # list[str]   — Distinguished Names used in binds
s.get("ldap_bind_mechanisms", []) # list[str]   — ["simple", "GSSAPI"]
s.get("ldap_search_bases", [])    # list[str]
s.get("ldap_entry_dns", [])       # list[str]   — DNs returned in search results
s.get("ldap_result_codes", [])    # list[dict]  — [{code, name}, ...]

# SMTP
s.get("smtp_mail_from", [])       # list[str]
s.get("smtp_rcpt_to", [])         # list[str]
s.get("smtp_ehlo_domains", [])    # list[str]
s.get("smtp_auth_mechanisms", []) # list[str]
s.get("smtp_has_auth")            # bool | None
s.get("smtp_has_starttls")        # bool | None
s.get("smtp_banner")              # str | None

# QUIC
s.get("quic_snis", [])            # list[str]
s.get("quic_alpn", [])            # list[str]
s.get("quic_versions", [])        # list[str]   — ["QUIC v1"]
s.get("quic_tls_versions", [])    # list[str]
s.get("quic_tls_ciphers", [])     # list[str]

# DCE/RPC
s.get("dcerpc_interfaces", [])    # list[dict]  — [{uuid, name}, ...]
s.get("dcerpc_operations", [])    # list[str]   — known operation names
s.get("dcerpc_named_pipes", [])   # list[str]
s.get("dcerpc_packet_types", [])  # list[str]

# ARP
s.get("arp_opcodes", [])    # list[dict]  — [{opcode, count}, ...]
s.get("arp_src_macs", [])   # list[str]
s.get("arp_dst_macs", [])   # list[str]
s.get("arp_src_ips", [])    # list[str]
s.get("arp_dst_ips", [])    # list[str]
s.get("arp_broadcast_count") # int | None
```

### Usage examples

```python
# All TLS sessions with a known-malicious JA3
bad = [s for s in ctx.sessions
       if any(a["is_malware"] for a in s.get("ja3_apps", []))]

# Kerberos sessions with pre-auth failures
preauth_fail = [s for s in ctx.sessions
                if any(e.get("name") == "KDC_ERR_PREAUTH_FAILED"
                       for e in s.get("krb_error_codes", []))]

# SMB sessions touching C$ or ADMIN$
admin_shares = [s for s in ctx.sessions
                if any("C$" in p or "ADMIN$" in p
                       for p in s.get("smb_tree_paths", []))]

# HTTP sessions with Basic auth (possible credential exposure)
basic_auth = [s for s in ctx.sessions
              if "Basic" in s.get("http_fwd_auth_types", [])]

# All DHCP vendor class IDs (OS/device fingerprinting)
vendors = {vc for s in ctx.sessions
           for vc in s.get("dhcp_vendor_classes", [])}

# Sessions by duration (longest first)
by_duration = sorted(ctx.sessions, key=lambda s: s.get("duration", 0), reverse=True)
```

---

## Node dict (`n` / `ctx.nodes[i]`)

Nodes represent unique IP endpoints (or subnets/clusters) seen in the capture.

### Fields (always present)

```python
n["id"]            # str        — primary key: "192.168.1.5" | "10.0.0.0/24" | "cluster:3"
n["ips"]           # list[str]  — all IPs mapped to this node
n["macs"]          # list[str]  — MAC addresses seen
n["mac_vendors"]   # list[str]  — OUI vendor lookup results
n["protocols"]     # list[str]  — ["DNS", "HTTP", "TLS"]
n["total_bytes"]   # int
n["packet_count"]  # int
n["is_private"]    # bool
n["is_subnet"]     # bool       — True if this is a subnet group node
n["hostnames"]     # list[str]  — reverse DNS / DNS answer names
n["ttls_out"]      # list[int]  — TTLs from packets sent by this node
n["ttls_in"]       # list[int]  — TTLs from packets received by this node
n["top_dst_ports"] # list       — [[port, count], ...] most-used dest ports
n["top_src_ports"] # list       — [[port, count], ...]
n["top_neighbors"] # list       — [[ip, bytes], ...]
n["top_protocols"] # list       — [[protocol, bytes], ...]
n["metadata"]      # dict | None — from metadata overlay file {name, role, ...}
```

### Cluster/subnet node additional fields

```python
n["is_cluster"]   # bool        — True for cluster nodes
n["cluster_id"]   # int | None
n["member_count"] # int | None  — number of IPs collapsed into this cluster
```

### Usage examples

```python
# External nodes only
external = [n for n in ctx.nodes if not n["is_private"] and not n["is_subnet"]]

# Nodes that speak Kerberos
kerberos_nodes = [n for n in ctx.nodes if "Kerberos" in n["protocols"]]

# Nodes with a known hostname
named = {n["id"]: n["hostnames"][0] for n in ctx.nodes if n["hostnames"]}

# Top talker by bytes
top = max(ctx.nodes, key=lambda n: n["total_bytes"])

# Nodes that only use one protocol
single_proto = [n for n in ctx.nodes if len(n["protocols"]) == 1]
```

---

## Edge dict (`e` / `ctx.edges[i]`)

Edges represent a directional conversation between two nodes **per protocol**. Two nodes can have multiple edges if they communicate over multiple protocols.

### Fields (always present)

```python
e["id"]          # str        — "src_ip||dst_ip||PROTOCOL"
e["source"]      # str        — source node ID
e["target"]      # str        — target node ID
e["protocol"]    # str        — "HTTP" | "DNS" | "TLS" | ...
e["total_bytes"] # int
e["packet_count"]# int
e["first_seen"]  # float      — Unix epoch
e["last_seen"]   # float      — Unix epoch
e["ports"]       # list[int]  — all ports used on this edge

# Aggregated from pkt.extra by the aggregator (protocol-specific, but at edge level)
e["tls_snis"]            # list[str]  — SNI hostnames seen on this edge
e["tls_versions"]        # list[str]  — TLS versions negotiated
e["tls_ciphers"]         # list[str]  — cipher suites offered (capped at 15)
e["tls_selected_ciphers"]# list[str]
e["http_hosts"]          # list[str]  — HTTP Host headers
e["dns_queries"]         # list[str]  — DNS queries (capped at 30)
e["ja3_hashes"]          # list[str]
e["ja4_hashes"]          # list[str]

# Protocol conflict (optional — only when port/payload disagree)
e["protocol_conflict"]   # bool
e["protocol_by_port"]    # list[str]
e["protocol_by_payload"] # list[str]
```

> **Note:** Edge-level fields are a subset of what sessions carry. For full protocol detail (Kerberos realms, SMB filenames, HTTP URIs, etc.) iterate `ctx.sessions` filtered by the edge's endpoints and protocol.

### Usage examples

```python
# Edges with TLS to unexpected destinations
suspicious_tls = [e for e in ctx.edges
                  if e["protocol"] == "TLS" and e["tls_snis"]
                  and not any("corp.example.com" in sni for sni in e["tls_snis"])]

# High-volume edges (> 100 MB)
heavy = [e for e in ctx.edges if e["total_bytes"] > 100 * 1024 * 1024]

# DNS edges by query count (highest first)
dns_edges = sorted([e for e in ctx.edges if e["protocol"] == "DNS"],
                   key=lambda e: len(e["dns_queries"]), reverse=True)

# Protocol conflicts
conflicts = [e for e in ctx.edges if e.get("protocol_conflict")]

# All unique JA3 hashes across all edges
all_ja3 = {h for e in ctx.edges for h in e["ja3_hashes"]}

# Get full session detail for a specific edge
src, tgt = "192.168.1.5", "10.0.0.1"
edge_sessions = [s for s in ctx.sessions
                 if s["src_ip"] in (src, tgt) and s["dst_ip"] in (src, tgt)
                 and s["protocol"] == "SMB"]
```

---

## Protocol extra fields (`pkt.extra`)

Complete per-protocol field reference. All accessed via `pkt.extra.get("key")`.

### DNS
| Field | Type | Example |
|---|---|---|
| `dns_query` | str | `"example.com"` |
| `dns_qr` | str | `"query"` / `"response"` |
| `dns_qtype_name` | str | `"A"` / `"AAAA"` / `"MX"` / `"TXT"` |
| `dns_qtype` | int | `1` |
| `dns_rcode_name` | str | `"NOERROR"` / `"NXDOMAIN"` / `"SERVFAIL"` |
| `dns_rcode` | int | `0` |
| `dns_aa` | bool | `False` |
| `dns_rd` | bool | `True` |
| `dns_answers` | list[str] | `["93.184.216.34"]` |
| `dns_answer_records` | list[dict] | `[{name, type_name, ttl, data}]` |
| `dns_id` | int | `0xABCD` |

### TLS
| Field | Type | Example |
|---|---|---|
| `tls_sni` | str | `"api.example.com"` |
| `tls_hello_version` | str | `"TLS 1.3"` |
| `tls_msg_type` | str | `"ClientHello"` / `"ServerHello"` / `"Certificate"` |
| `tls_selected_cipher` | str | `"TLS_AES_256_GCM_SHA384"` |
| `tls_cipher_suites` | list[str] | `["TLS_AES_128_GCM_SHA256", ...]` |
| `tls_alpn_offered` | list[str] | `["h2", "http/1.1"]` |
| `tls_alpn_selected` | str | `"h2"` |
| `tls_cert` | dict | `{subject_cn, issuer, not_before, not_after, sans, serial}` |
| `tls_cert_chain` | list[dict] | `[{subject_cn, issuer, serial}, ...]` |
| `tls_supported_versions` | list[str] | `["TLS 1.3", "TLS 1.2"]` |

### HTTP
| Field | Type | Example |
|---|---|---|
| `http_method` | str | `"GET"` / `"POST"` |
| `http_uri` | str | `"/api/v2/login"` |
| `http_host` | str | `"api.example.com"` |
| `http_user_agent` | str | `"Mozilla/5.0 (Windows NT 10.0; Win64)"` |
| `http_status` | int | `200` / `404` / `302` |
| `http_authorization` | str | `"Bearer eyJ..."` |
| `http_content_type` | str | `"application/json"` |
| `http_server` | str | `"nginx/1.18.0"` |
| `http_location` | str | `"https://other.example.com/path"` |

### Kerberos
| Field | Type | Example |
|---|---|---|
| `krb_msg_type` | str | `"AS-REQ"` / `"TGS-REP"` / `"KRB-ERROR"` |
| `krb_realm` | str | `"CORP.EXAMPLE.COM"` |
| `krb_cname` | str | `"alice@CORP.EXAMPLE.COM"` |
| `krb_sname` | str | `"cifs/fileserver.corp.example.com"` |
| `krb_error_name` | str | `"KDC_ERR_PREAUTH_FAILED"` |
| `krb_error_code` | int | `25` |
| `krb_etypes` | list[str] | `["aes256-cts-hmac-sha1-96", "rc4-hmac"]` |

### SMB
| Field | Type | Example |
|---|---|---|
| `smb_version` | str | `"SMBv2"` / `"SMBv3"` |
| `smb_command` | str | `"TREE_CONNECT"` / `"CREATE"` / `"READ"` |
| `smb_tree_path` | str | `"\\\\dc01\\SYSVOL"` |
| `smb_filename` | str | `"secret.docx"` |
| `smb_status_name` | str | `"STATUS_SUCCESS"` / `"STATUS_ACCESS_DENIED"` |
| `smb_dialect` | str | `"3.1.1"` |
| `smb_is_request` | bool | `True` |

### SSH
| Field | Type | Example |
|---|---|---|
| `ssh_banner` | str | `"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"` |
| `ssh_proto_version` | str | `"2.0"` |
| `ssh_software` | str | `"OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"` |
| `ssh_software_name` | str | `"OpenSSH_8.9p1"` |
| `ssh_kex_algorithms` | list[str] | `["curve25519-sha256", "ecdh-sha2-nistp256"]` |
| `ssh_encryption_client_to_server` | list[str] | `["chacha20-poly1305@openssh.com"]` |
| `ssh_host_key_algorithms` | list[str] | `["ssh-ed25519"]` |

### DHCP
| Field | Type | Example |
|---|---|---|
| `dhcp_msg_type` | str | `"DISCOVER"` / `"OFFER"` / `"ACK"` |
| `dhcp_hostname` | str | `"alice-laptop"` |
| `dhcp_vendor_class` | str | `"MSFT 5.0"` / `"dhcpcd-5.5.6"` |
| `dhcp_offered_ip` | str | `"192.168.1.42"` |
| `dhcp_param_list` | list[int] | `[1, 3, 6, 15, 28, 51]` |
| `dhcp_dns_servers` | list[str] | `["8.8.8.8", "8.8.4.4"]` |
| `dhcp_lease_time` | int | `86400` |

### LDAP
| Field | Type | Example |
|---|---|---|
| `ldap_op` | str | `"BindRequest"` / `"SearchRequest"` / `"SearchResultEntry"` |
| `ldap_bind_dn` | str | `"CN=alice,DC=corp,DC=example,DC=com"` |
| `ldap_bind_mechanism` | str | `"simple"` / `"GSSAPI"` |
| `ldap_search_base` | str | `"DC=corp,DC=example,DC=com"` |
| `ldap_search_scope` | str | `"sub"` / `"one"` / `"base"` |
| `ldap_result_name` | str | `"success"` / `"invalidCredentials"` |
| `ldap_attributes` | list[str] | `["sAMAccountName", "memberOf"]` |

### ICMP
| Field | Type | Example |
|---|---|---|
| `icmp_type_name` | str | `"Echo Request"` / `"Destination Unreachable"` / `"Time Exceeded"` |
| `icmp_code_name` | str | `"TTL Exceeded in Transit"` |
| `icmp_type` | int | `0` / `3` / `11` |
| `icmp_code` | int | `0` |
| `icmp_id` | int | `1234` |
| `icmp_seq` | int | `7` |
| `icmp_orig_dst` | str | `"8.8.8.8"` (from encapsulated packet, type 3/11) |

### FTP
| Field | Type | Example |
|---|---|---|
| `ftp_command` | str | `"USER"` / `"RETR"` / `"STOR"` |
| `ftp_arg` | str | `"alice"` / `"***"` (password redacted) |
| `ftp_username` | str | `"alice"` |
| `ftp_transfer_file` | str | `"report.pdf"` |
| `ftp_response_code` | int | `220` / `230` / `530` |
| `ftp_has_credentials` | bool | `True` |
| `ftp_transfer_mode` | str | `"passive"` |

### QUIC
| Field | Type | Example |
|---|---|---|
| `quic_sni` | str | `"youtube.com"` |
| `quic_alpn` | list[str] | `["h3"]` |
| `quic_version_name` | str | `"QUIC v1"` |
| `quic_packet_type` | str | `"Initial"` / `"Handshake"` |
| `quic_tls_ciphers` | list[str] | `["TLS_AES_128_GCM_SHA256"]` |

### SMTP
| Field | Type | Example |
|---|---|---|
| `smtp_command` | str | `"EHLO"` / `"MAIL"` / `"AUTH"` |
| `smtp_mail_from` | str | `"alice@example.com"` |
| `smtp_rcpt_to` | str | `"bob@example.com"` |
| `smtp_banner` | str | `"mail.example.com ESMTP Postfix"` |
| `smtp_auth_mechanism` | str | `"PLAIN"` / `"LOGIN"` |
| `smtp_has_starttls` | bool | `True` |

### DCE/RPC
| Field | Type | Example |
|---|---|---|
| `dcerpc_interface_name` | str | `"SAMR"` / `"DRSUAPI"` / `"LSARPC"` |
| `dcerpc_interface_uuid` | str | `"12345678-1234-abcd-ef00-0123456789ab"` |
| `dcerpc_packet_type` | str | `"bind"` / `"request"` / `"response"` |
| `dcerpc_opnum` | int | `5` |

---

## Quick-reference cheatsheet

```python
# Research chart skeleton
class MyChart(ResearchChart):
    name        = "my_chart"
    title       = "My Chart"
    description = "..."
    category    = "capture"

    def compute(self, ctx, params):
        for pkt in ctx.packets:          # raw packets
            ex = pkt.extra               # protocol fields
            ...

        for s in ctx.sessions:           # reconstructed sessions
            s.get("tls_snis", [])        # safe access
            ...

        for n in ctx.nodes:              # graph nodes
            n["id"], n["total_bytes"]    # always present
            ...

        for e in ctx.edges:              # graph edges
            e["protocol"], e["tls_snis"] # always present
            ...

# Plugin skeleton — two tiers, different ctx contents:

# Insight plugin (fires at load time, before graph is built)
class MyInsight(PluginBase):
    def analyze_global(self, ctx):
        # ctx.packets ✅  ctx.sessions ✅
        # ctx.nodes   ❌  ctx.edges    ❌  (graph not yet built)
        for pkt in ctx.packets: ...
        for s in ctx.sessions: ...

    def analyze_node(self, ctx):
        # ctx.target_node_id set; packets/sessions available; nodes/edges empty
        node_id = ctx.target_node_id
        relevant = [s for s in ctx.sessions if node_id in (s["src_ip"], s["dst_ip"])]

# Analysis plugin (fires after graph build — nodes and edges available)
from plugins.analyses import AnalysisBase
class MyAnalysis(AnalysisBase):
    def compute(self, ctx):
        # ctx.packets ✅  ctx.sessions ✅
        # ctx.nodes   ✅  ctx.edges    ✅
        for n in ctx.nodes: ...
        for e in ctx.edges: ...
```

---

## Per-chart data filters

Research charts that implement `build_data()` + `build_figure()` get automatic
per-chart filter controls in the UI at no extra cost.

### How it works

1. `build_data(ctx, params)` returns a flat list of entry dicts — one per plotted point or bar.
2. The framework calls `_detect_schema(entries)` to infer the type of each field.
3. The schema is returned alongside the figure as `filter_schema` in the API response.
4. The frontend renders appropriate filter controls in the card's "Chart filters" drawer.
5. When the researcher changes a filter, the card auto-reruns and sends `_filter_<field>` params.
6. The framework calls `_apply_filters(entries, filter_params, schema)` before `build_figure()`.

### Entry dict conventions

```python
def build_data(self, ctx, params) -> List[dict]:
    return [
        {
            "ts":       pkt.timestamp * 1000,  # time axis — EXCLUDED from filters
            "src":      pkt.src_ip,             # ip type   → text input (prefix match)
            "dst":      pkt.dst_ip,             # ip type
            "protocol": pkt.protocol,           # list type  → chips (≤20 unique values)
            "bytes":    pkt.orig_len,           # numeric    → min/max inputs
            "uri":      ex.get("http_uri",""),  # string     → contains text input
        }
        for pkt in ctx.packets
        ...
    ]
```

Reserve `"ts"` (also `"ts_ms"`, `"time"`, `"timestamp"`) for the time axis. These keys
are excluded from filter detection. All other keys are candidates.

### Auto-detected field types

| Condition | Detected type | Frontend control |
|-----------|--------------|-----------------|
| Value matches `^\d{1,3}(\.\d{1,3}){3}$` | `ip` | Text input — prefix or exact match |
| int or float | `numeric` | Min / max number inputs (both optional) |
| String, ≤ 20 unique values in sample | `list` | Multi-select chips; options = unique values |
| String, > 20 unique values | `string` | Text input — case-insensitive contains match |
| bool | skipped | — |

Detection samples the first 300 entries. For `ip` detection, the first 20 non-null values
are checked.

### Filter param names sent to the backend

| Type | Param key(s) |
|------|-------------|
| `ip` | `_filter_<field>` |
| `string` | `_filter_<field>` |
| `list` | `_filter_<field>` (comma-separated selected values) |
| `numeric` | `_filter_<field>_min` and/or `_filter_<field>_max` |

### build_figure receives filtered entries

```python
def build_figure(self, entries: List[dict], params: dict) -> go.Figure:
    # entries has already been filtered by the framework.
    # params is the same user param dict as build_data() received.
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=[e["ts"]    for e in entries],
        y=[e["bytes"] for e in entries],
        ...
    ))
    return fig   # do NOT call .to_dict() or apply SWIFTEYE_LAYOUT
```

### Legacy compute() path

Charts that implement only `compute()` continue to work unchanged.
`filter_schema` is returned as `{}` — no filter controls appear in the UI.

```python
def compute(self, ctx, params):
    # full control — no auto-filter support
    ...
    return fig  # go.Figure or raw dict
```
