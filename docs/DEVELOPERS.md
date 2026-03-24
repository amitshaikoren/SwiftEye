# SwiftEye Developer Documentation

**Version 0.10.6 | March 2026**

> **Doc maintenance rule:** Update this file whenever you touch architecture, extension points, API contracts, or developer-facing patterns. Update the version header when cutting a release. Stale docs are worse than no docs.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Design Philosophy](#3-design-philosophy)
4. [Scalability](#4-scalability)
5. [Getting Started](#5-getting-started)
6. [Backend Reference](#6-backend-reference)
7. [Frontend Reference](#7-frontend-reference)
8. [Plugin System](#8-plugin-system)
9. [API Reference](#9-api-reference)
10. [Data Flow](#10-data-flow)
11. [Adding Features](#11-adding-features)
12. [File Format Reference](#12-file-format-reference)

---

## 1. Overview

SwiftEye is a network traffic visualization platform for security researchers. It parses pcap/pcapng capture files and renders an interactive force-directed graph of network communications, with session reconstruction, protocol dissection, and extensible analysis plugins.

**Target users**: Security researchers, network analysts, incident responders.

**What it does**: Displays network traffic visually — who talked to whom, over what protocols, with what TCP behavior. Researchers bring the expertise; SwiftEye shows the data.

**What the core does NOT do**: Make security judgments, flag threats, or generate alerts. The core viewer and analysis layers present evidence for the researcher to interpret. Threat detection, alerting, and security scoring belong in the plugin system — specifically the analyses tier (graph-wide computation), where they can correlate across sessions and nodes without polluting the core viewer.

---

## 2. Architecture

```
swifteye/
├── backend/
│   ├── server.py                    # FastAPI server, all API routes, capture state
│   ├── constants.py                 # ALL Python constants: PROTOCOL_COLORS, WELL_KNOWN_PORTS,
│   │                                #   TCP_FLAG_*, ICMP_TYPES, CIPHER_SUITES, SWIFTEYE_LAYOUT
│   ├── models.py                    # Pydantic response models
│   ├── parser/                      # LAYER 1: Raw packet parsing
│   │   ├── packet.py                # PacketRecord dataclass (normalised packet)
│   │   ├── pcap_reader.py           # Router: <500MB → scapy (full dissection), ≥500MB → dpkt (partial)
│   │   ├── dpkt_reader.py           # dpkt reader (≥500MB files). NOTE: dissectors using
│   │                                #   scapy layers return empty on this path — DNS hostnames
│   │                                #   won't resolve. See roadmap for dissector parity fix.
│   │   ├── oui.py                   # MAC OUI → vendor name lookup (~700 entries, clean keys)
│   │   ├── ja3_db.py                # JA3 hash → {name, category, is_malware} (~60 entries, no duplicates)
│   │   └── protocols/               # Protocol registry package
│   │       ├── __init__.py          # Registries, resolution helpers, auto-imports dissectors
│   │       ├── ports.py             # Re-export shim → constants.py (backwards compat)
│   │       ├── signatures.py        # Payload signature matchers (TLS, HTTP, SSH, SMTP, FTP)
│   │       ├── dissect_dns.py       # DNS: query name, type, answers
│   │       ├── dissect_http.py      # HTTP: method, URI, host, status (scapy + manual)
│   │       ├── dissect_tls.py       # TLS: SNI, version, ciphers, JA3/JA4
│   │       ├── dissect_icmp.py      # ICMPv4 + ICMPv6: type/code names, NDP target
│   │       ├── dissect_ssh.py       # SSH: banner version, software, client heuristic
│   │       ├── dissect_ftp.py       # FTP: commands, username, filenames, credential flag
│   │       ├── dissect_dhcp.py      # DHCP: hostname, vendor class, msg type, IPs
│   │       ├── dissect_smb.py       # SMB v1/v2/v3: command, status, share path, filename
│   │       ├── dissect_smtp.py      # SMTP: EHLO, MAIL FROM, RCPT TO, AUTH, STARTTLS
│   │       ├── dissect_mdns.py      # mDNS: service discovery, SRV, TXT records
│   │       ├── dissect_ssdp.py      # SSDP/UPnP: M-SEARCH, NOTIFY, ST, USN, Location
│   │       ├── dissect_llmnr.py     # LLMNR: queries, answers (DNS wire format on port 5355)
│   │       ├── dissect_dcerpc.py   # DCE/RPC: packet type, interface UUID, service name, opnum
│   │       └── dissect_quic.py    # QUIC: version, connection IDs, SNI from Initial (Phase 1)
│   ├── analysis/                    # LAYER 2: Structural data organisation
│   │   ├── aggregator.py            # Graph building, filtering, entity_map, OUI+JA3 lookup
│   │   ├── sessions.py              # Session reconstruction + per-protocol aggregation
│   │   └── stats.py                 # Global statistics
│   ├── plugins/                     # LAYER 3: Plugin system (insights + analyses)
│   │   ├── __init__.py              # PluginBase, registry, UI slot system, display helpers
│   │   ├── insights/                # Per-node/per-session interpretation
│   │   │   ├── os_fingerprint.py    # Passive OS detection (SYN + SYN+ACK)
│   │   │   ├── tcp_flags.py         # TCP flag analysis with sender attribution
│   │   │   ├── dns_resolver.py      # DNS hostname resolution from capture
│   │   │   ├── network_map.py       # ARP table, gateway detection, LAN hosts
│   │   │   └── node_merger.py       # MAC-based node merging (pre-aggregation)
│   │   └── analyses/                # Graph-wide computation
│   │       ├── __init__.py          # AnalysisPluginBase, registry
│   │       ├── node_centrality.py   # Degree + betweenness + traffic ranking
│   │       └── traffic_characterisation.py  # Session fg/bg/ambiguous classification
│   ├── tests/                       # Pytest test suite
│   │   └── test_core.py             # Core path + regression + plugin tests
│   └── research/                    # LAYER 4: On-demand Plotly charts
│       ├── __init__.py              # ResearchChart base, Param, registry, run_chart()
│       ├── conversation_timeline.py # Peers of target IP over time
│       ├── ttl_over_time.py         # TTL between two peers, both directions
│       ├── session_gantt.py         # Session Gantt chart (Timeline page only)
│       ├── seq_ack_timeline.py      # TCP seq/ack numbers over time for a session
│       └── http_ua_timeline.py      # HTTP requests over time, coloured by User-Agent
├── frontend/
│   ├── package.json
│   ├── vite.config.js               # chunkSizeWarningLimit: 1024 (D3 + OUI table = ~900KB)
│   ├── index.html                   # Vite entry point (Plotly.js CDN loaded here)
│   └── src/
│       ├── main.jsx                 # React entry point
│       ├── version.js               # Single source of truth: VERSION = '0.10.6'
│       ├── App.jsx                  # Pure layout + routing (~220 lines)
│       ├── hooks/
│       │   └── useCapture.js        # All state, effects, handlers (~340 lines)
│       ├── api.js                   # All backend API calls
│       ├── utils.js                 # Formatting helpers (fN, fB, fD, fT, fTtime)
│       ├── displayFilter.js         # Wireshark-style filter: tokeniser → parser → evaluator
│       └── components/
│           ├── GraphCanvas.jsx      # D3 force simulation on canvas + annotation overlays
│           ├── TopBar.jsx           # Logo, filename, search, theme toggle
│           ├── FilterBar.jsx        # Display filter bar with autocomplete
│           ├── LeftPanel.jsx        # Protocols, Graph Options, panel switcher
│           ├── StatsPanel.jsx       # Global stats + plugin sections
│           ├── NodeDetail.jsx       # Node info, MACs+vendors, OS guess, plugin sections
│           ├── EdgeDetail.jsx       # Edge traffic, TLS (JA3 badges), HTTP, DNS
│           ├── SessionDetail.jsx    # Session packets, TCP state, SSH/FTP/DHCP/SMB sections
│           ├── SessionsTable.jsx    # Sortable session list with local search
│           ├── MultiSelectPanel.jsx # Stats for shift-click multi-selection
│           ├── ResearchPage.jsx     # On-demand Plotly charts + ChartErrorBoundary
│           ├── TimelinePanel.jsx    # Session Gantt + time scope
│           ├── HelpPanel.jsx        # Keyboard shortcuts and feature reference
│           ├── LogsPanel.jsx        # Auto-refreshing server log viewer
│           ├── Sparkline.jsx        # Time-bucketed packet count canvas sparkline
│           ├── PluginSection.jsx    # Generic renderer for plugin _display data
│           └── Tag.jsx, FlagBadge.jsx, Collapse.jsx, Row.jsx  # UI primitives
└── docs/
    ├── DEVELOPERS.md               # This file
    └── HANDOFF.md                  # Version history, known bugs, roadmap
```

### Layer Summary

| Layer | Directory | Responsibility | Rule |
|-------|-----------|---------------|------|
| **Parser** | `parser/` | Read raw packets → `PacketRecord` | Only touches scapy/dpkt objects. Never interprets. |
| **Analysis** | `analysis/` | Structure data for display | Operates on `PacketRecord` only. No interpretation. |
| **Insights** | `plugins/insights/` | Interpret and correlate per-node/session | Can read packets + sessions. Produces analysis results. |
| **Analyses** | `plugins/analyses/` | Graph-wide computation | Operates on full graph (nodes + edges + sessions). Returns `_display` for generic rendering. |
| **Research** | `research/` | On-demand deep-dive charts | Stateless compute per request. Viewer philosophy applies. |
| **Server** | `server.py` | HTTP API, state, orchestration | Wires layers together. Holds capture state. |
| **Frontend** | `frontend/src/` | Interactive visualisation | Consumes API. No analysis logic. |

---

## 3. Design Philosophy

### Viewer vs. Analyzer

The core question for every feature: **"Am I displaying what's in the packet, or am I interpreting it?"**

**Viewer (parser/analysis layer):**
- Grouping packets into sessions by IP+port tuple
- Building a graph of who-talked-to-whom
- Showing TCP flags, sequence numbers, TTL on a packet
- Extracting SSH banner version from the cleartext handshake
- Parsing DHCP hostname from Option 12

**Analyzer (plugin layer):**
- Mapping an IP to a hostname via DNS correlation
- Guessing an OS from TTL + window size
- Attributing "who initiated" from SYN flag patterns
- JA3 fingerprinting and app-name lookup

If you're unsure, err on the side of making it a plugin. Plugins can always access the same data as the core, but they keep the core clean.

### Zero Data Loss

The second core principle: **never discard raw data to create a cleaner view.** Aggregation (sessions, graphs, statistics) adds zoom levels on top of the data — it never replaces it. The researcher must always be able to drill from aggregated view → individual packets → raw bytes without hitting a wall.

**The decision tree for data limits:**

1. **Is it a resource guard?** (MAX_FILE_SIZE, MAX_PACKETS) → **Keep it.** These are explicit boundaries the researcher is aware of, not silent discarding.
2. **Is it a display limit?** (frontend `.slice(0, 20)`, stats TOP_TALKERS) → **Fine**, as long as the full data exists somewhere the researcher can reach. Show "X of Y" when truncating.
3. **Is it a storage/accumulation limit?** (CAP_* constants, dissector record caps) → **Violation.** The data is permanently lost and the researcher doesn't know. Move the limit to the display layer and include a total count.
4. **Is it a string truncation?** (User-Agent at 200 chars) → **Acceptable with indicator.** Append `…` or set a `_truncated` flag so the researcher knows the field was clipped. The raw pcap is the escape hatch for full values.

**When writing new code:**

- **Dissectors** (`parser/protocols/`): Extract everything the packet contains. Do not cap record counts or truncate strings without a truncation indicator. If memory is a concern, document the tradeoff and set a generous limit (not a tight one).
- **Protocol field accumulators** (`analysis/protocol_fields/`): Accumulate all data. Apply caps only in `serialize()`, never in `accumulate()`. When capping in serialize, include a `_total` key with the uncapped count.
- **Frontend sections** (`session_sections/*.jsx`): When using `.slice()` for display, show "Showing X of Y" and provide an expand mechanism. Never silently truncate a list the researcher might need to see in full.
- **Edge aggregation** (`aggregator.py`): Edges summarize across many sessions — display caps here are acceptable because the researcher can drill into individual sessions. This is aggregation adding a zoom level, not replacing data.

### Graph Options — Philosophy and Placement Rules

**Graph Options** contains toggles that change how the graph is *built* — not how it's filtered or displayed. Each toggle triggers a full `/api/graph` re-fetch.

| Toggle | Why it belongs here |
|--------|-------------------|
| Subnet /N grouping + prefix | Changes node identity — IPs become subnet nodes |
| Merge by MAC | Changes node identity — multiple IPs become one canonical node |
| IPv6 toggle | Changes which packets are included in node/edge construction |
| Show Hostnames | When off, passes empty hostname_map to build_graph — nodes show raw IPs |
| Subnet exclusions | Per-subnet uncluster: named subnets bypass grouping |

**What does NOT belong in Graph Options:**
- Protocol checkboxes — filter packets but don't change node identity
- Search / IP / port filters — narrow packets without reshaping nodes
- Display filter — purely client-side, never re-fetches
- Time range — temporal navigation, not structural

**Adding a new Graph Options toggle:**

1. Add state + setter to `useCapture.js`
2. Add the param to the graph fetch `useEffect` and its dependency array
3. Add the toggle UI to `LeftPanel.jsx` (pass state + setter as props via `c.xxx` in `App.jsx`)
4. Add query param handling in `/api/graph` in `server.py`
5. Add the filter/transform to `build_graph()` in `aggregator.py`

---

## 4. Scalability

Network captures can produce extremely large graphs. A 10-minute corporate capture may contain hundreds of thousands of packets across thousands of unique IP pairs. SwiftEye addresses this at both the visualization and compute layers.

### Visualization strategies

The goal: reduce what the user sees without losing data. The full capture is always available — the researcher scopes down.

**Implemented:**
- **Timeline time slider** — scope the entire view (graph, sessions, stats) to a time window. Gap-split sparkline with burst snap buttons.
- **Subnet grouping** — collapse IPs into `/N` subnet nodes (/8–/32). Selective unclustering per subnet via right-click.
- **Protocol filter** — checkboxes in left panel to hide noisy protocols (DNS, ARP).
- **Display filter** — Wireshark-style client-side expression filter. Instant, no backend round-trip.
- **Merge by MAC** — dual-stack hosts collapse into one node. Can halve visible nodes on IPv6-heavy networks.
- **Investigate neighbours** — right-click → isolate depth-1 neighborhood or full BFS connected component.
- **Hide node** — remove noisy nodes (broadcast, multicast) from view.
- **Search filter** — universal keyword match across IPs, MACs, hostnames, protocols, ports, flags.

**Not yet implemented:**
- Large graph layout (WebGL renderer, level-of-detail, server-side layout for 1000+ nodes)

### Compute strategies

**Implemented:**
- **Dual parser** — scapy for full dissection, dpkt for lightweight parsing. Currently both thresholds are at 500MB (dpkt effectively unused until dissector parity is confirmed).
- **Backend analyses** — centrality (Brandes O(V³)) and traffic characterisation run in Python, not the browser. Frontend receives pre-computed results.
- **Packet-based session scoping** — strict timestamp filtering avoids combinatorial blowup from long-running sessions.
- **Lazy execution** — analyses run on first graph build, not at upload time.

**Not yet implemented:**
- Multi-threaded parsing (embarrassingly parallel — no cross-packet state)
- Streaming/chunked parse (currently loads entire packet list into memory)
- Indexed packet store (O(1) lookups by session_key, IP, time range)
- Neo4j graph backend (Cypher queries, persistence, multi-capture)
- dpkt dissector parity (needed to lower the dpkt threshold to ~50MB)

### Design principle

The architecture assumes the researcher's first action is to scope down. The tool prioritises fast scoping (time slider, filters, subnet grouping) over brute-force rendering of the full graph.

### Zero data loss vs. memory constraints

SwiftEye is a desktop tool processing captures that can reach 500MB / 2M packets. The zero data loss principle (§3) creates tension with memory:

**Where the tension is real:**
- A heavy HTTP session can accumulate thousands of URIs. Uncapped, a 2M-packet capture with aggressive web crawling could balloon session memory by 5-10x on the worst sessions.
- Sending uncapped lists to the frontend means larger JSON payloads. 500 DNS queries × ~200 bytes ≈ 100KB per session detail request.
- Removing dissector-level caps (e.g. DNS answer records) means the parser stores more data per packet. For most captures this is negligible; for pathological cases (DNS amplification attacks with 200+ answer records) it matters.

**Where the tension is not real:**
- Stats aggregation (top-N talkers/ports) — the underlying session data is still complete. Top-N is a zoom level, not data loss.
- Edge-level caps — edges summarize across sessions. The researcher drills into individual sessions for full data.
- Resource guards (MAX_FILE_SIZE, MAX_PACKETS) — explicit boundaries, not silent discarding.
- Frontend `.slice()` — display pagination, not data loss. The full data is in memory.

**Resolution strategy:**
1. Accumulate everything in the session object (no caps in `accumulate()`).
2. Apply generous safety-valve caps in `serialize()` only (e.g. 500 items per list, 2000 chars per string). These exist for memory safety, not UX.
3. Always include `_total` counts when capping, so the researcher knows data was trimmed.
4. Paginate at the API level for large fields (`?field_offset=N`), matching the existing `packet_limit` pattern.
5. The raw pcap file is always the ultimate escape hatch — SwiftEye never modifies or deletes the source file.

---

## 5. Getting Started

### Prerequisites

- Python 3.10+
- Node.js 18+ (for frontend build)

### Installation

```bash
cd swifteye

# Python dependencies
pip install -r requirements.txt

# Frontend build
cd frontend && npm install && npm run build && cd ..

# Run
cd backend && python server.py
# Open http://localhost:8642
```

### Development Mode (hot reload)

```bash
# Terminal 1
cd backend && python server.py

# Terminal 2
cd frontend && npm run dev
# Open http://localhost:5173
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SWIFTEYE_PORT` | `8642` | Server listen port |

---

## 6. Backend Reference

### `parser/packet.py` — PacketRecord

Every parsed packet becomes a `PacketRecord`. All downstream code operates on this — never raw scapy/dpkt objects.

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | float | Unix timestamp |
| `src_ip`, `dst_ip` | str | Source/destination IP |
| `src_port`, `dst_port` | int | Source/destination port (0 for ICMP/ARP) |
| `src_mac`, `dst_mac` | str | Source/destination MAC |
| `transport` | str | "TCP", "UDP", "ICMP", "ICMPv6", "ARP", "OTHER" |
| `protocol` | str | Resolved application protocol |
| `ip_version` | int | 4 or 6 |
| `ttl` | int | IP TTL / IPv6 hop limit |
| `tcp_flags` | int | Raw TCP flag byte |
| `tcp_flags_list` | list[str] | e.g. `["SYN", "ACK"]` |
| `tcp_options` | list[dict] | Parsed TCP options: `{"kind": "MSS", "value": 1460}` |
| `seq_num`, `ack_num` | int | TCP sequence/acknowledgment numbers |
| `window_size` | int | TCP receive window |
| `orig_len` | int | Original packet length |
| `payload_len` | int | Application payload length |
| `payload_preview` | bytes | First 256 bytes of payload (hex dump in UI) |
| `extra` | dict | Protocol-specific fields from dissectors |
| `session_key` | str (property) | Canonical bidirectional flow key |

### `parser/pcap_reader.py` — read_pcap()

Routes to the best reader:
- **< 500MB** → scapy — full protocol dissection (DNS, TLS, HTTP, all dissectors work)
- **≥ 500MB** → `dpkt_reader` — faster for very large files but dissection is partial (DNS hostnames will not resolve, dissectors that use scapy layers return empty)

**Roadmap:** port all dissectors to work on raw bytes so dpkt and scapy paths produce identical output, then lower the threshold.

Max file size: 500MB. Max packets: 2M. Dissector exceptions are caught and logged as `WARNING` — malformed packets never crash the parse.

### `parser/protocols/` — Protocol Registry

**Four registries** auto-populated by decorator imports:
- `WELL_KNOWN_PORTS` — port → protocol name
- `PROTOCOL_COLORS` — protocol → hex color
- `DISSECTORS` — protocol → extractor function
- `PAYLOAD_SIGNATURES` — sorted list of (priority, protocol, matcher)

**Protocol detection pipeline (per packet):**

```
1. Port resolution      → WELL_KNOWN_PORTS[dport] or [sport]
2. Dissector runs       → pkt.extra gets populated
3. Payload detection    → scapy layers → PAYLOAD_SIGNATURES
4. Conflict resolution  → payload wins; conflict flagged on edge
```

**Currently registered dissectors:**

| File | Protocol | Key `extra` fields |
|------|----------|--------------------|
| `dissect_tls.py` | TLS/HTTPS | `tls_sni`, `tls_version`, `tls_ciphers`, `tls_selected_cipher`, `ja3`, `ja3_string`, `ja4` |
| `dissect_http.py` | HTTP | `http_method`, `http_uri`, `http_host`, `http_status`, `http_version` |
| `dissect_dns.py` | DNS | `dns_query`, `dns_type`, `dns_answers` |
| `dissect_icmp.py` | ICMP/ICMPv6 | `icmp_type`, `icmp_code`, `icmp_type_name`, `icmp_code_name`, `icmp_id`, `icmp_seq`, `icmpv6_target` |
| `dissect_ssh.py` | SSH | `ssh_banner`, `ssh_proto_version`, `ssh_software`, `ssh_software_name`, `ssh_client` |
| `dissect_ftp.py` | FTP | `ftp_command`, `ftp_arg`, `ftp_response_code`, `ftp_username`, `ftp_transfer_file`, `ftp_has_credentials`, `ftp_server_banner` |
| `dissect_dhcp.py` | DHCP | `dhcp_msg_type`, `dhcp_hostname`, `dhcp_vendor_class`, `dhcp_requested_ip`, `dhcp_offered_ip`, `dhcp_server_ip`, `dhcp_param_list`, `dhcp_domain`, `dhcp_bootfile` |
| `dissect_smb.py` | SMB | `smb_version` (SMBv1/v2/v3), `smb_command`, `smb_status`, `smb_status_name`, `smb_tree_path`, `smb_filename`, `smb_dialect`, `smb_is_request` |
| `dissect_smtp.py` | SMTP | `smtp_command`, `smtp_ehlo_domain`, `smtp_mail_from`, `smtp_rcpt_to`, `smtp_response_code`, `smtp_banner`, `smtp_auth_mechanism`, `smtp_has_auth`, `smtp_has_starttls` |
| `dissect_mdns.py` | mDNS | `mdns_query`, `mdns_qtype`, `mdns_qr`, `mdns_answers`, `mdns_service_type`, `mdns_service_name`, `mdns_hostname`, `mdns_port`, `mdns_txt_records` |
| `dissect_ssdp.py` | SSDP/UPnP | `ssdp_method`, `ssdp_st`, `ssdp_usn`, `ssdp_location`, `ssdp_server`, `ssdp_nts`, `ssdp_nt`, `ssdp_mx`, `ssdp_user_agent` |
| `dissect_llmnr.py` | LLMNR | `llmnr_query`, `llmnr_qtype`, `llmnr_qr`, `llmnr_answers`, `llmnr_tc` |
| `dissect_dcerpc.py` | DCE/RPC | `dcerpc_version`, `dcerpc_packet_type`, `dcerpc_call_id`, `dcerpc_interface_uuid`, `dcerpc_interface_name`, `dcerpc_opnum` |
| `dissect_quic.py` | QUIC | `quic_version`, `quic_version_name`, `quic_dcid`, `quic_scid`, `quic_packet_type`, `quic_sni`, `quic_alpn`, `quic_tls_versions`, `quic_tls_ciphers` |

**Adding a new dissector:**

```python
# backend/parser/protocols/dissect_myproto.py
from typing import Dict, Any
from . import register_dissector, register_payload_signature

@register_payload_signature("MYPROTO", priority=25)
def _detect(payload: bytes) -> bool:
    return payload[:4] == b"MY\x01\x00"

@register_dissector("MYPROTO")
def dissect_myproto(pkt) -> Dict[str, Any]:
    info = {}
    if pkt.haslayer("Raw"):
        # ... parse payload ...
        info["myproto_field"] = "value"
    return info
```

Then in `protocols/__init__.py` add:
```python
from . import dissect_myproto  # noqa: F401
```

And in `constants.py` add to `PROTOCOL_COLORS` and `WELL_KNOWN_PORTS`.

**Signature priority guidelines:**
- 10–15: High-confidence magic bytes (TLS `0x16`, SSH `SSH-`)
- 20–30: Banner detection (SMTP `220...ESMTP`, DHCP magic cookie)
- 40–60: Heuristic content patterns

### `parser/oui.py` — MAC Vendor Lookup

`lookup_vendor(mac: str) -> str` — returns vendor name or `""`.

Accepts any common MAC format (`aa:bb:cc:dd:ee:ff`, `AA-BB-CC`, `aabbccddeeff`). Uses the first 3 bytes (OUI prefix). ~700 entries (all 6-character hex keys, malformed keys removed) covering Apple, Cisco, Intel, Samsung, Dell, HP, VMware, Huawei, TP-Link, Ubiquiti, Espressif (ESP32), VirtualBox, QEMU/KVM, Raspberry Pi, and others.

Called from `aggregator.py` when building nodes. Result stored in `node["mac_vendors"]` (parallel array to `node["macs"]`).

### `parser/ja3_db.py` — JA3 Application Lookup

`lookup_ja3(hash: str) -> Optional[Dict]` — returns `{name, category, is_malware}` or `None`.

~60 curated entries (no duplicates — conflicting malware entries for Chrome/Safari/LibreSSL hashes removed): browsers (Firefox, Chrome, Safari, Edge, IE11), TLS libraries (Python requests, Go net/http, Java JSSE, curl, Node.js, .NET), and ~10 known malware families (Cobalt Strike, QakBot, AsyncRAT, Sliver, Havoc, etc.).

Called from `aggregator.py` (edges → `ja3_apps`) and `sessions.py` (sessions → `ja3_apps`). The `JA3Badge` component in `EdgeDetail` and `SessionDetail` renders a green pill for legitimate apps and a red `⚠` pill for known malware.

### `analysis/aggregator.py` — Graph Building

`build_graph(packets, ...)` is the central function. Key steps:
1. `filter_packets()` — time, protocol, IP, port, search, IPv6 toggle
2. Entity map applied — `resolve(ip)` maps merged IPs to canonical
3. Node and edge maps built from filtered packets
4. OUI vendor + JA3 app name resolution
5. Hostname and researcher metadata enrichment
6. Serialised to JSON-friendly dicts with sets → sorted lists

`entity_map` comes from `node_merger.build_entity_map()`. When `merge_by_mac=True`, IPs sharing a MAC are union-found into groups. `_pick_canonical()` prefers the most-seen IPv4; if all are IPv6, picks the most-seen IPv6. Cross-family merges (IPv4 ↔ IPv6 sharing a MAC) are permitted — the merged node's `ips` list contains all addresses.

**Session matching after merge:** `EdgeDetail` receives the `nodes` list and builds `nodeIpsMap: Map<nodeId → Set<ip>>`. `matchEndpoint()` checks a session IP against all IPs in the merged node group — not just the canonical ID. This ensures sessions from `2a0d:6fc0::1` appear on the same edge as sessions from `192.168.1.177` after MAC merge.

### `analysis/sessions.py` — Session Reconstruction

Groups packets by `session_key` into bidirectional flows. Core transport fields (packet counts, bytes, direction, TCP state, IP headers, window/seq/ack) live in `sessions.py`. Protocol-specific fields (TLS, HTTP, DNS, etc.) are handled by auto-discovered modules in `analysis/protocol_fields/` — see "Adding a New Protocol Dissector" in §11.

Per-session fields include:

- Basic: `packet_count`, `total_bytes`, `duration`, `initiator_ip`, `responder_ip`
- TCP: `has_handshake`, `has_fin`, `has_reset`, `init_window_initiator/responder`, `window_min/max`, `seq_first/last`, `ack_first/last`, `tcp_options_seen`
- TLS: `tls_snis`, `tls_versions`, `tls_ciphers`, `ja3_hashes`, `ja4_hashes`, `ja3_apps`
- HTTP: `http_hosts`, `http_methods`, `http_uris`
- DNS: `dns_queries` (list of `{query, qtype, answers, qr}`)
- SSH: `ssh_versions`
- FTP: `ftp_commands`, `ftp_usernames`, `ftp_transfer_files`, `ftp_has_credentials`
- DHCP: `dhcp_hostnames`, `dhcp_vendor_classes`, `dhcp_msg_types`
- SMB: `smb_versions`, `smb_commands`, `smb_tree_paths`, `smb_filenames`

### `analysis/protocol_fields/` — Protocol Field Handlers

Auto-discovered modules that handle protocol-specific session field init, accumulation, and serialization. Each module exports three functions:

- `init()` → dict of initial fields (sets, lists, None)
- `accumulate(s, ex, is_fwd, source_type)` → merge one packet's `pkt.extra` into the session
- `serialize(s)` → convert sets to sorted lists, apply caps

**`source_type` parameter:** identifies which adapter produced the packet. Protocol handlers use this when the same protocol needs different accumulation logic depending on the data source. For example, Zeek HTTP logs contain both request and response fields in a single record, so the HTTP handler must add both directions regardless of `is_fwd` when `source_type == "zeek"`.

Valid `source_type` values (set by each adapter in `pkt.extra["source_type"]`):

| Value | Source | Notes |
|-------|--------|-------|
| `None` | pcap/pcapng | Raw packets. Direction from TCP flags or first-packet heuristic. |
| `"zeek"` | Zeek log adapters | Pre-aggregated records. One record may contain both directions. |
| `"splunk"` | Splunk CSV/JSON | Planned. |
| `"sysmon"` | Sysmon XML/JSON | Planned. |
| `"netflow"` | Netflow/IPFIX | Planned. |

When adding a new adapter, add its `source_type` string to this table and to `analysis/protocol_fields/__init__.py`.

### `plugins/node_merger.py` — MAC-Based Node Merging

Uses union-find to group IPs sharing a MAC address. Called at `/api/graph` time (not at upload time) so toggling "Merge by MAC" never requires re-uploading.

`_is_mergeable(ip)` excludes: IPv6 multicast (`ff::`), IPv6 link-local (`fe80::`), IPv6 loopback (`::1`), IPv4 multicast/broadcast, IPv4 loopback.

`_is_multicast_mac(mac)` excludes `33:33:*` (IPv6 multicast) and `01:00:5e:*` (IPv4 multicast) from being used as merge keys.

**Three-layer router filter (all must pass):** (1) src_mac only — never dst_mac; (2) `_is_router_mac()` checks OUI vendor against `_INFRA_VENDORS` (Cisco, Juniper, Aruba, Ubiquiti, Palo Alto, Fortinet, Sophos, WatchGuard, Brocade, Extreme, Arista, MikroTik, Ruckus, Meraki); (3) group size cap at 8 IPs.

Cross-family merges (IPv4 + global IPv6 sharing a MAC) are intentionally **allowed** — a dual-stack host should appear as one node. Session matching handles this via `nodeIpsMap` in `EdgeDetail`.

### Error Isolation Rules

| Layer | On error | Log level |
|-------|----------|-----------|
| Dissector (`pkt.extra`) | Catches, skips dissection | `WARNING` |
| JA3/JA4 computation | Catches, skips fingerprint | `WARNING` |
| Entity map (node merger) | Catches, falls back to no merging | `ERROR` |
| Plugin `analyze_global` | Catches, skips plugin | `ERROR` |
| Research chart `compute` | Catches, returns error message | `ERROR` |
| Individual packet parse | Catches, skips packet | (silent) |

---

## 7. Frontend Reference

### Version String

**Single source of truth:** `frontend/src/version.js` exports `VERSION`. `TopBar.jsx` imports it. **Never hardcode the version string elsewhere.**

When cutting a release:
1. Update `version.js`
2. Update `HANDOFF.md` header
3. Update `DEVELOPERS.md` header
4. Then make code changes

### State Management — `useCapture.js`

All capture-related state lives in `frontend/src/hooks/useCapture.js`. `App.jsx` calls it once (`const c = useCapture()`) and uses the result for layout and routing only.

`useCapture` owns:
- Capture lifecycle: `loaded`, `loading`, `loadMsg`, `error`, `fileName`
- Server data: `graph`, `sessions`, `sessionTotal`, `stats`, `timeline`, `protocols`, `pColors`, `pluginResults`, `pluginSlots`
- Filters: `timeRange`, `enabledP`, `search`, `bucketSec`, `subnetG`, `subnetPrefix`, `mergeByMac`, `includeIPv6`
- Display filter: `dfExpr`, `dfApplied`, `dfError`, `dfResult`
- Annotations and synthetic elements
- Selection state: `selNodes`, `selEdge`, `selSession`, `rPanel`
- Investigation: `investigatedIp`, `investigationNodes`; `hiddenNodes`
- Panel resize state
- `subnetExclusions` — set of subnet strings that have been manually unclustered; cleared by `toggleSubnetG()` when grouping is turned off (use `toggleSubnetG` instead of `setSubnetG` directly)

`App.jsx` owns only: `darkMode`, `gSize` (graph container dimensions for Sparkline width).

**Memoised derived values (stable references — never recomputed on unrelated renders):**

| Value | Dependencies | Purpose |
|-------|-------------|---------|
| `visibleNodes` | `graph.nodes`, `hiddenNodes` | Nodes after hide filter — passed to GraphCanvas |
| `visibleEdges` | `graph.edges`, `hiddenNodes` | Edges after hide filter — passed to GraphCanvas |
| `osGuesses` | `graph.nodes` | Distinct OS guesses for display filter chips |
| `availableIps` | `graph.nodes` | IP list for Research chart autocomplete |
| `timeLabel` | `timeline`, `timeRange` | Formatted time scope string for timeline bar |

These must remain `useMemo`-ed. The GraphCanvas simulation `useEffect([nodes, edges])` only restarts when these references actually change. If they're computed inline in JSX they create new array references on every render, causing the graph to wiggle on every state change.

### Settings — `useSettings.js`

Persistent UI settings stored in `localStorage`. Import with `const { settings, setSetting } = useSettings()`.

| Key | Default | Purpose |
|-----|---------|---------|
| `theme` | `'dark'` | Active theme name — CSS class applied to `document.body` |
| `llmApiKey` | `''` | LLM provider API key — stored locally, never sent to SwiftEye backend |
| `llmModel` | `'gpt-4o-mini'` | LLM model string for Analysis panel |

`THEMES` constant (array of `{id, label}`) is exported separately for components that only need the list (e.g. `SettingsPanel.jsx`).

`setSetting(key, value)` updates a single key and persists immediately. `App.jsx` owns the theme application: reads `settings.theme` and applies it to `document.body.className`.

### Component Hierarchy


```
App.jsx (layout + routing only)
├── TopBar.jsx          — logo, filename, search, theme
├── FilterBar.jsx       — display filter bar
├── LeftPanel.jsx       — protocols, Graph Options, panel switcher
├── GraphCanvas.jsx     — D3 force simulation + annotation overlays
├── Sparkline.jsx       — timeline strip sparkline
└── [Right Panel — one of]:
    ├── StatsPanel.jsx
    ├── NodeDetail.jsx
    ├── EdgeDetail.jsx
    ├── SessionDetail.jsx
    ├── MultiSelectPanel.jsx
    ├── SessionsTable.jsx    — has own local search, debounced independent fetch
    ├── ResearchPage.jsx     — ChartErrorBoundary wraps each ChartCard
    ├── TimelinePanel.jsx
    ├── AnalysisPage.jsx     — AI analysis (skeleton); full-width like Research
    ├── HelpPanel.jsx
    └── LogsPanel.jsx
```

### GraphCanvas.jsx — Critical Details

D3 force simulation on HTML canvas (not SVG — performance). Key rules:

- **Never restart simulation unnecessarily.** The simulation `useEffect` depends on `[nodes, edges]`. Pass `visibleNodes`/`visibleEdges` (memoised in `useCapture`) — not inline `.filter()` calls.
- **Annotation overlays** are HTML elements positioned over the canvas. They update on zoom/pan via `transformVersion` state (incremented in D3 zoom handler). This is the only way to keep HTML in sync with D3 canvas transforms.
- **Node drag vs zoom conflict** — `zoomEnabled` flag in the interaction `useEffect` disables D3 zoom while a node is being dragged.
- **Resize handling** — a 200ms polling interval checks `containerRef.current.clientWidth/Height`. On change: update centering forces; restart simulation only if `alpha() > 0.001` (already cooled sims stay still).

Node label priority: researcher metadata `name` → first DNS hostname → IP address. Hostnames render in cyan.

**Lasso select** — `Shift + right-click-drag` draws a selection rectangle. Implemented via `pointerdown` with `e.button === 2 && e.shiftKey`. The lasso rect is a React overlay div. On `pointerup`, nodes whose screen-space position falls within the rect are selected. `contextmenu` is suppressed if `lassoRef.current` is set (to prevent the context menu firing immediately after lasso release).

**Relayout** — `doRelayout()` function inside GraphCanvas. Deletes `fx`/`fy` from all nodes (unpins them) then calls `simRef.current.alpha(0.9).alphaTarget(0).restart()`. Exposed via the ↺ Relayout button overlay (top-right of canvas).

**Synthetic cluster** — `onCreateSyntheticCluster(nodeIds)` prop. Called from the canvas context menu when ≥2 nodes are selected. Implemented in `useCapture.handleCreateSyntheticCluster`: creates a purple synthetic node aggregating member IPs/bytes, hides member nodes via `hiddenNodes`, re-routes external edges. `cluster_members` field on the node tracks membership.

**Investigate split** — two props: `onInvestigateNeighbours` (depth-1: node + direct peers) and `onInvestigate` (full BFS connected component). Both appear as separate context menu items.

### Timestamp Formatting (`utils.js`)

`fT(ts)` — date + time: `"Mar 14 10:14:55 AM"`. Use in detail panels.
`fTtime(ts)` — time only: `"10:14:55 AM"`. Use in compact timeline labels.

Never use `toLocaleTimeString()` directly — always go through `fT`/`fTtime`.

### SessionDetail — Protocol Sections

New protocol-specific sections appear when the session has relevant data:

| Section | Condition | Shows |
|---------|-----------|-------|
| SSH | `ssh_versions.length > 0` | Software version string |
| FTP | credentials / usernames / files | ⚠ credential warning, usernames, transferred files |
| DHCP | hostnames / vendor class / msg types | Message flow, hostname, vendor class (OS fingerprint) |
| SMB | versions / paths / filenames | Version (v1/v2/v3), share paths, filenames |
| TLS | SNIs / versions / JA3 | SNI, version, cipher, JA3 badges |

### JA3Badge Component

Defined inline in both `EdgeDetail.jsx` and `SessionDetail.jsx`. Renders a JA3 hash with:
- Green pill + app name if hash is in `ja3_db` and `is_malware = False`
- Red pill + `⚠ name` if `is_malware = True`
- Hash only if not in database

`ja3_apps` is resolved server-side at aggregation time, not client-side.

### Adding a New Frontend Component

1. Create `frontend/src/components/MyComponent.jsx`
2. Import in `App.jsx` (for top-level panels) or the appropriate parent
3. Add panel routing in `App.jsx`'s right panel `if/else` block if it's a new panel type
4. If it needs capture state, destructure from `useCapture()` — never duplicate state
5. `npm run build`

---

## 8. Plugin System

### Architecture

The plugin system has two tiers:

**Insights** (`plugins/insights/`) — per-node/per-session interpretation. Each insight subclasses `PluginBase`, declares UI slots, and implements `analyze_global()`. They run once on pcap load and annotate nodes/edges/sessions. Researchers interact with insight data in NodeDetail, EdgeDetail, and StatsPanel.

**Analyses** (`plugins/analyses/`) — graph-wide computation. Each analysis subclasses `AnalysisPluginBase`, implements `compute(ctx)`, and returns data with `_display` lists. They run lazily after the first graph build and are rendered as expandable cards on the Analysis page. Researchers add new analyses by writing a single Python file — no frontend code needed.

All plugin execution is isolated in try/except. A crashing plugin logs an error and is skipped — it never affects the core viewer or other plugins.

### Creating an Insight Plugin

```python
# backend/plugins/insights/my_insight.py
from plugins import PluginBase, UISlot, AnalysisContext
from plugins import display_rows, display_list, display_text

class MyInsight(PluginBase):
    name = "my_insight"
    description = "Counts interesting things"
    version = "0.1.0"

    def get_ui_slots(self):
        return [
            UISlot(slot_type="stats_section", slot_id="my_stats",
                   title="My Insight", priority=40, default_open=True),
        ]

    def analyze_global(self, ctx: AnalysisContext):
        count = sum(1 for p in ctx.packets if p.protocol == "HTTP")
        return {
            "my_stats": {
                "http_count": count,
                "_display": [
                    *display_rows({"HTTP packets": count}),
                ],
            },
        }
```

Register in `server.py`'s `_register_plugins()`:
```python
("plugins.insights.my_insight", "MyInsight"),
```

### Creating an Analysis Plugin

```python
# backend/plugins/analyses/my_analysis.py
from plugins.analyses import AnalysisPluginBase
from plugins import display_table, display_text

class MyAnalysis(AnalysisPluginBase):
    name        = "my_analysis"
    title       = "My Analysis"
    description = "Computes something over the full graph."
    icon        = "📊"
    version     = "1.0"

    def compute(self, ctx) -> dict:
        # ctx has: packets, sessions, nodes, edges
        n = len(ctx.nodes)
        return {
            "_display": [
                display_text(f"Graph has {n} nodes"),
                display_table(["Node", "Connections"], [
                    [node["id"], str(len(node.get("ips", [])))]
                    for node in ctx.nodes[:10]
                ]),
            ],
        }
```

Register in `server.py`'s `_register_analyses()`:
```python
("plugins.analyses.my_analysis", "MyAnalysis"),
```

### Display Primitives

| Helper | Renders | Example |
|--------|---------|---------|
| `display_rows({"K": "V"})` | Key-value pairs | `display_rows({"OS": "Linux", "TTL": 64})` |
| `display_tags([(text, color)])` | Colored badges | `display_tags([("SYN", "#22d3ee")])` |
| `display_list([(label, value)], clickable=False)` | Labeled list | `display_list([("10.0.0.1", "42×")], clickable=True)` |
| `display_text(text, color="#8b949e")` | Freeform note | `display_text("Based on SYN packets")` |
| `display_table(headers, rows)` | Table | `display_table(["IP", "Count"], [...])` |

### Existing Insight Plugins

| Plugin | File | Slots | Rendering |
|--------|------|-------|-----------|
| `os_fingerprint` | `insights/os_fingerprint.py` | `node_detail_section`, `stats_section` | Dedicated (node), Generic (stats) |
| `tcp_flags` | `insights/tcp_flags.py` | `stats_section` | Dedicated |
| `dns_resolver` | `insights/dns_resolver.py` | `node_detail_section`, `stats_section` | Generic |
| `network_map` | `insights/network_map.py` | `stats_section` | Generic |
| `node_merger` | `insights/node_merger.py` | — | No UI; produces `entity_map` for graph endpoint |

### Existing Analysis Plugins

| Analysis | File | Description |
|----------|------|-------------|
| `node_centrality` | `analyses/node_centrality.py` | Degree, betweenness (Brandes), traffic-weighted ranking |
| `traffic_characterisation` | `analyses/traffic_characterisation.py` | Classifies sessions as foreground / background / ambiguous |

### UI Slot Types

| Slot Type | Where It Appears |
|-----------|-----------------|
| `node_detail_section` | Collapsible section in NodeDetail |
| `edge_detail_section` | Collapsible section in EdgeDetail |
| `session_detail_section` | Section in SessionDetail |
| `stats_section` | Section in StatsPanel |

---

## 9. API Reference

Base URL: `http://localhost:8642`

### Capture Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/upload` | Upload pcap/pcapng (multipart form, max 500MB) |
| `GET` | `/api/status` | `{capture_loaded, file_name, packet_count}` |

### Data Endpoints

| Method | Endpoint | Key Parameters | Description |
|--------|----------|---------------|-------------|
| `GET` | `/api/stats` | — | Global capture statistics |
| `GET` | `/api/timeline` | `bucket_seconds` (default 15) | Time-bucketed packet counts |
| `GET` | `/api/graph` | `time_start`, `time_end`, `protocols`, `search`, `subnet_grouping`, `subnet_prefix`, `merge_by_mac`, `include_ipv6`, `show_hostnames`, `subnet_exclusions` | Filtered graph. Nodes include `ips`, `macs`, `mac_vendors`, `ja3_apps`, `os_guess`. |
| `GET` | `/api/sessions` | `sort_by`, `limit`, `search`, `time_start`, `time_end` | Session list + `total` count. Time scoping uses packet-based filtering (see below). |
| `GET` | `/api/session_detail` | `session_id`, `packet_limit` | Session packets with payload preview |
| `GET` | `/api/protocols` | — | Protocol list + colors |
| `GET` | `/api/subnets` | `prefix` | Subnet groupings |
| `GET` | `/api/slice` | `time_start`, `time_end`, `protocols`, `search`, `include_ipv6` | Export filtered pcap (binary download) |

#### Packet-based session scoping (v0.9.43)

When any endpoint accepts `time_start`/`time_end`, sessions are scoped by checking which sessions have **at least one packet** inside the window — not by checking whether the session's `start_time`/`end_time` overlap the window. This is the authoritative rule: `filter_packets()` selects packets with `t_start <= timestamp <= t_end`, then sessions are filtered to those whose `session_key` appears in the filtered packet set. This applies to `/api/stats`, `/api/sessions`, and `/api/research/{chart}`.

**Why not overlap?** A session can span 5 minutes but only have packets in the first 10 seconds. An overlap check would include it in any window that touches those 5 minutes, even a 2-second window at minute 3 where it has zero packets. Packet-based scoping avoids this.

### Annotation Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/annotations` | All annotations |
| `POST` | `/api/annotations` | Create `{id, x, y, label, color, node_id?, edge_id?}` |
| `PUT` | `/api/annotations/{id}` | Update annotation fields |
| `DELETE` | `/api/annotations/{id}` | Delete annotation |
| `DELETE` | `/api/annotations` | Clear all |

### Synthetic Element Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/synthetic` | All synthetic nodes/edges |
| `POST` | `/api/synthetic` | Create synthetic node or edge |
| `PUT` | `/api/synthetic/{id}` | Update synthetic element |
| `DELETE` | `/api/synthetic/{id}` | Delete synthetic element |
| `DELETE` | `/api/synthetic` | Clear all |

### Plugin Endpoints (Insights)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/plugins` | Plugin info + UI slot declarations |
| `GET` | `/api/plugins/results` | All global plugin analysis results |
| `GET` | `/api/plugins/node/{id}` | Per-node plugin results |

### Analysis Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/analysis` | Registered analysis plugins (metadata, no capture required) |
| `GET` | `/api/analysis/results` | All analysis results. Runs lazily on first graph build. |
| `POST` | `/api/analysis/rerun` | Force re-run all analyses (e.g. after graph filters change) |

### Research Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/research` | List charts with param declarations |
| `POST` | `/api/research/{name}` | Run chart → `{"figure": {data, layout}}` |

### Utility

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/logs` | Server log buffer |
| `POST` | `/api/metadata` | Upload researcher metadata JSON |
| `DELETE` | `/api/metadata` | Clear metadata |

---

## 10. Data Flow

### On Pcap Upload

```
POST /api/upload
    → read_pcap() → List[PacketRecord]
       (scapy path <500MB, dpkt path ≥500MB)
       (each packet: port resolution → dissectors → payload signatures)

    → CaptureStore.load():
        → build_sessions(packets)       # sessions.py
        → compute_global_stats(packets) # stats.py
        → build_time_buckets(packets)   # aggregator.py
        → get_subnets(packets)          # aggregator.py

    → _run_plugins():
        → OSFingerprintPlugin.analyze_global()
        → TCPFlagsPlugin.analyze_global()
        → DNSResolverPlugin.analyze_global()
        (each wrapped in try/except — failures are logged, not re-raised)

    → Frontend loadAll():
        → GET /api/stats, /api/timeline, /api/protocols
        → GET /api/sessions, /api/plugins/results, /api/plugins
        → GET /api/annotations, /api/synthetic
```

### On Graph Request

```
GET /api/graph?merge_by_mac=true&...
    → build_entity_map(packets)          # node_merger.py (union-find by MAC)
    → get hostname_map from plugin results
    → build_graph(packets, filters, entity_map, hostname_map, metadata_map)
        → filter_packets()               # time, protocol, search, IPv6
        → for each packet:
            src_id = resolve(src_ip)     # entity_map lookup → canonical
            dst_id = resolve(dst_ip)
            node_map[src_id].ips.add(src_ip)  # node accumulates all IPs
            edge_map[key].packet_count++
        → enrich nodes: hostname_map, metadata_map, OUI vendor, JA3 apps
        → serialize: sets → sorted lists
```

### On Node Click

```
User clicks node
    → GraphCanvas.onPointerUp → onSelect("node", nodeId)
    → useCapture: setSelNodes([nodeId]), setRPanel("detail")
    → App.jsx: rightContent = <NodeDetail nodeId={nodeId} .../>
    → NodeDetail reads node from graph.nodes
    → NodeDetail slices pluginResults for this node's OS fingerprint
```

### On Edge Click → Session Matching

```
User clicks edge
    → useCapture: setSelEdge(edge), setRPanel("edge")
    → App.jsx: rightContent = <EdgeDetail edge={edge} nodes={visibleNodes} sessions={sessions}/>
    → EdgeDetail builds nodeIpsMap: Map<nodeId → Set<ip>> from nodes
    → edgeSessions = sessions.filter(s =>
        matchEndpoint(s.src_ip, src) && matchEndpoint(s.dst_ip, tgt))
    → matchEndpoint checks nodeIpsMap — handles merged nodes where
      the canonical ID differs from the session's recorded IP
```

---

## 11. Adding Features

### Decision Tree

```
Is it reading raw packet fields and presenting them?
  → YES: Parser layer (dissector or PacketRecord field)
  → NO: Is it correlating, inferring, or computing derived data?
    → YES: Plugin (plugins/)
    → NO: Is it a user-triggered deep-dive computation?
      → YES: Research chart (research/)
      → NO: Is it UI interaction / display change?
        → YES: Frontend component
```

### Adding a New Protocol Dissector

1. Add port to `WELL_KNOWN_PORTS` in `constants.py`
2. Add color to `PROTOCOL_COLORS` in `constants.py`
3. Add payload signature (optional) — `protocols/signatures.py` or in the dissector file itself
4. Create `protocols/dissect_myproto.py` with `@register_dissector("MYPROTO")`
5. Add `from . import dissect_myproto` to `protocols/__init__.py`
6. Add session field handler in `analysis/protocol_fields/myproto.py` — define `init()`, `accumulate(s, ex, is_fwd, source_type)`, `serialize(s)`. Auto-discovered, no changes to `sessions.py` needed.
7. Add UI section in `SessionDetail.jsx` if needed

### Adding a New Analysis Plugin

1. Create `backend/plugins/my_plugin.py` — see Plugin System section
2. Add to `plugin_specs` in `server.py`'s `_register_plugins()`
3. `npm run build`

### Adding a New Research Chart

1. Create `backend/research/my_chart.py` — subclass `ResearchChart`
2. Add to `_register_charts()` in `server.py`: `("research.my_chart", "MyChartClass")`
   - **Important:** the class name must match exactly — a mismatch silently skips the chart
3. No frontend changes needed

### Adding a New API Endpoint

1. Add route in `server.py`
2. Add Pydantic model in `models.py` if needed
3. Add fetch function in `api.js`
4. Use `_require_capture()` guard only if the endpoint reads capture data (`store.packets`, `store.sessions`, etc.)

---

## 12. File Format Reference

### Researcher Metadata JSON

Upload via META button or `POST /api/metadata`.

```json
{
    "10.0.0.1": {
        "name": "DC01",
        "role": "Domain Controller",
        "notes": "Primary AD server"
    },
    "192.168.1.50": {
        "name": "web-prod-1",
        "role": "Web Server"
    },
    "aa:bb:cc:dd:ee:ff": {
        "name": "Unknown device"
    }
}
```

Keys can be IP addresses or MAC addresses. The `name` field is used as the graph node label. All other fields appear in NodeDetail.

### Node Object (from `/api/graph`)

Key fields in each node dict:

| Field | Type | Description |
|-------|------|-------------|
| `id` | str | Canonical IP (or subnet string like `192.168.1.0/24`) |
| `ips` | list[str] | All IPs in this node (>1 when merged by MAC) |
| `macs` | list[str] | All MACs seen for this node |
| `mac_vendors` | list[str] | Vendor names parallel to `macs` |
| `hostnames` | list[str] | DNS-resolved hostnames |
| `os_guess` | str | OS guess from os_fingerprint plugin |
| `is_private` | bool | Whether any IP is RFC1918 / link-local |
| `is_subnet` | bool | Whether this is a subnet group node |
| `packet_count` | int | Total packets to/from this node |
| `total_bytes` | int | Total bytes to/from this node |

### Session Object (from `/api/sessions`)

Key fields beyond the basics:

| Field | Type | Description |
|-------|------|-------------|
| `ja3_apps` | list[dict] | `[{hash, name, category, is_malware}]` for known JA3s |
| `ssh_versions` | list[str] | SSH software strings seen in this session |
| `ftp_has_credentials` | bool | True if USER+PASS sequence seen |
| `ftp_transfer_files` | list[str] | RETR/STOR filenames |
| `dhcp_hostnames` | list[str] | Option 12 hostnames from DHCP packets |
| `dhcp_vendor_classes` | list[str] | Option 60 vendor class strings |
| `smb_tree_paths` | list[str] | Share paths from TREE_CONNECT requests |
| `smb_filenames` | list[str] | Filenames from CREATE requests |
