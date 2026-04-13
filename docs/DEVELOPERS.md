# SwiftEye Developer Documentation

**Version 0.19.0 | April 2026**

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
13. [Graph Algorithms](#13-graph-algorithms)
14. [Analysis Graph & Query System](#14-analysis-graph--query-system)
15. [Storage Backend](#15-storage-backend)
16. [State Lifetime Reference](#16-state-lifetime-reference)

---

## 1. Overview

SwiftEye is a network traffic visualization platform for security researchers. It parses pcap/pcapng capture files and renders an interactive force-directed graph of network communications, with session reconstruction, protocol dissection, and extensible analysis plugins.

**Target users**: Security researchers, network analysts, incident responders.

**What it does**: Displays network traffic visually — who talked to whom, over what protocols, with what TCP behavior. Researchers bring the expertise; SwiftEye shows the data.

**What the core does NOT do**: Make security judgments or generate verdicts. The core viewer and analysis layers present evidence for the researcher to interpret. Pattern detection and alerting belong in the plugin system — the **alerts tier** (`plugins/alerts/`) surfaces security-relevant patterns as evidence cards, never as verdicts. Descriptions say "may indicate X", never "this is X".

**Long-term vision**: SwiftEye's single-capture, single-user mode is Phase 1. The platform will grow into a **multi-capture, multi-user data platform** where teams of researchers work across many captures, correlate findings, and query at scale. Architectural decisions today (engine-agnostic query contracts, stateless graph building, plugin isolation) are made with this future in mind. See HANDOFF.md §6 "Long-term vision: multi-capture platform" for the full roadmap.

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
│   │   ├── pcap_reader.py           # Public entry point (read_pcap), delegates to parallel_reader
│   │   ├── dpkt_reader.py           # L2/L3/L4 parsing via dpkt (all files use this path)
│   │   ├── l5_dispatch.py           # L5 enrichment: protocol detection, scapy L5 object construction,
│   │                                #   dissector dispatch, JA3/JA4 fingerprinting
│   │   ├── parallel_reader.py       # Multiprocessing wrapper: pre-scan pcap offsets, split, spawn workers
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
│   │   └── adapters/               # Ingestion adapters (multi-source support)
│   │       ├── __init__.py          # IngestionAdapter base, registry, detect_adapter()
│   │       ├── pcap_adapter.py      # pcap/pcapng files via pcap_reader
│   │       ├── zeek/               # All Zeek log adapters
│   │       │   ├── __init__.py      # Imports all Zeek modules to register them
│   │       │   ├── common.py        # Shared Zeek log parsing utilities
│   │       │   ├── conn.py          # conn.log → base sessions
│   │       │   ├── dns.py           # dns.log → DNS enrichment
│   │       │   ├── http.py          # http.log → HTTP enrichment
│   │       │   ├── ssl.py           # ssl.log → TLS enrichment
│   │       │   ├── smb.py           # smb_files.log + smb_mapping.log → SMB enrichment
│   │       │   └── dce_rpc.py       # dce_rpc.log → DCE/RPC enrichment
│   │       └── tshark/              # Tshark CSV export adapters
│   │           ├── __init__.py      # Imports all tshark modules to register them
│   │           ├── common.py        # Shared CSV parsing, metadata index loader
│   │           ├── metadata.py      # metadata.csv → full L2-L4 packet records
│   │           ├── arp.py           # arp.csv → ARP packet records
│   │           ├── dns.py           # dns_request/response.csv → DNS records
│   │           ├── http.py          # http_request/response.csv → HTTP records
│   │           ├── smb.py           # smb.csv → SMB packet records
│   │           └── dce_rpc.py       # dce_rpc.csv → DCE/RPC packet records
│   ├── analysis/                    # LAYER 2: Structural data organisation
│   │   ├── aggregator.py            # Graph building, filtering, entity_map, OUI+JA3 lookup
│   │   ├── sessions.py              # Session reconstruction + per-protocol aggregation
│   │   ├── stats.py                 # Global statistics
│   │   ├── graph_core.py            # Shared networkx graph builder (used by clustering + pathfinding)
│   │   ├── clustering.py            # 4 clustering algorithms (Louvain, k-core, hub-spoke, shared-neighbor)
│   │   └── pathfinding.py           # Path analysis: hop layers, edge sets, directed/undirected
│   ├── plugins/                     # LAYER 3: Plugin system (insights + analyses)
│   │   ├── __init__.py              # PluginBase, registry, UI slot system, display helpers
│   │   ├── insights/                # Per-node/per-session interpretation
│   │   │   ├── os_fingerprint.py    # Passive OS detection (SYN + SYN+ACK)
│   │   │   ├── tcp_flags.py         # TCP flag analysis with sender attribution
│   │   │   ├── dns_resolver.py      # DNS hostname resolution from capture
│   │   │   ├── network_map.py       # ARP table, gateway detection, LAN hosts
│   │   │   └── node_merger.py       # MAC-based node merging (pre-aggregation)
│   │   ├── analyses/                # Graph-wide computation
│   │   │   ├── __init__.py          # AnalysisPluginBase, registry
│   │   │   ├── node_centrality.py   # Degree + betweenness + traffic ranking
│   │   │   └── traffic_characterisation.py  # Session fg/bg/ambiguous classification
│   │   └── alerts/                  # Security pattern detectors
│   │       ├── __init__.py          # AlertRecord, AlertPluginBase, registry, run_all_detectors()
│   │       ├── arp_spoofing.py      # Multi-MAC IP claims, gratuitous ARP floods
│   │       ├── suspicious_ua.py     # Scripting tool UAs, empty UA
│   │       ├── malicious_ja3.py     # Known malware JA3 hashes, deprecated TLS
│   │       └── port_scan.py         # TCP + UDP port scanning detection
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
│       ├── version.js               # Single source of truth: VERSION = '0.11.2'
│       ├── App.jsx                  # Pure layout + routing (~220 lines)
│       ├── hooks/
│       │   └── useCapture.js        # All state, effects, handlers (~340 lines)
│       ├── api.js                   # All backend API calls
│       ├── utils.js                 # Formatting helpers (fN, fB, fD, fT, fTtime)
│       ├── displayFilter.js         # Wireshark-style filter: tokeniser → parser → evaluator
│       ├── clusterView.js           # applyClusterView: cluster collapse transform (client-side)
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
│           ├── PathDetail.jsx       # Pathfinding results: hop layers, edges, IP inputs
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

**Guiding principle:** *Simple things should feel obvious; hard things should remain possible for a skilled user.* The common case (load a pcap, explore the graph) must require zero configuration. The advanced case (custom charts, query language, plugin hooks) must be available and powerful.

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
- **Protocol field accumulators** (`data/protocol_fields/`): Accumulate all data. Apply caps only in `serialize()`, never in `accumulate()`. When capping in serialize, include a `_total` key with the uncapped count.
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

Public entry point. Delegates to `parallel_reader.read_pcap_parallel()` which uses dpkt for L2/L3/L4 parsing and the registered protocol dissectors (via `l5_dispatch.py`) for L5 enrichment. All file sizes use the same code path.

Max file size: 2 GB. Max packets: 2M. Dissector exceptions are caught and logged as `WARNING` — malformed packets never crash the parse.

### `parser/l5_dispatch.py` — enrich_l5()

L5 (application layer) enrichment. Called after dpkt has parsed L2/L3/L4 fields into a PacketRecord. Constructs the appropriate scapy L5 object from raw payload bytes (`DNS(payload)`, `TLS(payload)`, or `Raw(load=payload)`) and dispatches to the registered protocol dissector. Also handles JA3/JA4 fingerprinting for TLS. Strips transport-layer quirks (e.g. TCP DNS 2-byte length prefix) before passing to dissectors.

### `parser/parallel_reader.py` — read_pcap_parallel()

Multiprocessing wrapper. Pre-scans pcap packet header byte offsets (I/O only, no packet data), splits into N chunks, spawns workers via `multiprocessing.get_context('spawn')`. Falls back to single-threaded for pcapng, small files, or on failure. Can be disabled via `use_parallel=False` for debugging.

pcapng support is best-effort via dpkt. Standard captures (EPB/SPB blocks) work correctly. NRB, DSB, and custom blocks are silently skipped. See roadmap item `pcapng-battle-test`.

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

See `backend/parser/protocols/dissect_template.py` for a complete starter file.

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

**`scapy_layer` parameter:**

Most dissectors should NOT set `scapy_layer` — they receive a lightweight proxy
with `haslayer("Raw")` / `pkt["Raw"].load` and parse raw bytes themselves.
This is fast (no scapy overhead per packet).

Only set `scapy_layer` when your dissector needs a real scapy-parsed object
(e.g. DNS needs `pkt.haslayer(DNS)` / `pkt[DNS].qd.qname`):

```python
from scapy.layers.dns import DNS
@register_dissector("mDNS", scapy_layer=DNS)
def dissect_mdns(pkt): ...
```

Currently only DNS, mDNS, and LLMNR use this (all with `scapy_layer=DNS` since
they share DNS wire format). If you're unsure, don't set it — the proxy works
for all dissectors that use `haslayer("Raw")`.

**Signature priority guidelines:**
- 10–15: High-confidence magic bytes (TLS `0x16`, SSH `SSH-`)
- 20–30: Banner detection (SMTP `220...ESMTP`, DHCP magic cookie)
- 40–60: Heuristic content patterns

### Writing a Protocol Dissector (Contract)

Dissectors live in `backend/parser/protocols/dissect_<protocol>.py`.
They are called for all files via the same unified code path (since v0.17.0).

**What the dissector receives:**
A scapy L5 object. Depending on the protocol:
- DNS: `DNS(payload_bytes)` — use `pkt.haslayer(DNS)` / `pkt[DNS]`
- TLS: `TLS(payload_bytes)` — use `pkt.haslayer(TLS)` if scapy-TLS installed
- Everything else: `Raw(load=bytes)` — use `pkt.haslayer("Raw")` / `pkt["Raw"].load`

Transport-layer quirks are stripped before the dissector is called:
- TCP DNS: the 2-byte length prefix is removed. You receive clean DNS wire format.
- Future protocols with TCP prefix: handle it in `l5_dispatch.enrich_l5()`.

**What the dissector does NOT receive:**
- IP addresses, ports, transport type — those are on PacketRecord already
- Reassembled TCP stream — you see ONE packet's payload at a time
- Guaranteed complete payload — the packet may have been captured truncated

**Rules:**
1. Always return `{}` on any parse failure — never raise an exception
2. Do not assume the protocol is on its well-known port
3. Use `pkt.haslayer("Raw")` and `pkt["Raw"].load` to access payload bytes — this works with the lightweight proxy (default, fast) and with real scapy objects
4. Only add `scapy_layer=SomeClass` to `@register_dissector` if you truly need scapy's parsed object (e.g. DNS). This is slower — avoid unless necessary
5. Do not import inside functions — module level only
6. Register with `@register_dissector("PROTOCOL_NAME")`

**Edge cases:**
- TCP protocols may span multiple packets (streams). You see one packet. Handle partial data gracefully (return partial info rather than `{}`).
- Non-standard ports: protocol detection runs payload signatures first. Your dissector may be called on traffic from any port.
- Application layer depends on lower layers. If you need to know whether the transport was TCP or UDP (e.g. for DNS), that decision belongs in `l5_dispatch.py`, not inside the dissector.

### `parser/oui.py` — MAC Vendor Lookup

`lookup_vendor(mac: str) -> str` — returns vendor name or `""`.

Accepts any common MAC format (`aa:bb:cc:dd:ee:ff`, `AA-BB-CC`, `aabbccddeeff`). Uses the first 3 bytes (OUI prefix). ~700 entries (all 6-character hex keys, malformed keys removed) covering Apple, Cisco, Intel, Samsung, Dell, HP, VMware, Huawei, TP-Link, Ubiquiti, Espressif (ESP32), VirtualBox, QEMU/KVM, Raspberry Pi, and others.

Called from `aggregator.py` when building nodes. Result stored in `node["mac_vendors"]` (parallel array to `node["macs"]`).

### `parser/ja3_db.py` — JA3 Application Lookup

`lookup_ja3(hash: str) -> Optional[Dict]` — returns `{name, category, is_malware}` or `None`.

~60 curated entries (no duplicates — conflicting malware entries for Chrome/Safari/LibreSSL hashes removed): browsers (Firefox, Chrome, Safari, Edge, IE11), TLS libraries (Python requests, Go net/http, Java JSSE, curl, Node.js, .NET), and ~10 known malware families (Cobalt Strike, QakBot, AsyncRAT, Sliver, Havoc, etc.).

Called from `aggregator.py` (edges → `ja3_apps`) and `sessions.py` (sessions → `ja3_apps`). The `JA3Badge` component in `EdgeDetail` and `SessionDetail` renders a green pill for legitimate apps and a red `⚠` pill for known malware.

### `data/aggregator.py` — Graph Building

`build_graph(packets, ...)` is the central function. Key steps:
1. `filter_packets()` — time, protocol, IP, port, search, IPv6 toggle
2. Entity map applied — `resolve(ip)` maps merged IPs to canonical
3. Node and edge maps built from filtered packets
4. OUI vendor + JA3 app name resolution
5. Hostname and researcher metadata enrichment
6. Serialised to JSON-friendly dicts with sets → sorted lists

`entity_map` comes from `node_merger.build_entity_map()`. When `merge_by_mac=True`, IPs sharing a MAC are union-found into groups. `_pick_canonical()` prefers the most-seen IPv4; if all are IPv6, picks the most-seen IPv6. Cross-family merges (IPv4 ↔ IPv6 sharing a MAC) are permitted — the merged node's `ips` list contains all addresses.

**Session matching after merge:** `EdgeDetail` receives the `nodes` list and builds `nodeIpsMap: Map<nodeId → Set<ip>>`. `matchEndpoint()` checks a session IP against all IPs in the merged node group — not just the canonical ID. This ensures sessions from `2a0d:6fc0::1` appear on the same edge as sessions from `192.168.1.177` after MAC merge.

### `data/sessions.py` — Session Reconstruction

Groups packets by `session_key` into bidirectional flows. Core transport fields (packet counts, bytes, direction, TCP state, IP headers, window/seq/ack) live in `sessions.py`. Protocol-specific fields (TLS, HTTP, DNS, etc.) are handled by auto-discovered modules in `data/protocol_fields/` — see "Adding a New Protocol Dissector" in §11.

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

### Session Boundary Detection

#### The problem

A **5-tuple** is the combination of source IP, destination IP, source port, destination port, and transport protocol (TCP/UDP). SwiftEye groups packets into sessions by 5-tuple — all packets with the same 5-tuple land in the same session. But in real traffic, the same 5-tuple can be reused by completely different conversations. For example, a browser might open a TCP connection to a server on port 443 (HTTPS), close it, and then open a new one to the same server on the same ports. Without boundary detection, both conversations would appear as one giant session.

`build_sessions()` in `sessions.py` solves this by running `_check_boundary()` on each packet. When it detects that a new conversation has started on the same 5-tuple, it "splits" — the subsequent packets go into a new session.

#### How splitting decisions are made

The boundary detector uses four independent checks (referred to in the code as "signals 1-4"). Each check looks for a different clue that a new conversation has started. They are evaluated in order on every packet; **if any one of them says "split", it splits** — the rest are skipped for that packet. This is the "OR logic" referenced in code comments.

The overall design is **conservative**: it's better to accidentally keep two conversations together (the researcher can still see the data) than to accidentally split one conversation into two (which loses context and confuses session-level analysis).

We intentionally do **not** implement a full TCP state machine (tracking states like ESTABLISHED, TIME_WAIT, CLOSE_WAIT, etc.). A full state machine is fragile when packets are out of order, missing, or come from different capture sources. The four checks below achieve good accuracy with far less complexity.

#### Per-5-tuple flow state

Each unique 5-tuple gets a `flow_state` dict that persists across packets. This is how the boundary detector "remembers" what it saw earlier on the same 5-tuple:

| Key | Type | What it tracks |
|-----|------|----------------|
| `closed_at` | float | When the first FIN or RST was seen on this 5-tuple (0 means "not closed yet"). Only the **first** close packet sets this — if side A sends FIN at t=2 and side B replies with FIN-ACK at t=2.5, the value stays at t=2. |
| `last_ts` | float | Timestamp of the most recent packet on this 5-tuple. Used to measure gaps between packets. |
| `last_seq` | int or None | The most recent TCP sequence number. `None` means no TCP packet has been seen yet. |
| `last_resp_isn` | int or None | The Initial Sequence Number (ISN) from the most recent SYN-ACK. Used to detect when a responder starts a new connection (see check 1 below). `None` means no SYN-ACK has been seen. |

Protocol-specific checkers (check 4) add their own keys to the same dict, always prefixed with their protocol name to avoid collisions (e.g. `last_dhcp_xid`, `last_dns_ts` — never something generic like `last_ts`).

When a split happens, the state resets for the new session: `closed_at` goes back to 0, `last_seq` and `last_resp_isn` go back to `None`. `last_ts` keeps the current packet's timestamp since that packet is now the first packet of the new session.

#### Check 1: TCP connection closed, then reopened

This is the most common split scenario. Once a FIN (graceful close) or RST (forced close) has been recorded on a 5-tuple, subsequent packets are evaluated:

| What arrives | What happens | Why |
|--------------|-------------|-----|
| A SYN without ACK | **Split immediately.** | A bare SYN is the first packet of a new TCP connection. There's no ambiguity. |
| A SYN-ACK with a different ISN than the previous SYN-ACK | **Split immediately.** | This means the responder received a new SYN (which we may have missed in the capture) and is responding with a fresh ISN. Inspired by how Wireshark detects new streams. If the ISN is the same as before, it's just a retransmission — no split. |
| Any packet more than 5 seconds after the close | **Split.** | The grace period has expired. The old connection is done, and whatever comes next is a new conversation. This also handles the case where a SYN was dropped — no SYN arrived, but other data eventually does, and the 5-second gap tells us it's not leftover teardown traffic. |
| Any packet within 5 seconds of the close | **No split.** | This is the "grace period." After a FIN or RST, there's often still traffic in flight: the other side's FIN-ACK, final ACKs, retransmissions, or data that was already sent before the close was received. All of that belongs to the original session. Even after a RST (where one side forcefully killed the connection), the other side may still have packets in flight that it sent before learning about the RST. |

#### Check 2: Long silence (timestamp gap)

If there's been no traffic on a 5-tuple for a long time and then a packet suddenly appears, it's likely a new conversation — even if no FIN/RST was seen (maybe it was lost, or maybe it's UDP which has no close mechanism).

| Transport | Gap threshold | Why this value |
|-----------|---------------|----------------|
| TCP | 120 seconds | TCP connections can sit idle for minutes using keepalives. 120s avoids falsely splitting connections that are alive but quiet. |
| UDP | 60 seconds | UDP has no keepalive mechanism, so silence is a stronger indicator. 60s balances between bursty protocols (DNS) and protocols that poll slowly (SNMP). |

For protocols where we know better thresholds, check 4 (protocol-specific) overrides these generic values.

#### Check 3: TCP sequence number jump

TCP sequence numbers normally increment steadily. If the sequence number suddenly jumps by more than 1,000,000 AND there's been a time gap of more than 5 seconds, it's likely a different connection that reused the same ports — the new connection got a very different random ISN (Initial Sequence Number).

This catches the case where a connection ended but we never saw the FIN or RST (dropped in capture, or happened outside the capture window).

Important details:
- **Handles wraparound:** TCP sequence numbers are 32-bit, so they wrap from ~4.3 billion back to 0. The check accounts for this so a legitimate wrap isn't mistaken for a jump.
- **Requires a time gap too:** A large sequence jump alone could just be a burst of data. Requiring >5 seconds of silence adds confidence that it's actually a different connection.
- **Sequence number 0 is valid:** A TCP ISN can genuinely be 0. The code uses `None` (not 0) to mean "we haven't seen a sequence number yet."

#### Check 4: Protocol-specific checks

Some protocols have their own rules for what constitutes a "new conversation." These live in the protocol's own module in `protocol_fields/` (not in `sessions.py`) as an optional `check_boundary()` function. The registry auto-discovers them — drop one in and it works, no wiring needed.

Current protocol-specific checks:

| Protocol | What triggers a split | Threshold | Why |
|----------|-----------------------|-----------|-----|
| DNS | No DNS traffic for a while, then a new query arrives | 10 seconds | Based on Zeek's default DNS inactivity timeout. DNS transactions are fast; 10s of silence means the conversation is over. |
| HTTP | No HTTP traffic for a while | 30 seconds | Based on Zeek's default. HTTP connections can be kept alive between requests, but 30s of silence usually means the user moved on. |
| DHCP | A different transaction ID (xid) appears, OR inactivity timeout | xid change / 10 seconds | DHCP transactions are identified by their xid field. Multiple clients on the same subnet all broadcast on the same 5-tuple (`0.0.0.0:68 → 255.255.255.255:67`). Without xid splitting, traffic from every DHCP client would be lumped into one session. |

#### How split sessions are identified

When a session is split, the new sessions get a `#` suffix on their ID: the original is `10.0.0.1|10.0.0.2|12345|80|TCP`, the second becomes `…#1`, the third `…#2`, etc. The first session (generation 0) keeps its original ID with no suffix, so existing session references stay valid.

Internally, two dicts track the state per 5-tuple:
- `flow_generation[base_key]` — a counter: how many splits have happened so far on this 5-tuple
- `flow_state[base_key]` — the mutable state dict passed to `_check_boundary()`

The first packet on each 5-tuple is special: it runs through `_check_boundary()` to seed the state (e.g. recording the first DHCP xid), but the result is always discarded (you can't split before the first packet). This ensures that when the second packet arrives, there's something to compare against.

#### Adding a new protocol boundary checker

1. Add a `check_boundary(flow_state, ex, ts)` function to your protocol's module in `protocol_fields/`.
2. Store any state you need in `flow_state` using protocol-prefixed keys (e.g. `last_myproto_ts`, never `last_ts` which is used by the generic checks).
3. Return `True` to split, `False` to keep packets in the same session. Check for your protocol's keys in `ex` first — return `False` early if the packet isn't relevant to your protocol.
4. The registry auto-discovers it on import. No changes to `sessions.py` needed.

### `data/protocol_fields/` — Protocol Field Handlers

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

When adding a new adapter, add its `source_type` string to this table and to `data/protocol_fields/__init__.py`.

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

### State Management — `useCapture.js` + `FilterContext.js`

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

#### FilterContext — observable global filter state

`frontend/src/FilterContext.js` exposes the active filter as a React context so any component can read it without prop drilling.

**Shape** (provided by `App.jsx` via `<FilterContext.Provider>`):
| Field | Type | Description |
|-------|------|-------------|
| `timeRange` | `[number, number]` | Current slider indices |
| `enabledP` | `Set<string>` | Active composite protocol keys (`"4/TCP/HTTPS"`) |
| `search` | `string` | Current search text |
| `includeIPv6` | `bool` | IPv6 visibility |
| `protocolList` | `string[]` | Protocols in the loaded capture (from `/api/protocols`) |
| `allProtocolKeysCount` | `number` | Total composite key count (for "all enabled" check) |

**Exported helpers:**
- `useFilterContext()` — hook to consume the context. Throws if used outside a provider.
- `toProtocolNames(enabledP, allProtocolKeysCount)` — converts composite keys to simple protocol name strings for API calls (takes last `/`-delimited segment, deduplicates). Returns `''` when all protocols are enabled.
- `applyDisplayFilter(sessions, filterCtx)` — client-side session filter matching all active filter dimensions. Used by `NodeDetail` and `EdgeDetail` in SCOPED mode.

**Rule:** the filter state itself lives in `useCapture`. `FilterContext` is the *read side* only. To change the filter, use `c.setEnabledP`, `c.setSearch`, etc. directly from `useCapture`.

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
    ├── AlertsPanel.jsx      — Alerts page: security pattern findings with severity filter, search, evidence cards
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

**Lasso select** — `Shift + right-click-drag` draws a freehand selection polygon. Implemented via `pointerdown` with `e.button === 2 && e.shiftKey`. The lasso path is rendered as an SVG polygon overlay. On `pointerup`, nodes whose screen-space position falls within the polygon are selected using a **winding number** point-in-polygon test (non-zero winding = inside). This gives union behavior on self-overlapping paths — circling an area twice keeps it selected, unlike ray-casting which would XOR it back out. `contextmenu` is suppressed if `lassoRef.current` is set (to prevent the context menu firing immediately after lasso release).

**Relayout** — `doRelayout()` function inside GraphCanvas. Deletes `fx`/`fy` from all nodes (unpins them) then calls `simRef.current.alpha(0.9).alphaTarget(0).restart()`. Exposed via the ↺ Relayout button overlay (top-right of canvas).

**Manual cluster (lasso group)** — `onCreateManualCluster(nodeIds)` prop. Called from the canvas context menu when ≥2 nodes are lasso-selected. Implemented in `useCapture.handleCreateManualCluster`: assigns all selected nodes to a new cluster_id in the `manualClusters` state (a `nodeId → clusterId` map). The `graph` useMemo merges `manualClusters` with backend `rawGraph.clusters` and feeds the combined map to `applyClusterView`. This means manual groups produce real hexagon mega-nodes — expandable, renamable, and part of the view transform. Works even when no clustering algorithm is running. Manual clusters reset on algorithm change.

**Expand cluster** — `onExpandCluster(clusterId)` prop. Adds the cluster_id to `clusterExclusions` (a `Set<number>` in useCapture). The `graph` useMemo passes this set to `applyClusterView(nodes, edges, clusters, exclusions)`, which skips excluded cluster_ids during grouping — their member nodes stay as individual nodes with their real edges. Purely client-side, no API call. `clusterExclusions` resets when the clustering algorithm changes (via `useEffect` on `clusterAlgo`). Collapse back is possible via `handleCollapseCluster(clusterId)` which removes the id from the set.

**Cluster rename** — `renameCluster(clusterId, name)` in useCapture sets `clusterNames[clusterId] = name`. ClusterDetail header renders an `EditableClusterName` component (click to edit, Enter/blur to save, Escape to cancel). ClusterLegend reads `clusterNames` for display but is not editable. Names reset on algorithm change alongside exclusions.

- `clusterExclusions` — set of cluster_ids that have been manually expanded; cleared when `clusterAlgo` changes (use the algo change effect, not manual clearing)
- `clusterNames` — map of cluster_id → custom name string; cleared alongside exclusions on algo change
- `manualClusters` — map of node_id → cluster_id for user-created groups (lasso → "Group selected"). Merged with `rawGraph.clusters` in the `graph` useMemo. Cleared on algo change.

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

The plugin system has three tiers:

**Insights** (`plugins/insights/`) — per-node/per-session interpretation. Each insight subclasses `PluginBase`, declares UI slots, and implements `analyze_global()`. They run once on pcap load and annotate nodes/edges/sessions. Researchers interact with insight data in NodeDetail, EdgeDetail, and StatsPanel.

**Analyses** (`plugins/analyses/`) — graph-wide computation. Each analysis subclasses `AnalysisPluginBase`, implements `compute(ctx)`, and returns data with `_display` lists. They run lazily after the first graph build and are rendered as expandable cards on the Analysis page. Researchers add new analyses by writing a single Python file — no frontend code needed.

**Alerts** (`plugins/alerts/`) — security pattern detection. Each detector subclasses `AlertPluginBase`, implements `detect(ctx) → List[AlertRecord]`, and returns evidence-based findings. They run after graph build (after analyses) and are rendered as expandable cards on the Alerts page. Philosophy: alerts surface patterns for the researcher to investigate, never verdicts. Descriptions say "may indicate X", not "this is X".

**Two alert sources (architectural context):**
- **Generated alerts (Phase 1):** detectors run on capture data inside SwiftEye. `AlertPluginBase` plugins receive `ctx`, find patterns, return `AlertRecord` objects.
- **Provided alerts (future):** pre-formed alerts from external systems (e.g. Suricata `eve.json`). Ingested via the adapter system, not derived by SwiftEye. `AlertRecord.source` distinguishes: `"detector"` vs `"external"`.

**Future extension points:**
- `AlertPluginBase.get_charts()` — optional method to declare per-detector Research panel charts (scope 1: per-instance, scope 2: same-type aggregate). Not yet implemented.
- Scope 3 cross-type charts live as standalone `ResearchChart` subclasses in `research/alerts/`, reading `store.alerts` directly.
- Alert correlation — grouping related `AlertRecord` objects into higher-level findings (Phase 2).
- Graph-structural detectors — lateral movement, beaconing, DNS tunneling using graph topology as signal (Phase 3).

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

### Creating an Alert Detector

```python
# backend/plugins/alerts/my_detector.py
import uuid
from plugins.alerts import AlertPluginBase, AlertRecord

class MyDetector(AlertPluginBase):
    name    = "my_detector"
    version = "1.0"

    def detect(self, ctx):
        # ctx has: packets, sessions, nodes, edges
        alerts = []
        for s in ctx.sessions:
            if s.get("protocol") == "HTTP" and not s.get("http_fwd_user_agents"):
                alerts.append(AlertRecord(
                    id=uuid.uuid4().hex[:8],
                    title="Empty User-Agent",
                    subtitle=f"HTTP session with no UA from {s.get('src_ip')}",
                    severity="low",
                    detector=self.name,
                    source="detector",
                    source_name=self.name,
                    timestamp=s.get("start_time"),
                    src_ip=s.get("src_ip"),
                    dst_ip=s.get("dst_ip"),
                    evidence=[{"key": "Sessions", "value": "1", "note": "No UA string"}],
                    node_ids=[s.get("src_ip")],
                ))
        return alerts
```

Register in `server.py`'s detector registration block:
```python
("plugins.alerts.my_detector", "MyDetector"),
```

**`AlertRecord` fields:**

| Field | Type | Description |
|-------|------|-------------|
| `id` | `str` | Unique ID (uuid4 hex, 8 chars) |
| `title` | `str` | Detector type name, e.g. "ARP Spoofing" |
| `subtitle` | `str` | One-line finding, e.g. "IP claimed by 2 MACs" |
| `severity` | `str` | `"high"` / `"medium"` / `"low"` / `"info"` |
| `detector` | `str` | Plugin name, e.g. `"arp_spoofing"` |
| `source` | `str` | `"detector"` (generated) or `"external"` (provided) |
| `source_name` | `str` | Human-readable source name |
| `timestamp` | `float?` | Epoch of first triggering packet/session |
| `src_ip` | `str?` | Primary involved IP |
| `dst_ip` | `str?` | Secondary involved IP |
| `evidence` | `list` | List of `{"key": str, "value": str, "note": str}` |
| `node_ids` | `list` | IPs involved (for graph highlight) |
| `edge_ids` | `list` | Edge IDs involved |
| `session_ids` | `list` | Session IDs involved |

### Existing Alert Detectors

| Detector | File | Severity | Description |
|----------|------|----------|-------------|
| `arp_spoofing` | `alerts/arp_spoofing.py` | high/medium | IP claimed by multiple MACs, gratuitous ARP floods |
| `suspicious_ua` | `alerts/suspicious_ua.py` | medium/low | Scripting tool UAs (curl, nmap, etc.), empty UA |
| `malicious_ja3` | `alerts/malicious_ja3.py` | high/low | Known malware JA3 hashes, deprecated TLS 1.0/1.1 |
| `port_scan` | `alerts/port_scan.py` | high/medium | TCP + UDP port scanning (threshold-based) |

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
| `POST` | `/api/upload/confirm-schema` | Resume a staged Zeek/tshark upload after column mapping. Body: `{token, mapping: {detected_col: expected_col}}`. Calls `parse_with_mapping()`. |
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
| `GET` | `/api/hostnames` | — | DNS-resolved hostname map `{ip: hostname}` |
| `GET` | `/api/slice` | `time_start`, `time_end`, `protocols`, `search`, `include_ipv6` | Export filtered pcap (binary download) |
| `GET` | `/api/paths` | `source`, `target`, `cutoff` (default 5), `max_paths` (default 10), `directed` (default false) | Simple paths between two nodes. See §13. |
| `GET` | `/api/edge-sessions` | `edge_id` (`src\|dst\|protocol`), `sort_by`, `limit` | Sessions for a specific edge. Handles directional edges and subnet/MAC-split nodes. |
| `GET` | `/api/edge/{edge_id}/detail` | `time_start`, `time_end`, `protocols`, `ip_filter`, `port_filter`, `flag_filter`, `search` | Lazy full edge detail (TLS, HTTP, DNS field summaries). `edge_id` is path-encoded `src\|dst\|protocol`. |
| `GET` | `/api/node-animation` | `nodes` (comma-separated IPs), `protocols` | Session start/end events for spotlight nodes, used by the Animation panel. |

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

### Investigation Notebook Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/investigation` | Load investigation notebook `{markdown, images}` |
| `PUT` | `/api/investigation` | Save investigation notebook. Body: `{markdown: str}` |
| `POST` | `/api/investigation/image` | Upload an image (multipart). Returns `{id, url}` where `url` is a base64 data URI for embedding. |
| `GET` | `/api/investigation/image/{img_id}` | Retrieve an uploaded image by ID. |
| `POST` | `/api/investigation/export` | Export the notebook as a PDF. Returns binary PDF. |

### Query Endpoints

See §14 for the full query contract, expression language, and SQL/Cypher/PySpark translation.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/query` | Run a structured JSON query against the analysis graph. Returns `{results: [...], action}`. |
| `POST` | `/api/query/parse` | Parse raw query text (Cypher, SQL, Spark SQL) into a JSON contract. Used for live parse preview. |
| `GET` | `/api/query/schema` | Field schema for the query builder — all queryable fields with types and operators. |

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

### Alert Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/alerts` | All alerts sorted by severity + summary counts. Returns `{alerts: [...], summary: {high, medium, low, info, total}}`. Requires loaded capture. |

### Research Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/research` | List charts with param declarations |
| `POST` | `/api/research/{name}` | Run chart → `{"figure": {data, layout}}` |
| `GET` | `/api/research/custom/schema` | Sources + fields + `has_data` flags for custom chart builder. Works without a loaded capture (all `has_data` false). |
| `POST` | `/api/research/custom` | Field-mapping payload → Plotly figure dict. Requires a loaded capture. Body: `{source, chart_type, x_field, y_field, color_field, size_field, hover_fields, title, _timeStart, _timeEnd, _filterProtocols, _filterSearch, _filterIncludeIpv6}` |

> **Route ordering note:** The `/custom` and `/custom/schema` routes in `routes/research.py` must be declared **before** the `/{chart_name}` wildcard — FastAPI matches in declaration order and would otherwise capture "custom" as a chart name.

### Utility

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/logs` | Server log buffer |
| `GET` | `/api/meta/edge-fields` | Edge field registry — all documented edge fields with types and descriptions. |
| `GET` | `/api/metadata` | Retrieve loaded researcher metadata |
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
6. Add session field handler in `data/protocol_fields/myproto.py` — define `init()`, `accumulate(s, ex, is_fwd, source_type)`, `serialize(s)`. Auto-discovered, no changes to `sessions.py` needed.
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

**Custom ad-hoc charts** (no Python required) are built from the Research panel UI via `POST /api/research/custom`. See `backend/research/custom_chart.py` for the source/field extraction logic and `ResearchPage.jsx` (`CustomChartBuilder`) for the frontend wizard.

**Dynamic field discovery:** `custom_chart.py` scans `pkt.extra` at schema-request time to auto-discover fields added by new dissectors. Drop a new dissector in `parser/protocols/` and its fields appear in the custom chart builder without any registration step.

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

---

## 13. Graph Algorithms

Graph algorithms live in `backend/analysis/` and share a common networkx graph builder. They operate on the node/edge topology produced by the aggregator — currently IPs and connections, but the contract is **node-agnostic** by design (see roadmap).

### Architecture

```
analysis/
├── graph_core.py      # Shared: build_nx_graph(nodes, edges) → nx.Graph
├── clustering.py      # 4 algorithms → {node_id: cluster_id} assignments
└── pathfinding.py     # Path analysis → hop layers + edge sets
```

**Shared core** — `graph_core.py` owns `build_nx_graph(nodes, edges)`, which converts SwiftEye node/edge dicts into a weighted, undirected networkx `Graph`. All graph-theory modules import from here. Edges are weighted by `total_bytes` (summed when the same pair has multiple protocol edges).

**Adding a new algorithm module:**
1. Create `analysis/your_module.py`
2. Import `build_nx_graph` from `graph_core`
3. Accept `(nodes, edges, **params)` — same contract as clustering/pathfinding
4. Add an API endpoint in `server.py` that calls `build_graph(store.packets)` and passes results to your module
5. When a 3rd algorithm module is added, extract a formal plugin registry (see roadmap)

### Clustering (`clustering.py`)

Four algorithms, each returning `{node_id: cluster_id}`:

| Algorithm | What it does | When to use |
|-----------|-------------|-------------|
| `louvain` | Modularity optimisation (Louvain method). Resolution param controls granularity. | General community detection |
| `kcore` | k-core decomposition. Labels by core number. | Find densely-connected cores |
| `hub_spoke` | Classifies high-degree nodes as hubs, their exclusive neighbours as spokes. | Identify star topologies (NAT, proxies) |
| `shared_neighbor` | Agglomerative clustering by Jaccard similarity of neighbour sets. | Find peers that talk to the same hosts |

Backend returns cluster assignments as metadata (`clusters: {node_id: cluster_id}`). The frontend does visual collapse client-side via `applyClusterView()` in `clusterView.js`. Graph data is **never mutated** by clustering — toggling off is instant (no API call).

### Pathfinding (`pathfinding.py`)

`find_paths(nodes, edges, source, target, cutoff, max_paths, directed)` finds simple paths between two nodes and returns **aggregated** results:

```python
{
    "source": "10.0.0.1",
    "target": "10.0.0.5",
    "directed": False,
    "path_count": 7,
    "hop_layers": {"0": ["10.0.0.1"], "1": ["10.0.0.2", "10.0.0.3"], "2": ["10.0.0.5"]},
    "edges": [{"source": "10.0.0.1", "target": "10.0.0.2", "protocols": ["TCP"], "total_bytes": 1234, "session_count": 3}],
    "nodes": ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.5"]
}
```

**Key design decisions:**
- Individual paths are **never** returned to the frontend. Only the union of nodes/edges across all paths, with hop distances.
- `hop_layers` — each node's minimum distance from source across all discovered paths. Gives BFS-style layered view.
- `directed` mode uses `nx.DiGraph` (respects edge direction = initiator→responder). Undirected uses `nx.Graph`.
- Hard ceilings: `MAX_PATHS=20`, `MAX_CUTOFF=10` to prevent runaway computation.
- Uses `nx.all_simple_paths` with early termination at `max_paths`.

**API:** `GET /api/paths?source=X&target=Y&cutoff=5&max_paths=10&directed=false`

### Frontend: PathDetail panel (`PathDetail.jsx`)

Right panel component shown when pathfinding results are active. Renders:
- **Source/target IP inputs** — pre-filled from graph pick, manually editable. Enter or "Find" button re-runs the query.
- **Directed/undirected toggle** — re-runs with changed mode.
- **Hop layers** — nodes grouped by BFS distance from source. Source and target highlighted. Each node is collapsible: click the arrow to expand and see its edges on the path (protocol tags, byte counts).
- **All Edges** — flat list of every unique edge across all paths.
- **Clickable navigation** — clicking a node opens NodeDetail, clicking an edge opens EdgeDetail. A "← Back to Path Analysis" link returns to PathDetail.

**State in useCapture:**
- `pathfindSource` — node ID awaiting target pick (crosshair cursor mode)
- `pathfindResult` — aggregated response object from API (or null)
- `pathfindLoading` — boolean for loading state
- `runPathfindFromPanel(source, target, {directed})` — re-run from PathDetail inputs
- Pathfind state **auto-clears** when `rawGraph` changes (time range, filters, etc.) to prevent stale overlays

**Investigation overlay** — when pathfinding results are active, `investigationNodes` is set to the union of all path nodes. Non-path nodes dim to ~10% opacity on the canvas. The investigation banner shows path count and node count.

### Limitations and future work

- **Operates on raw graph only.** Currently pathfinding uses `build_graph(store.packets)` which returns the raw IP-level topology. When clustering is active, cluster mega-nodes are not valid pathfinding targets — the "Find paths to..." context menu item is hidden for cluster/subnet nodes.
- **Node-agnostic contract (ROADMAP).** Graph algorithms should operate on the current visible graph topology, not assume IP-level nodes. When clustering is active, a cluster is a valid node with edges. Beyond network captures, the same algorithms should work on any node type (processes, users, firewall rules, sysmon events). The contract is: accept `(nodes, edges)` where each node has an `id` and each edge has `source`/`target` — the algorithm doesn't know or care what the IDs represent. This requires:
  1. Frontend passes the cluster-transformed graph to pathfinding (not raw)
  2. Backend endpoint accepts pre-transformed node/edge lists (or the frontend sends them)
  3. Edge metadata aggregation works regardless of what the node IDs look like
  4. PathDetail renders node IDs without assuming they're IPs (no IP-specific formatting)
- **Plugin registry.** When a 3rd algorithm module is added, extract a formal registry pattern (auto-discovery like protocol_fields) so new algorithms are drop-in files.

## 14. Analysis Graph & Query System

### Overview

The analysis graph is a persistent NetworkX graph built once at capture load time. It serves structured queries ("find all nodes with >1 MAC") independently of the stateless view graph (`build_graph()`) that handles filtered visualization.

Two separate paths from the same data store:
- **View graph** — `build_graph()`, stateless, rebuilt per filter change. What you see on the canvas.
- **Analysis graph** — `build_analysis_graph()`, built once on upload, persists for capture lifetime. What you query against.

Query results (matched node/edge IDs) overlay onto the view graph as highlights, groups, or filters — no view graph rebuild needed.

### Data structure under the hood

NetworkX stores everything as nested Python dicts. This is the actual internal representation:

```python
# Node storage — G._node (or G.nodes)
# Each key is an IP address, value is a dict of accumulated attributes
G._node = {
    "192.168.1.50": {
        "macs":       {"aa:bb:cc:11:22:33", "aa:bb:cc:44:55:66"},
        "protocols":  {"DNS", "HTTP", "SMB"},
        "ports":      {53, 80, 443, 445},
        "hostnames":  {"workstation-5"},
        "ja3s":       {"e7d705b6..."},
        "ttls":       {64, 128},
        "vendors":    {"Intel"},
        "packets":    1482,
        "bytes":      924810,
        "os_guess":   "Windows 10",
        "is_private": True,
        "arp_seen":   True,
    },
    "10.0.0.1": { ... },
}

# Edge storage — G._adj (adjacency dict)
# Nested dict: G._adj[u][v] = edge attributes
G._adj = {
    "192.168.1.50": {
        "10.0.0.1": {
            "sessions":      ["s1", "s2", "s3"],   # session IDs (keys into store.sessions)
            "protocols":     {"DNS", "HTTPS"},
            "ports":         {53, 443},
            "packets":       312,
            "bytes":         48200,
            "has_handshake": True,
            "has_reset":     False,
            "ja3s":          {"e7d705b6..."},
            "dns_queries":   ["example.com"],
            "http_hosts":    ["example.com"],
            "first_seen":    1711612800.0,
            "last_seen":     1711614600.0,
        },
    },
}
```

This structure serializes to JSON trivially (`nx.node_link_data(G)`) and maps naturally to:
- **Neo4j**: nodes → Neo4j nodes with properties, edges → relationships with properties
- **SQL**: nodes table + edges table + attribute columns
- **Parquet/Spark**: node DataFrame + edge DataFrame

### Query API contract

`POST /api/query` accepts engine-agnostic structured JSON:

```json
{
  "target": "nodes",
  "conditions": [
    { "field": "protocols", "op": "contains", "value": "ARP" },
    { "field": "macs", "op": "count_gt", "value": 1 }
  ],
  "logic": "AND",
  "action": "highlight"
}
```

The `op` field determines the operator. Operators are grouped by the type of field they apply to:

**Numeric operators** (for `packets`, `bytes`, `degree`, `sessions`):
`>`, `<`, `=`, `!=`, `>=`, `<=`

**Count-of operators** (for any set field — MACs, protocols, ports, JA3s, hostnames, etc.):
`count_gt`, `count_lt`, `count_eq` — applies `len(field)` then compares. This is the generic alternative to pre-baked fields like `mac_count`. "Count of MACs > 1" = `{"field": "macs", "op": "count_gt", "value": 1}`.

**Set operators** (for set-valued fields):
`contains`, `contains_all`, `contains_any`, `is_empty`, `not_empty`

**String operators** (for text fields like `os_guess`, `hostnames`):
`equals`, `starts_with`, `matches` (regex)

**Boolean operators** (for flags like `is_private`, `has_handshake`):
`is_true`, `is_false`

**Topology operators** (graph structure queries — Phase 2):
`connects_to`, `connects_only_to`, `same_neighbors_as`, `path_exists`

### Query text parsing — multi-syntax support

Users can type queries in three syntaxes. All parse to the same JSON contract above.

**Supported syntaxes:**
| Syntax | Example | Parser library |
|--------|---------|---------------|
| Cypher | `MATCH (n) WHERE n.packets > 1000 RETURN n` | Custom tokenizer + recursive-descent parser |
| SQL | `SELECT * FROM nodes WHERE packets > 1000` | `sqlglot` (Python, 31+ dialects) |
| Spark SQL | `SELECT * FROM nodes WHERE packets > 1000` (parsed with `dialect="spark"`) | `sqlglot` |

**Architecture — two parsing layers:**

1. **Frontend** calls `POST /api/query/parse` with raw query text. Backend returns the parsed JSON contract. Live parse preview debounced at 300ms. Frontend regex parsers have been deleted.

2. **Backend parsers** (`backend/analysis/query_parser.py`) — `POST /api/query/parse` receives raw text, parses into AST, walks AST to extract conditions, returns JSON contract. Cypher uses a custom tokenizer + recursive-descent parser; SQL/Spark SQL uses sqlglot. 47 pytest tests in `backend/tests/test_query_parser.py`.

**Data flow:**
```
User types query → POST /api/query/parse (raw text) → Cypher parser / sqlglot AST → JSON contract → POST /api/query → resolve_query(G, contract) → results
```

**Data flow (future — Phase 3, real DB backend):**
```
User types Cypher → pass directly to Neo4j (no parsing)
User types SQL → pass directly to PostgreSQL (no parsing)
User types SQL but backend is Neo4j → sqlglot transpiles SQL→Cypher → Neo4j
```

**Library notes:**
- **Cypher parser** (custom): Tokenizer + recursive-descent for the WHERE-clause subset (comparisons, AND/OR, CONTAINS, STARTS/ENDS WITH, IS NULL/TRUE/FALSE, IN [...], =~ regex). `graphglot` (tested v0.5.0) was evaluated but rejected — it's a GQL/ISO parser that fails on basic openCypher features (AND/OR, CONTAINS, STARTS WITH, regex). If a mature openCypher parser emerges, swap in the Cypher section only.
- **`sqlglot`** (SQL/Spark, v30.1.0): Zero dependencies, battle-tested. Walks AST expression types (GT, LT, EQ, Like, Is, In, ArrayContains, And, Or) to extract field/op/value. Can transpile between 31+ dialects — key for the multi-backend future.

**Key files:**
- `backend/analysis/query_parser.py` — backend parsing (Cypher custom + sqlglot)
- `backend/tests/test_query_parser.py` — 47 pytest tests
- `backend/analysis/query_engine.py` — JSON contract resolver (NetworkX, unchanged)
- `frontend/src/query/queryExamples.js` — canned example queries per syntax
- `frontend/src/components/QueryBuilder.jsx` — UI with Visual + Freehand modes

### Response format

```json
{
  "matched_nodes": [
    { "id": "192.168.1.50", "match_details": { "macs": ["aa:bb:cc:11:22:33", "aa:bb:cc:44:55:66"] } }
  ],
  "matched_edges": [],
  "action": "highlight",
  "total_matched": 1,
  "total_searched": 48,
  "summary": "1 of 48 nodes matching query"
}
```

---

## 15. Storage Backend

### Overview

The storage backend provides indexed access to packets and sessions, replacing O(n) scans with O(1) lookups on the hot paths. It is an abstraction layer: the ABC (`StorageBackend`) defines the contract; concrete implementations provide the storage.

**Phases:**
| Phase | Class | Storage | Status |
|-------|-------|---------|--------|
| 1 | `MemoryBackend` | In-memory lists + dict indexes | **Shipped (v0.16.0)** |
| 2 | `SQLiteBackend` | Embedded SQLite file | Planned |
| 3 | `PostgresBackend` | PostgreSQL + TimescaleDB | Planned |

### Directory structure

```
backend/storage/
    __init__.py          # exports: StorageBackend, MemoryBackend, EventRecord
    backend.py           # StorageBackend ABC
    memory.py            # MemoryBackend (Phase 1)
    serializers.py       # Packet serialization helpers (_payload_hexdump, _payload_entropy, etc.)
    event_record.py      # EventRecord dataclass (Phase 2 migration target, not yet wired)
```

### StorageBackend ABC (`backend/storage/backend.py`)

```python
class StorageBackend(ABC):
    def load(self, packets: List["PacketRecord"], sessions: List[dict]) -> None: ...
    def clear(self) -> None: ...
    def get_packets_for_session(self, session_id: str, limit: int = 1000, offset: int = 0) -> List[dict]: ...
    def get_session(self, session_id: str) -> Optional[dict]: ...
    def get_sessions(self, sort_by="time", limit=200, offset=0, search="", time_start=None, time_end=None) -> Tuple[List[dict], int]: ...
    def get_session_keys_for_time_range(self, time_start: float, time_end: float) -> Set[str]: ...
    @property is_loaded -> bool
    @property packet_count -> int
    @property session_count -> int
```

### MemoryBackend indexes

| Index | Type | Purpose |
|-------|------|---------|
| `_by_session_key` | `Dict[str, List[int]]` | session_key → packet list indices |
| `_sessions_by_id` | `Dict[str, dict]` | session ID → session dict (O(1) lookup) |
| `_session_keys_by_15s_bucket` | `Dict[int, Set[str]]` | time bucket → session keys active in that window |

### Integration with CaptureStore

`CaptureStore` owns a `backend: MemoryBackend` instance. At the end of `load()`, after `build_sessions()` and `build_analysis_graph()`, it calls `self.backend.load(self.packets, self.sessions)` to build indexes. `get_packets_for_session()` delegates to the backend.

The `AnalysisContext` contract is unchanged — plugins and research charts still receive `packets=store.packets, sessions=store.sessions` as plain Python lists.

### EventRecord (Phase 2 target)

`EventRecord` is the planned universal normalized data record that all ingestion sources will map to. Defined in `backend/storage/event_record.py`. Not wired to any pipeline in Phase 1 — it exists so Phase 2 has a migration target. See HANDOFF.md §7 for the full ETL architecture design.

### Phase 2 contract (SQLiteBackend)

Phase 2 implements the same `StorageBackend` ABC with a SQLite file backend. The ABC signatures are designed so Phase 2 is a drop-in swap with no call-site changes. Key design decisions:
- `get_sessions()` returns `(List[dict], int)` → maps to `SELECT ... LIMIT ? OFFSET ?` + `SELECT COUNT(*)`
- `get_packets_for_session()` takes `(session_id, limit, offset)` → maps to `SELECT * FROM packets WHERE session_key=? LIMIT ? OFFSET ?`
- `get_session_keys_for_time_range()` returns `Set[str]` → maps to `SELECT DISTINCT session_key FROM packets WHERE timestamp BETWEEN ? AND ?`
- Backend selection via `SWIFTEYE_BACKEND=memory|sqlite|postgres` env var (Phase 3)

### Frontend query builder

The dropdown organizes fields into categories with subcategories. The operator dropdown adapts based on the field type:

```
── Counts (numeric) ────────────
  Total packets
  Total bytes
  Degree (connected peers)
  Session count

── Count of... (any set) ───────
  MACs                    ← "count of MACs > 1" replaces hardcoded mac_count
  Protocols
  Ports
  JA3 fingerprints
  Hostnames
  TTLs
  Vendors

── Contains (set membership) ───
  Protocols               ← "protocols contains DNS"
  Ports                   ← "ports contains 443"
  MACs
  JA3 fingerprints
  Hostnames
  DNS queries (edges)
  HTTP hosts (edges)

── Flags (boolean) ─────────────
  Is private
  Has handshake (edges)
  Has reset (edges)
  ARP seen

── Text (string match) ─────────
  OS guess
  Hostnames (regex)

── Topology (graph structure) ──
  Connects to [IP]
  Connects only to [IP]
  Same neighbors as [IP]
  Path exists to [IP]
```

The field list is **dynamic** — built from whatever attributes exist on the loaded capture's analysis graph. New protocol_fields or plugin attributes appear automatically without frontend changes. Categories are determined by the field's Python type (set → "Count of" + "Contains" categories, int/float → "Counts", bool → "Flags", str → "Text").

### Engine migration path

The `POST /api/query` contract is engine-agnostic. The backend resolver can swap without API or frontend changes:

| Phase | Engine | Mode | When |
|-------|--------|------|------|
| Phase 1 (now) | NetworkX in-memory | Portable | Single-capture, single-user |
| Phase 2 | LadybugDB (embedded) | Portable | Native Cypher, persistent graph, zero setup |
| Phase 3 | Spark connector | Enterprise | Query company's data lake via Spark SQL |
| Phase 4 | Neo4j / Graph DB | Enterprise | Multi-capture correlation, cross-capture Cypher |
| Phase 5 | Postgres + Spark | Enterprise | Multi-user platform, full persistence |

### Two deployment modes

SwiftEye targets two deployment modes with shared frontend and query contract:

**Portable mode** — single-user, zero-setup, laptop. Data from local files (pcap, CSV, Zeek). Graph engine: NetworkX (or embedded LadybugDB). Query execution: local.

**Enterprise mode** — multi-user, connected to the organization's Spark/Databricks cluster. Researchers request slices of petabyte-scale data, SwiftEye builds graphs from the slices locally. Queries route to the remote Spark cluster or a graph DB.

The **query router** is the key abstraction: parsers and frontend are identical in both modes. Only the resolver changes — local (NetworkX) vs remote (Spark/Neo4j). See HANDOFF.md §6 "Long-term vision" for the full architecture diagram, PySpark translation table, and enterprise integration flow.

### PySpark → SQL translation

**Primary audience:** PySpark-fluent (SOC, threat hunters, data engineers in Spark/Databricks). **Secondary (wider) audience:** SQL/KQL/Cypher-fluent (security researchers, network analysts, graph investigators). All syntaxes are first-class.

PySpark DataFrame expressions are parsed as Python code using the `ast` stdlib module (not regex), then converted to equivalent SQL that runs through sqlglot.

Supported subset: `.filter()` / `.where()`, `col()` comparisons, `.contains()`, `.startswith()`, `.endswith()`, `.isNull()`, `.isNotNull()`, `.isin()`, `.between()`, chained filters (→ AND), `count()` / `size()`.

Out of scope (use Spark notebook): UDFs, joins, groupBy+agg, withColumn/explode/pivot, variable references.

See HANDOFF.md §6 for the full PySpark→SQL translation table and scope boundary.

See `query_system_design.html` for visual architecture diagram and UI mockups.

---

## 16. State Lifetime Reference

What survives what event — the canonical answer to "why did my X disappear?"

| State | Stored in | Survives page refresh | Survives re-upload | Survives server restart |
|---|---|---|---|---|
| Theme / layout settings | `localStorage` | Yes | Yes | Yes |
| LLM provider config + API keys | `backend/llm_keys.json` | Yes | Yes | Yes |
| Custom research chart configs | `localStorage` | Yes | Yes | Yes |
| Scope toggles (node scope, research scope) | `localStorage` | Yes | Yes | Yes |
| Capture data (packets, sessions) | backend RAM | No | Replaced | No |
| Analysis graph (nodes, edges, enrichment) | backend RAM | No | Replaced | No |
| Annotations (node labels, edge notes) | backend RAM | No | No (cleared on load) | No |
| Synthetic nodes / edges | backend RAM | No | No (cleared on load) | No |
| Investigation state | backend RAM | No | No | No |
| Alert triggers / results | backend RAM | No | Replaced | No |

**Re-upload** means the user uploads a new capture file. `store.load()` clears annotations, synthetic nodes/edges, and metadata_map before loading the new data — see `services/capture.py`.

**Why this matters for development:** if you add new persistent state, decide where it lives before writing code:
- User preference (survives across sessions) → `localStorage`
- Capture-derived data (scoped to one capture's lifetime) → backend `CaptureStore`
- Must survive server restarts → requires Phase 2 storage (SQLite/Postgres) — not yet implemented

**Roadmap:** `save-load-workspaces` will serialize annotations, synthetic nodes, and investigation state to a portable JSON bundle — the first step toward backend persistence for user-created data.

---

## 17. LLM Interpretation Panel

### Overview

The LLM panel (`AnalysisPage.jsx` → `LLMInterpretationPanel.jsx`) lets researchers ask natural-language questions about the loaded capture. The backend builds a structured context packet from live capture state and streams a markdown answer from a configured provider (Ollama or any OpenAI-compatible API).

**Entry points:**
- `POST /api/llm/chat` — streams NDJSON events (see Wire format below)
- `POST /api/llm/context-preview` — dev/debug, returns the context packet without calling a provider
- `GET /api/llm/keys` — returns stored provider config
- `POST /api/llm/keys` — saves provider config to `backend/llm_keys.json`

---

### Backend package: `backend/llm/`

| File | Role |
|---|---|
| `contracts.py` | Dataclasses for the request/response wire types. `ChatRequest`, `ProviderConfig`, `ChatOptions`, stream event types (`MetaEvent`, `ContextEvent`, `DeltaEvent`, `FinalEvent`, `ErrorEvent`). Stable — don't change shapes without bumping the wire format. |
| `question_tags.py` | Deterministic rule-based tagger. Reads the question text + frontend selection + scope mode, returns a list of tag strings (e.g. `entity_node`, `dns`, `broad_overview`). No ML. Runs in microseconds. |
| `translators.py` | Field-renaming and capitalisation helpers. Converts raw backend dict keys into human-readable labels before injecting into the context packet (e.g. `bytes_total` → `Total bytes`). |
| `context_builder.py` | Scope-aware context retrieval. Given the request and tags, pulls the right data surfaces from `store` (graph nodes/edges, sessions, alerts, capture metadata). Returns a structured `context_packet` dict. |
| `prompts.py` | Prompt assembly. `build_system_prompt(tags, context_packet, model_name, is_simple_question)` returns a structured markdown system prompt. `build_user_content(messages)` formats the conversation history. Small models (sub-8B by regex on model name) receive a compact-mode override that suppresses preamble and caps output at 300 words. |
| `service.py` | Orchestration. `stream_chat(request)` runs the full pipeline (tag → context → prompt → provider → stream) and yields serialisable event dicts. `build_context_only(request)` runs steps 1–3 only (used by `/context-preview`). |
| `key_store.py` | Reads/writes `backend/llm_keys.json`. Provider config (including API keys) is stored server-side, not in browser localStorage. |
| `providers/` | Provider adapters (see below). |

---

### Question tags

Tags are strings returned by `tag_question()` in `question_tags.py`. They drive two things: which data surfaces `context_builder` retrieves, and which prompt variant `prompts.py` uses.

| Tag | Meaning |
|---|---|
| `broad_overview` | No specific entity or protocol — include full capture summary |
| `entity_node` | Question is about a specific node (IP) |
| `entity_edge` | Question is about a specific edge (IP pair) |
| `entity_session` | Question is about a specific session |
| `alert_evidence` | Question is about a specific alert |
| `dns` | DNS-specific question |
| `tls` | TLS/certificate question |
| `http` | HTTP question |
| `credentials` | Credential-exposure question |
| `attribution_risk` | Attacker attribution / threat-actor question |
| `capture_adjacent_background_question` | General knowledge question that touches capture context |
| `mixed_question` | Multiple tags apply |
| `unrelated_question` | Off-topic — context building is skipped |

**Precedence order** (higher = checked first): explicit selection → scope mode → entity resolution → protocol keywords → attribution risk → background markers → default `broad_overview`.

**Adding a new tag:**
1. Add a constant in `question_tags.py` (`TAG_MYNEWTAG = "my_new_tag"`)
2. Add detection logic in `tag_question()` — insert before the `return` at the precedence level that makes sense
3. Add a context-retrieval branch in `context_builder.py` if the tag needs its own surfaces
4. Add a prompt variant in `prompts.py` if the tag needs special instructions

---

### Providers

All providers implement `ProviderAdapter` (`providers/base.py`):

```python
class ProviderAdapter(ABC):
    def stream_chat(self, system_prompt: str, user_content: str, config: ProviderConfig) -> Iterator[str]:
        ...  # yield text delta strings
    def supports_tools(self) -> bool: return False
    def supports_json_mode(self) -> bool: return False
```

| Kind string | Class | Notes |
|---|---|---|
| `ollama` | `OllamaAdapter` | Calls `{base_url}/api/chat`. No API key. Default base URL: `http://localhost:11434`. |
| `openai` | `OpenAICompatibleAdapter` | OpenAI chat completions (`/v1/chat/completions`). Requires API key. |
| `openai_compatible` | `OpenAICompatibleAdapter` | Same adapter, different kind string — for self-hosted endpoints (LM Studio, vLLM, Together, etc.). |

**Adding a new provider:**
1. Create `backend/llm/providers/my_provider.py`, subclass `ProviderAdapter`, implement `stream_chat`
2. Register in `providers/__init__.py`: `"my_kind": MyAdapter`
3. Add `"my_kind"` as an option in `SettingsPanel.jsx`

---

### Streaming NDJSON wire format

`POST /api/llm/chat` streams `application/x-ndjson` — one JSON object per line. Events arrive in this order:

```
meta       → { type: "meta",    request_id, provider, model }
context    → { type: "context", scope_mode, snapshot_id, surfaces: [...], tags: [...] }
warning?   → { type: "warning", message }          (0 or more — one per context limitation)
delta*     → { type: "delta",   text }              (one per token chunk)
final      → { type: "final",   snapshot_id, answer_markdown, usage: {input_tokens, output_tokens} }
```

On error at any point, the stream ends with:
```
error      → { type: "error",   message }
```

The frontend hook `useLlmChat.js` reads these events via `streamLlmChat()` in `api.js` and accumulates deltas into a single `transcript` string rendered as markdown.

---

### Request body (`POST /api/llm/chat`)

```json
{
  "messages":     [{ "role": "user", "content": "..." }],
  "scope":        { "mode": "full_capture|current_view|selected_entity", "entity_type": null, "entity_id": null },
  "viewer_state": { "time_start": null, "time_end": null, "protocols": null, "search": "", "include_ipv6": true, ... },
  "selection":    { "node_ids": [], "edge_id": null, "session_id": null, "alert_id": null },
  "provider":     { "kind": "ollama", "model": "qwen2.5:14b-instruct", "base_url": "", "api_key": "", "temperature": 0.2, "max_tokens": 1400 },
  "options":      { "intent": "qa", "allow_context_expansion": true, "debug_return_context": false, "is_simple_question": false }
}
```

If `provider.api_key` is empty and a key is stored server-side (`llm_keys.json`), the server injects it automatically.

If `options.debug_return_context` is `true`, the stream returns a single `final` event whose `answer_markdown` is the raw context packet as JSON — useful for prompt iteration.

If `options.is_simple_question` is `true` (set by starter chips), the `## Next Steps` section is suppressed from the prompt.

---

### Testing locally with Ollama

```bash
# 1. Pull a model
ollama pull qwen2.5:14b-instruct

# 2. Start SwiftEye (loads a pcap first via the UI)
py backend/server.py

# 3. Hit the context-preview endpoint to inspect what the LLM will see
curl -s -X POST http://localhost:8642/api/llm/context-preview \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"What nodes are in this capture?"}],"scope":{"mode":"full_capture"},"viewer_state":{},"selection":{},"provider":{"kind":"ollama","model":"qwen2.5:14b-instruct"}}' \
  | python -m json.tool

# 4. Stream a real answer
curl -s -N -X POST http://localhost:8642/api/llm/chat \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"What nodes are in this capture?"}],"scope":{"mode":"full_capture"},"viewer_state":{},"selection":{},"provider":{"kind":"ollama","model":"qwen2.5:14b-instruct"}}'
```

**Backend unit tests** live in `backend/tests/test_question_tags.py`, `test_context_builder.py`, `test_prompts.py`, `test_translators.py`. Run with `py -m pytest backend/tests/ -v`.
