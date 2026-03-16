# SwiftEye — Handoff Document
## Version 0.9.53 | March 2026

### v0.9.52 — Final audit pass
- **Version bump** to 0.9.52. FastAPI version string synced.
- **Audit fixes applied** from comprehensive code review:
  - `graph_cache` and `_analysis_results` cleared on new capture upload (was leaking stale data).
  - Analyses now run on an **unfiltered graph** (`_build_analysis_graph_and_run()`) so results always reflect the full capture, not a filtered subset.
  - Single canonical `AnalysisContext` class in `plugins/__init__.py`. `research/__init__.py` imports it instead of defining a duplicate. `ResearchContext` alias removed.
  - CSV parser in VisualizePage replaced with quote-aware state machine (handles commas inside quoted fields).
  - Visualize page accessible from the upload screen via "Visualize custom data" button (renders standalone with back button when no capture loaded).
  - `nodeGroup` column mapping now functional — assigns group IDs and adds D3 clustering force.
  - ForceGraph uses CSS variables for theme compatibility.
  - Registration pattern DRYed into `_dynamic_register()` helper.
  - Unused `AnalysisResult` dataclass, `useCallback` import, `time` import removed.
  - `_run_plugins()` docstring corrected.
- **AnalysisPage** — restored original dedicated UI for Node Centrality and Traffic Characterisation (rich tables, sort buttons, IP search, evidence badges, bars). Additional researcher analyses render generically below via `_display` protocol.
- **Retransmission plugin removed** — was silently failing. May be re-added in a future version.
- **Visualize panel** marked BETA (nav badge + page header).
- **Known bugs documented**: OS filter vs gateway mismatch, Windows OS filter incorrect, Visualize time slider live-rendering.
- **Canvas vignette fix** — removed the `rgba(255,255,255,0.025)` center highlight from the radial vignette in GraphCanvas. It was visible as an opaque yellowish disc on dark/OLED themes due to white-on-black blending. Now uses transparent center with edge-only darkening.

#### Investigation panel
- **New nav item "Investigation"** — full-width markdown notebook for documenting findings during analysis.
- **Split-pane editor** — left pane is a plain-text markdown editor, right pane is a live-rendered preview. Toggle between Edit, Split, and Preview modes.
- **Screenshot support** — paste from clipboard (Ctrl+V) or drag-and-drop images. Images are uploaded to the backend and embedded via `![alt](img_id)` syntax. Also supports file upload via the camera button.
- **Auto-save** — debounced 1.5s auto-save to the backend. Manual save button also available.
- **PDF export** — "Export PDF" button generates a formatted PDF via the backend (reportlab) with headings, bold/italic, code blocks, bullet lists, embedded images, and a SwiftEye header with capture name and timestamp.
- **Toolbar** — quick-insert buttons for headings, bold, italic, code blocks, bullets, horizontal rules.
- **Per-capture** — investigation notes are tied to the loaded capture. New upload clears the notebook.
- **API**: `GET /api/investigation`, `PUT /api/investigation`, `POST /api/investigation/image`, `POST /api/investigation/export`.

### v0.9.50 — Pre-1.0 feature complete

#### Plugin architecture: insights vs analyses
- **Reorganised `backend/plugins/`** into two tiers:
  - `plugins/insights/` — per-node/per-session interpretation (OS fingerprint, TCP flags, DNS resolver, network map, node merger). Run once on pcap load, annotate nodes/edges/sessions.
  - `plugins/analyses/` — graph-wide computation (node centrality, traffic characterisation). Each analysis is a Python class (`AnalysisPluginBase`) that operates on the full unfiltered graph and returns `_display` data. Researchers add analyses by writing a single Python file — no frontend code needed. Analyses with dedicated UI (centrality, traffic) keep their rich frontend panels; new ones render generically.
- **API endpoints**: `GET /api/analysis` (metadata), `GET /api/analysis/results` (results, lazy), `POST /api/analysis/rerun` (force re-run).
- **Node centrality** — Python backend implementation (Brandes betweenness). Dedicated frontend panel with ranked table, sort by score/degree/betweenness/traffic, IP search, click-to-select.
- **Traffic characterisation** — Python backend implementation. Dedicated frontend panel with fg/bg/ambiguous classification, evidence badges, stacked bar, IP filter, expandable evidence rows.
- **`graph_cache`** on `CaptureStore`. Unfiltered graph built lazily on first `/api/graph` request. Cleared on new upload.

#### Visualize panel (BETA)
- **New nav item "Visualize"** — full-width page, independent of loaded capture. Accessible from upload screen.
- Upload CSV, TSV, or JSON (max 10K rows, 50MB). Quote-aware CSV parser.
- **Column mapping**: source node, target node (required); edge label/color/weight, node color/size/group, hover data, timestamp (optional).
- **Timestamp column** enables time slider for filtering rows. Duplicate edges aggregated with count.
- D3 force-directed layout with zoom/pan/drag, node group clustering force. Theme-aware colors.

#### Test suite
- **`backend/tests/test_core.py`** — pytest skeleton: `build_sessions`, `compute_global_stats`, `filter_packets`, `build_graph`, `build_time_buckets`, `build_mac_split_map`, v0.9.43 session scoping regression, insight plugin loads, analysis plugin `compute()`.
- Run: `cd backend && pytest tests/ -v`

### Fixed in v0.9.43
- **Timeline/stats/sessions not filtering by time window** — all three time-scoped endpoints (`/api/stats`, `/api/sessions`, `/api/research/{chart}`) used an overlap check to filter sessions: "include if the session's time range overlaps the window." This meant long-running sessions that merely *touched* the window were included even if they had no packets in it. A 5-minute session starting inside Burst 1 would appear in a 45-second window, and its Gantt bar would stretch the x-axis far past the window boundary.
  - **Root cause:** session filtering used `start_time <= t_end AND end_time >= t_start` (overlap test) instead of checking whether the session had actual packets in the window.
  - **Fix:** all three endpoints now use **packet-based session scoping** — filter packets by strict `t_start <= timestamp <= t_end`, collect their `session_key` values, and only include sessions present in that set. This is authoritative: no packets in the window → session excluded.
  - **Gantt x-axis clamped** — when a time range is active, the x-axis is clamped to the window duration so bars from sessions extending past the window don't stretch the chart. X-axis label changes to "Seconds since window start" when scoped.

### Fixed in v0.9.42
- **Overview panel now updates with timeline** — two silent failures were swallowing errors:
  1. `/api/stats` was calling `compute_global_stats(scoped_pkts)` with one arg — signature requires two (`packets, sessions`). Added `scoped_sess` filtered by the same time window.
  2. `/api/sessions` endpoint didn't accept `time_start`/`time_end` query params at all — the frontend was sending them but the backend ignored them. Added `time_start: Optional[float]` and `time_end: Optional[float]` to the endpoint and applied the filter.
- **Session Gantt x-axis** — `t_global_min` now uses `ctx.time_range[0]` (the window start) so the x-axis is always relative to the selected burst, not the full capture start. Added `time_range` field to `research.AnalysisContext`. Server now passes it when building the context.
- **"Traffic Map" renamed to "Overview"** — updated in `LeftPanel.jsx`, `StatsPanel.jsx`, `HelpPanel.jsx`.

### Fixed in v0.9.41
- **Session Gantt time scope** — replaced old Sparkline + bucket-index sliders with the gap-split sparkline (same `GapSparkline` + `SegCanvas` pattern as the main strip). Burst snap buttons appear when gaps are detected. Timestamps show full DD/MM/YYYY format. 1s bucket added back.
- **Gap collapse threshold** — changed to >20% of duration AND >10 minutes (600s). More conservative than the previous 5min/10% but less strict than the original 1day/20%.

### Fixed in v0.9.40
- **Timeline now filters all panels** — sessions and stats were not re-fetching when `timeRange` changed. Fixed:
  - Added `timeRange` + `timeline` to sessions `useEffect` deps; now passes `time_start`/`time_end` to `fetchSessions`.
  - Added new `useEffect([timeRange, timeline])` that calls `fetchStats` with time params.
  - `fetchStats` in `api.js` now accepts `{timeStart, timeEnd}`.
  - `fetchSessions` in `api.js` now accepts a `timeParams` object as third arg.
  - Backend `/api/stats` now accepts `time_start`/`time_end` query params and calls `compute_global_stats` on the scoped packet list.
- **Gap collapse threshold lowered** — was `>1 day AND >20% duration` (only triggered for multi-day gaps). Now `>5 minutes AND >10% duration`. A 1-hour capture with a 10-minute gap will now collapse; a 20-second capture with a 3-second pause won't.

### Fixed in v0.9.39
- Equal segment widths — burst segments now share available width equally (not proportional to bucket count). Burst 1 with 5 buckets gets same width as Burst 2 with 500 buckets.
- Gap marker wider (36→56px) and hatching brighter (0.2→0.5 opacity, 1.5→2px stroke).
- Bucket size buttons (1s/5s/15s/30s/60s) restored.

### Changed in v0.9.38
- Gap-split sparkline. `splitTimeline()` reads `is_gap` markers from backend. Segments rendered as proportional-width canvases. Gaps shown as 36px //// hatch with duration label. No bucket selector UI. No viewport/activeBurst state.


### Known limitations — burst detection (needs field testing)
Burst split thresholds: gap must be **>60 real seconds AND >20% of total capture duration**.
Both conditions must be true. Designed for the two-pcap case (hours-apart gap).

Not yet validated on:
- Moderate gaps (e.g. 2-3 min pauses inside a 15-min session)
- Captures with many small bursts across a long window
- Coarse bucket sizes (30s, 60s): a single packet per minute marks every bucket active,
  hiding gaps entirely — genuine bursts may not be detected
- Very short captures (<5 min) with meaningful internal pauses

To revisit: test against varied real pcaps. Tuning candidates: min gap seconds (60),
min gap fraction (0.20). Logic lives in `detectBursts()` in `TimelineStrip.jsx`.


<p align="center"><img src="frontend/public/logo.png" alt="SwiftEye Logo" width="100"/></p>

---

## 0. Maintenance Rules

Every session that changes features, fixes bugs, or updates the roadmap **must** update all three docs **before** any code changes:

| File | Update when |
|------|-------------|
| `README.md` | Features added/removed, limits change, quick-start steps change |
| `HANDOFF.md` | Bug fixed, roadmap item added/changed, architecture decision made |
| `docs/DEVELOPERS.md` | API changes, new extension points, architecture changes, new patterns |

**HANDOFF first, always.** The version header, changelog entry, and roadmap tick go in before the first line of code.

---

## 0b. Change Checklists

### Adding a new protocol (port-based detection)
- [ ] `backend/constants.py` — add port → name entry in `WELL_KNOWN_PORTS`
- [ ] `backend/constants.py` — add name → hex colour in `PROTOCOL_COLORS`
- [ ] `frontend/src/components/FilterBar.jsx` — add to `FIELD_SUGGESTIONS` autocomplete
- [ ] `HANDOFF.md` — changelog

### Adding payload signature detection
- [ ] All steps above
- [ ] `backend/parser/protocols/signatures.py` — `@register_payload_signature("MY_PROTO", priority=N)`
- [ ] Priority guide: 10–15 = magic bytes, 20–30 = banner, 40–60 = heuristic

### Adding a protocol dissector
- [ ] All steps from "Adding a new protocol" above
- [ ] `backend/parser/protocols/dissect_<n>.py` — `@register_dissector("MY_PROTO")` returning extra fields dict
- [ ] `backend/parser/protocols/__init__.py` — `from . import dissect_<n>  # noqa: F401`
- [ ] If new `pkt.extra` keys should appear in EdgeDetail — collect them in `aggregator.py` `build_graph()`
- [ ] If those fields should be in the display filter — update `displayFilter.js` FIELDS + eval functions
- [ ] If those fields should autocomplete — add to FilterBar `FIELD_SUGGESTIONS`
- [ ] **Note:** Dissectors using scapy layers (e.g. `pkt.haslayer(DNS)`) only work on the scapy path (files < 500MB). The dpkt path uses `_PayloadProxy` which only handles `"Raw"`. See roadmap for fix.

### Keeping TLS fingerprinting working after adding an HTTPS variant
- [ ] `backend/parser/pcap_reader.py` — add to `_TLS_PROTOCOLS`
- [ ] `backend/parser/dpkt_reader.py` — add to `_TLS_PROTOCOLS` (both files must stay in sync)

### Adding a Graph Options toggle
Graph Options are toggles that reshape how the backend *builds* the graph — they trigger a full `/api/graph` re-fetch.

- [ ] `frontend/src/hooks/useCapture.js` — add `useState` + setter
- [ ] `frontend/src/hooks/useCapture.js` — add param to the graph fetch `useEffect` call and dependency array
- [ ] `frontend/src/api.js` `fetchGraph()` — add to `URLSearchParams`
- [ ] `frontend/src/components/LeftPanel.jsx` — add toggle to Graph Options section (pass value + setter as props via App.jsx)
- [ ] `frontend/src/App.jsx` — pass `c.myToggle` and `c.setMyToggle` as props to LeftPanel
- [ ] `backend/server.py` `/api/graph` — add `Query` param
- [ ] `backend/analysis/aggregator.py` `build_graph()` — add param and implement filter/transform
- [ ] `HANDOFF.md` — changelog + roadmap tick
- [ ] `docs/DEVELOPERS.md` — Graph Options table + API reference

### Adding a backend filter (packet-narrowing, not reshaping)
- [ ] `backend/analysis/aggregator.py` `filter_packets()` — add param and logic here (single source of truth)
- [ ] `backend/analysis/aggregator.py` `build_graph()` — pass through to `filter_packets()`
- [ ] `backend/server.py` `/api/graph` — add `Query` param
- [ ] `frontend/src/hooks/useCapture.js` — add state + pass as graph fetch param + dependency array
- [ ] `frontend/src/api.js` `fetchGraph()` — add to `URLSearchParams`

### Adding an insight plugin
- [ ] `backend/plugins/insights/my_plugin.py` — subclass `PluginBase`, implement `get_ui_slots()` + `analyze_global()`
- [ ] `backend/server.py` `_register_plugins()` — add `("plugins.insights.my_plugin", "MyPlugin")`
- [ ] If per-node IP→data: update `NodeDetail.jsx` to slice the global result to the current node
- [ ] If adds a flat field to graph nodes (like `os_guess`): update `_enrich_nodes_with_plugins()`, `displayFilter.js`, FilterBar `FIELD_SUGGESTIONS`
- [ ] `HANDOFF.md` + `docs/DEVELOPERS.md`

### Adding a graph-wide analysis plugin
- [ ] `backend/plugins/analyses/my_analysis.py` — subclass `AnalysisPluginBase`, implement `compute(ctx)` returning `_display` data
- [ ] `backend/server.py` `_register_analyses()` — add `("plugins.analyses.my_analysis", "MyAnalysis")`
- [ ] No frontend changes needed — the Analysis page renders cards generically from `_display`
- [ ] `HANDOFF.md` + `docs/DEVELOPERS.md`

### Adding a research chart
- [ ] `backend/research/my_chart.py` — subclass `ResearchChart`, implement `compute()`, call `fig.update_layout(SWIFTEYE_LAYOUT)`
- [ ] `backend/server.py` `_register_charts()` — add `("research.my_chart", "MyChart")`
- [ ] `HANDOFF.md` + `docs/DEVELOPERS.md`

### Adding a new API endpoint
- [ ] `backend/server.py` — route function + `_require_capture()` decision (see rule below)
- [ ] `backend/models.py` — Pydantic model if response shape is non-trivial
- [ ] `frontend/src/api.js` — fetch function

**`_require_capture()` rule:**
- **Add it** if the endpoint reads `store.packets/sessions/stats/time_buckets/protocols/subnets/annotations/synthetic/metadata_map`
- **Don't add it** if it reads static server-startup data (plugin registrations, chart registrations, log buffer)

**`.catch()` rule:**
- **Add `.catch(() => fallback)`** only when the endpoint has `_require_capture()` AND it's called at capture-load time in `loadAll()`
- **Don't add** if no guard — errors should surface to the user

### Adding a display filter field
- [ ] `frontend/src/displayFilter.js` — add to `FIELDS` set
- [ ] `frontend/src/displayFilter.js` — add `case` in `evalNodePred()` and/or `evalEdgePred()`
- [ ] `frontend/src/components/FilterBar.jsx` — add to `FIELD_SUGGESTIONS` and help table

---

## 1. Project Vision

SwiftEye is a **network traffic visualization platform for security researchers**.

**Core philosophy: viewer, not analyzer.** The platform shows what's in the data. Researchers bring the expertise. Analysis features (OS fingerprinting, DNS resolution, traffic characterisation) are plugins that present data, never make security judgments.

The boundary: if it's displaying what's in the packet → core viewer. If it requires correlation, inference, or domain knowledge → plugin.

---

## 2. Architecture

```
swifteye/
├── backend/
│   ├── server.py                    # FastAPI, CaptureStore, orchestration, annotations, synthetic
│   ├── constants.py                 # Single source of truth: PROTOCOL_COLORS, WELL_KNOWN_PORTS,
│   │                                #   TCP_FLAG_NAMES/BITS, ICMP_TYPES, CIPHER_SUITES, SWIFTEYE_LAYOUT
│   ├── models.py                    # Pydantic API response models
│   ├── parser/
│   │   ├── packet.py                # PacketRecord dataclass (normalised packet)
│   │   ├── pcap_reader.py           # Router: <500MB → scapy (full dissection), ≥500MB → dpkt (partial)
│   │   ├── dpkt_reader.py           # dpkt path for very large files. NOTE: dissectors using scapy
│   │   │                            #   layers (DNS, etc.) return empty on this path. See roadmap.
│   │   ├── oui.py                   # MAC vendor lookup (~700 OUI entries)
│   │   ├── ja3_db.py                # JA3 hash → {name, category, is_malware} (~60 entries)
│   │   └── protocols/
│   │       ├── __init__.py          # Registries, resolution, auto-imports dissectors
│   │       ├── signatures.py        # Payload signature matchers
│   │       ├── dissect_dns.py       # DNS (scapy layer — only works on scapy path)
│   │       ├── dissect_http.py      # HTTP (scapy + manual fallback)
│   │       ├── dissect_tls.py       # TLS (scapy + manual fallback)
│   │       ├── dissect_icmp.py      # ICMP/ICMPv6 type/code resolver
│   │       ├── dissect_ssh.py       # SSH banner
│   │       ├── dissect_ftp.py       # FTP commands/credentials
│   │       ├── dissect_dhcp.py      # DHCP hostname/vendor class
│   │       └── dissect_smb.py       # SMB v1/v2/v3 share paths/filenames
│   ├── analysis/
│   │   ├── aggregator.py            # filter_packets(), build_graph(), entity_map, OUI+JA3 lookup
│   │   │                            #   IPv6 filter uses resolved IPs when entity_map active
│   │   ├── sessions.py              # Session reconstruction, directional metrics, all protocol fields
│   │   └── stats.py                 # Global statistics
│   ├── plugins/
│   │   ├── __init__.py              # PluginBase, registry, display helpers, UISlot system
│   │   ├── insights/                # Per-node/per-session interpretation
│   │   │   ├── os_fingerprint.py    # Passive OS detection from SYN/SYN+ACK
│   │   │   ├── tcp_flags.py         # TCP sender attribution
│   │   │   ├── dns_resolver.py      # IP → hostname from captured DNS responses
│   │   │   ├── network_map.py       # ARP table, gateway detection, LAN hosts
│   │   │   ├── node_merger.py       # Pre-aggregation: merge IPs by MAC into one node
│   │   │   └── network_map.py      # ARP table, gateway detection, LAN hosts
│   │   └── analyses/                # Graph-wide computation
│   │       ├── __init__.py          # AnalysisPluginBase, registry, run_all_analyses()
│   │       ├── node_centrality.py   # Degree + betweenness + traffic-weighted ranking
│   │       └── traffic_characterisation.py  # Session fg/bg/ambiguous classification
│   ├── tests/                       # Pytest test suite
│   │   └── test_core.py             # Core path + regression + plugin tests
│   └── research/
│       ├── __init__.py              # ResearchChart base, Param, registry, run_chart()
│       ├── conversation_timeline.py
│       ├── ttl_over_time.py
│       ├── session_gantt.py
│       └── seq_ack_timeline.py      # SEQ/ACK scatter — also called inline from SessionDetail
├── frontend/
│   └── src/
│       ├── version.js               # VERSION = '0.9.1' — ONLY place to update version
│       ├── App.jsx                  # Pure layout. Calls useCapture(), decides right-panel content
│       ├── hooks/useCapture.js      # ALL capture state, effects, fetches, handlers
│       ├── api.js                   # All backend calls
│       ├── displayFilter.js         # Wireshark-style filter parser + client-side evaluator
│       └── components/
│           ├── GraphCanvas.jsx      # D3 force graph on canvas + annotation overlays
│           ├── TopBar.jsx           # Logo, filename, search, theme toggle, META/settings button
│           ├── FilterBar.jsx        # Display filter bar with autocomplete + OS chips
│           ├── LeftPanel.jsx        # Protocols, Graph Options, panel switcher
│           ├── NodeDetail.jsx       # Node info: IPs+MACs+vendors, OS fingerprint, notes
│           ├── EdgeDetail.jsx       # Edge info: TLS (JA3/JA4), protocol conflicts
│           ├── SessionDetail.jsx    # Session: overview/flags/seq-ack/packets/payload tabs
│           ├── SessionsTable.jsx    # Sessions list with local search + sort
│           ├── MultiSelectPanel.jsx # Panel shown when 2+ nodes selected
│           ├── StatsPanel.jsx       # Traffic Map panel (default right panel)
│           ├── ResearchPage.jsx     # Full-width research charts page
│           ├── TimelinePanel.jsx    # Full-width Gantt page
│           ├── AnalysisPage.jsx     # Full-width analysis page (backend-rendered cards)
│           ├── VisualizePage.jsx   # Custom data graph (CSV/TSV/JSON upload + column mapping)
│           ├── HelpPanel.jsx        # Help panel: Guide + Plugins & Protocols tabs
│           ├── SettingsPanel.jsx    # Settings panel: theme picker, LLM API key
│           ├── LogsPanel.jsx        # Server log viewer (polls /api/logs)
│           ├── PluginSection.jsx    # Generic plugin UI slot renderer + dedicated renderers
│           ├── Sparkline.jsx        # Canvas sparkline with active range highlight
│           ├── Collapse.jsx         # Collapsible section primitive
│           ├── Tag.jsx              # Protocol/status tag chip
│           ├── FlagBadge.jsx        # TCP flag badge
│           └── Row.jsx              # Layout row primitive
└── requirements.txt
```

### Key Architectural Rules (MUST NOT VIOLATE)

- `visibleNodes`/`visibleEdges` MUST be `useMemo`-ed in `useCapture.js` — never inline `.filter()` in JSX (causes simulation restart on every render)
- `_require_capture()` only on endpoints reading per-capture store fields — never on static startup data
- `store.annotations/synthetic/metadata_map` are cleared in `store.load()` on every new upload
- `VERSION` string lives only in `frontend/src/version.js` — imported everywhere else
- All state/logic in `useCapture.js`, App.jsx is pure layout only
- HANDOFF updated FIRST before any code changes
- `mac_vendors` derived as `[lookup_vendor(mac) for mac in sorted(n["macs"])]` at serialisation — parallel to `macs`
- IPv6 filter in `build_graph`: when `entity_map` active + `include_ipv6=False`, check resolved IPs not raw packet IPs

### API Endpoints

| Method | Endpoint | Params / Notes |
|--------|----------|----------------|
| POST | `/api/upload` | Multipart pcap file |
| GET | `/api/status` | Capture loaded status, filename |
| GET | `/api/stats` | Global capture statistics |
| GET | `/api/timeline` | `bucket_seconds` — time-bucketed packet counts |
| GET | `/api/graph` | `time_start`, `time_end`, `protocols`, `search`, `subnet_grouping`, `subnet_prefix`, `merge_by_mac`, `include_ipv6`, `show_hostnames`, `subnet_exclusions` |
| GET | `/api/sessions` | `limit`, `search` — session list |
| GET | `/api/session_detail` | `session_id`, `packet_limit` |
| GET | `/api/protocols` | Protocol list + colours |
| GET | `/api/subnets` | Subnet groupings |
| GET | `/api/slice` | `time_start`, `time_end`, `protocols`, `search`, `include_ipv6` — binary pcap download |
| GET | `/api/plugins` | Plugin UI slot declarations (no capture required) |
| GET | `/api/plugins/results` | All global plugin results |
| GET | `/api/research` | List registered charts (no capture required) |
| POST | `/api/research/{name}` | Run chart — body: `{params..., _timeStart?, _timeEnd?}` |
| GET/POST/DELETE | `/api/metadata` | Researcher metadata JSON |
| GET/POST | `/api/annotations` | Annotation CRUD |
| PUT/DELETE | `/api/annotations/{id}` | Update/delete annotation |
| GET/POST | `/api/synthetic` | Synthetic node/edge CRUD |
| PUT/DELETE | `/api/synthetic/{id}` | Update/delete synthetic element |
| DELETE | `/api/synthetic` | Clear all synthetic elements |
| GET | `/api/hostnames` | DNS-resolved hostname map |
| GET | `/api/logs` | Server log buffer |

---

## 3. Scalability

The fundamental challenge for a project like SwiftEye is that network captures can produce extremely large graphs. A 10-minute corporate capture can contain hundreds of thousands of packets across thousands of unique IP pairs. Naively rendering this as a force-directed graph would be both computationally prohibitive and visually useless — a dense hairball where nothing is readable. SwiftEye addresses this at both the visualization layer and the compute layer.

### Visualization-side strategies

These reduce what the user *sees* without losing data. The full capture is always available — the researcher narrows their view to what matters.

| Strategy | Status | How it helps |
|----------|--------|-------------|
| **Timeline time slider** | ✅ Implemented | The gap-split sparkline with Start/End sliders lets the researcher scope the entire view (graph, sessions, stats) to a specific time window. A 2-hour capture with a 30-second window of interest becomes manageable. Burst snap buttons auto-detect activity clusters. |
| **Subnet grouping** | ✅ Implemented | Collapses individual IPs into `/N` subnet nodes (configurable /8–/32). A /24 with 200 hosts becomes one node. Right-click any subnet node to uncluster just that subnet — selective expansion without losing the grouped view elsewhere. |
| **Protocol filter** | ✅ Implemented | Protocol checkboxes in the left panel. Uncheck DNS and ARP to remove the noisy service traffic, leaving only the application-layer conversations visible. |
| **Display filter** | ✅ Implemented | Wireshark-style expression filter (`ip`, `port`, `protocol`, `tls.sni`, `os`, `subnet`, CIDR, `&&`/`||`/`!`). Client-side, instant. Researchers can drill down to exactly the traffic they care about without waiting for a backend round-trip. |
| **Merge by MAC** | ✅ Implemented | Dual-stack hosts (IPv4 + IPv6 on the same MAC) collapse into a single node. On networks with heavy IPv6, this can halve the visible node count while preserving all connection data. |
| **Search filter** | ✅ Implemented | Universal keyword search that filters both graph and sessions. Matches IPs, MACs, hostnames, protocols, ports, and TCP flags simultaneously. |
| **Investigate neighbours** | ✅ Implemented | Right-click a node → "Investigate neighbours" (depth-1) or "Investigate component" (full BFS). Isolates the relevant subgraph without manually filtering. |
| **Hide node** | ✅ Implemented | Right-click → Hide. Removes noisy nodes (broadcast addresses, multicast) from the view. Unhide all badge to restore. |
| **Label threshold** | ✅ Implemented | Configurable minimum connection count for node labels. Low-connection nodes render without labels, reducing visual clutter at low zoom. |
| **Large graph layout** | ❌ Not yet | For 1000+ node graphs, the D3 force simulation is slow to converge. Candidate approaches: WebGL renderer (e.g. pixi.js or deck.gl), level-of-detail rendering (show subnet hulls when zoomed out, expand to individual nodes on zoom), or server-side layout computation with pre-positioned coordinates. |

### Compute-side strategies

These reduce processing time and memory usage for large captures.

| Strategy | Status | How it helps |
|----------|--------|-------------|
| **Dual parser (scapy / dpkt)** | ✅ Implemented (threshold issue) | `pcap_reader.py` routes files: <500MB → scapy (full dissection with all protocol layers), ≥500MB → dpkt (lightweight C-based parsing, partial dissection). Currently `DPKT_THRESHOLD == MAX_FILE_SIZE == 500MB`, so dpkt is effectively never used. Once dpkt dissector parity is confirmed, the threshold will be lowered to ~50MB so most captures benefit from dpkt's speed. |
| **Backend-computed analyses** | ✅ Implemented | Node centrality (Brandes betweenness) and traffic characterisation run in Python on the server, not client-side JavaScript. The frontend receives pre-computed results. This moves O(V³) computation off the browser. |
| **Packet-based session scoping** | ✅ Implemented | Time-range filtering uses strict packet timestamps, not session overlap checks. Only sessions with actual packets in the window are included. This avoids the combinatorial blowup of including long-running sessions in every narrow window. |
| **Lazy analysis execution** | ✅ Implemented | Analyses (centrality, traffic characterisation) run lazily on the first graph build, not at upload time. This avoids blocking the upload response for large captures. |
| **Multi-threaded pcap parsing** | ❌ Not yet | Each packet is parsed independently (no cross-packet state in the parser layer), so parsing is embarrassingly parallel. Planned approach: split the raw packet iterator into N chunks, parse each in a `ProcessPoolExecutor`, concatenate and sort by timestamp. Scapy's GIL-bound layer construction needs multiprocessing (not threads); dpkt may benefit from threads. Prerequisites: profiling to confirm the parser is the bottleneck. |
| **Streaming / chunked parse** | ❌ Not yet | Currently the entire packet list is built in memory before any processing begins. For very large captures (>500MB), a streaming approach would emit `PacketRecord` objects as they are parsed, feeding them into sessions/graph incrementally. Requires rearchitecting `build_sessions()` and `build_graph()` to accept iterators instead of lists. |
| **Indexed packet store** | ❌ Not yet | Full-list scans (e.g. `filter_packets()` iterating all packets) are O(N) on every API call. For captures above ~500K packets, an indexed store keyed by `session_key`, `src_ip`, `dst_ip`, and time range would enable O(1) lookups. Candidate: sorted arrays with bisect, or an embedded database (SQLite). |
| **Neo4j graph backend** | ❌ Not yet | Replace in-memory node/edge dicts with Neo4j. Benefits: Cypher queries replace Python loops, native graph storage survives restarts, enables multi-capture persistence and cross-capture queries. Architecture: keep in-memory as fallback via `SWIFTEYE_GRAPH_BACKEND=neo4j|memory`. Prerequisites: large pcap support profiling first. Long-term. |
| **dpkt dissector parity** | ❌ Partially done | DNS, FTP, DHCP, SMB have raw-byte parsers that work on both paths. HTTP/TLS/SSH have manual fallbacks. But scapy-specific dissectors (e.g. `pkt.haslayer(DNS)`) still return empty on the dpkt path. Full parity needed before lowering the dpkt threshold. |

### The practical outcome

For a typical security research capture (10–60 minutes, 50K–500K packets, 50–500 unique IPs), SwiftEye renders a usable graph in under 5 seconds. The researcher narrows it further with time scoping, protocol filters, and subnet grouping — usually arriving at a 20–50 node subgraph within 30 seconds of loading. The scalability strategies exist to push this boundary higher, but the current architecture is designed around the principle that **the researcher's first action is always to scope down**, and the tool should make scoping fast and intuitive.

---

## 4. Current Features

### Core Viewer
- [x] Pcap/pcapng: scapy for <500MB (full dissection), dpkt for ≥500MB (partial); max 500MB
- [x] Multi-pcap: drop multiple files at once; merged by timestamp
- [x] Three-tier protocol detection: port → scapy layers → payload signatures; conflicts flagged
- [x] ~90 well-known port mappings; payload signatures for TLS, HTTP, SSH, SMTP, FTP, DHCP, SMB
- [x] Dissectors: DNS, HTTP, TLS, ICMP/ICMPv6, SSH, FTP, DHCP, SMB
- [x] JA3 + JA4 TLS fingerprints; JA3 → app name lookup (browser/tool/malware); red badge for malware
- [x] MAC vendor lookup (~700 OUI entries); displayed in NodeDetail Advanced section
- [x] Force-directed graph on canvas (D3); multi-edge (one edge per protocol pair)
- [x] Shift+click multi-select with scoped statistics
- [x] Lasso select: Shift+right-drag draws selection rectangle; releases selects all nodes inside
- [x] Backend filters: time range, protocol, search, subnet grouping (/8–/32), Merge by MAC, Show IPv6, Show hostnames
- [x] Subnet uncluster: right-click subnet node → expand to individual IPs; re-clustering works correctly
- [x] Wireshark-style display filter (client-side): ip, port, protocol, tls.sni, os, private, CIDR, role, gateway, &&/||/!
- [x] Investigation mode: "Investigate neighbours" (depth-1) or "Investigate component" (full BFS connected component)
- [x] Relayout button: unpins all nodes and reheats D3 simulation for a clean redistribution
- [x] Synthetic cluster: select 2+ nodes → right-click canvas → cluster into one purple node; edges rerouted automatically
- [x] Node detail: IPs + MACs (with vendor), OS fingerprint, hostnames, connections by direction, researcher notes
- [x] Session detail: overview / flags / SEQ/ACK (inline chart) / packets / payload tabs
- [x] SEQ/ACK Timeline: inline Plotly chart in Session Detail; also available in Research page
- [x] Timeline sparkline: 5s/15s/30s/60s buckets, Start/End range sliders
- [x] Session Gantt: full-width Plotly page (Timeline nav)
- [x] Research page: full-width Plotly charts with time scope (Conversation Timeline, TTL over time, Seq/Ack, DNS Timeline, JA3 Timeline, JA4 Timeline)
- [x] Annotations: right-click canvas/node/edge → pinned labels; persist across reloads; cleared on new upload
- [x] Synthetic nodes/edges: right-click → dashed rendering with ✦ marker; custom colour/size/notes; persisted
- [x] Payload preview: hex+ASCII dump in Session Detail Payload tab
- [x] PCAP export: "Export pcap" button downloads current filtered view
- [x] Hide node: right-click → hide; badge with Unhide all
- [x] Researcher metadata: META button → JSON upload; name becomes node label
- [x] 8 themes: dark (default), dark-blue, oled, colorblind, blood, amber, synthwave, pastel
- [x] Settings panel: theme picker, LLM API key + model (persisted in localStorage)
- [x] Analysis panel: "Analysis ✦" nav; Coming Soon cards (Node Centrality, Traffic Characterisation); LLM interpretation skeleton (API key, model selector, disabled button)
- [x] Resizable right panel (220–600px); Help panel with tabbed Guide + Plugins & Protocols

### Plugin System
- [x] OS Fingerprint — TTL, window size, MSS, TCP options from SYN/SYN+ACK
- [x] TCP Flags — sender attribution (who initiated, closed, reset)
- [x] DNS Resolver — IP → hostname from captured DNS responses; hostnames become node labels
- [x] Network Map — ARP table, gateway detection (diamond shape), LAN hosts, hop estimation
- [x] Node Merger — merge IPs sharing a MAC (including dual-stack) before graph building

### Research Charts
- [x] Conversation Timeline — peers of target IP over time, dot size = bytes
- [x] TTL over time — TTL between two peers, both directions
- [x] Session Gantt — all sessions Gantt (Timeline page)
- [x] Seq/Ack Timeline — TCP seq/ack scatter per session; also inline in SessionDetail SEQ/ACK tab
- [x] DNS Timeline — DNS queries over time by IP
- [x] JA3 Timeline — JA3 fingerprint events over time
- [x] JA4 Timeline — JA4 fingerprint events over time

---

## 5. Known Bugs / Architecture Notes

### Open
- **OS filter "network device (likely)" doesn't match gateway/router** — the OS fingerprint plugin produces the guess "network device (likely)" but the display filter/OS dropdown doesn't match nodes identified as gateway/router by the network_map plugin. The two plugins produce independent results — OS fingerprint looks at TTL/window/MSS while network_map looks at ARP/gateway behaviour. The filter should recognise gateway nodes as matching the "network device" filter.
- **Windows OS filter incorrect** — the OS fingerprint `os contains "Windows"` filter does not correctly match all Windows-detected nodes. Likely a casing or substring issue in the display filter evaluator or the OS guess string format. Needs investigation.
- **Visualize time slider re-renders graph during drag** — the time window slider in the Visualize panel rebuilds the graph on every slider move via `useMemo`. It should debounce or require a "Run" button press like the Timeline panel does.
- **`get_packets_for_session()` in CaptureStore** — serialisation logic that belongs in `analysis/sessions.py`. Low priority, no user impact.
- **`_looks_like_ip_keyed()` heuristic** — fragile sampling of plugin result dict keys. Right fix: `slot_data_type: "ip_map" | "global"` on UISlot. Low breakage risk with existing plugins.
- **dpkt dissector parity** — partially addressed in v0.9.15 (DNS, FTP, DHCP, SMB now have raw-byte parsers). HTTP/TLS/SSH already had manual fallbacks. However, DPKT_THRESHOLD == MAX_FILE_SIZE == 500MB means dpkt is effectively never used (files ≥500MB are rejected first). Roadmap: lower DPKT_THRESHOLD to ~50MB once parity is confirmed. The raw-byte parsers are ready.

### Fixed in v0.9.4
- **Seq/Ack chart: two modes** — "Bytes/time" (SEQ relative to ISN vs seconds, lines+markers, slope = throughput) and "SEQ/ACK" (relative SEQ vs relative ACK, scatter, diagonal = healthy flow). Toggle buttons switch mode and clear the figure so Run re-fetches. Legend moved to horizontal below the chart (`y: -0.2`) to stop covering the data.
- **Seq/Ack panel auto-widens** — opening the SEQ/ACK tab calls `onTabChange` → App.jsx widens panel to 500px if narrower. `setPanelWidth` exported from `useCapture`.
- **IPv4/IPv6 header collapse in session overview** — new "IPv4 Header" / "IPv6 Header" collapse after TTL, showing: IP version, DF flag, DSCP with named values (EF=voice, AF classes, CS classes), ECN decoded (ECT0/ECT1/CE), IPv6 flow label. Aggregated in `sessions.py` as `ip_version`, `dscp_values`, `ecn_values`, `df_set`, `ip6_flow_labels` (all set → sorted list). IPv6 traffic class decoded identically to IPv4 ToS (upper 6 bits = DSCP, lower 2 = ECN).
- **Payload tab: ASCII-only default, Hex toggle, copy buttons** — hex bytes hidden by default, "Hex" toggle shows `offset hex ascii`. Per-packet copy buttons: ASCII (printable chars joined), Hex (formatted dump), Raw (plain hex string for CyberChef/piping). `payload_bytes` field added to `get_packets_for_session`.
- **IP header fields per packet in Payload tab** — each packet row shows TTL, DF/MF flags, DSCP, ECN, TCP checksum inline. IPv6 rows show hop limit, DSCP, ECN, flow label.
- **ISN per direction in Advanced** — `seq_isn_init` / `seq_isn_resp` tracked in `sessions.py`, shown in Advanced section for context when reading the relative chart.
- **New `PacketRecord` fields** — `ecn`, `ip_checksum`, `tcp_checksum`, `ip6_flow_label`. Scapy reader populates all; IPv6 traffic class decoded to `dscp`/`ecn` same as IPv4.
- **Seq/Ack chart: layout fix** — corrupted layout block from prior session cleaned up. Both modes use a shared layout with dynamic axis titles.

### Fixed in v0.9.3
- **Payload tab: "Raw bytes" toggle** — hex dump is now hidden by default. A "Raw bytes" toggle button reveals it. Packet rows always show: direction, size, TTL, DF/MF flags, DSCP, ECN, flow label (IPv6), and TCP checksum — the useful header info at a glance without the noise.
- **IP header fields per packet** — both IPv4 and IPv6 fields now extracted and shown inline on each packet row in the Payload tab: IPv4: TTL, DF/MF flags, DSCP, ECN, checksum; IPv6: hop limit, DSCP, ECN, flow label. New `PacketRecord` fields: `ecn`, `ip_checksum`, `tcp_checksum`, `ip6_flow_label`. Scapy reader populates all of them; dpkt reader gets them where available.
- **Advanced: ISN per direction** — `seq_isn_init` and `seq_isn_resp` now tracked in `sessions.py` (first SEQ seen from each direction). Shown in the Advanced section of overview so the relative seq/ack chart can be understood in context: "initiator started at seq 1,234,567,890, which is 0 on the chart".
- **Seq/Ack chart redesigned** — now plots relative SEQ vs time (seconds from session start) instead of raw SEQ vs ACK. Raw TCP ISNs are arbitrary 32-bit values that make the chart unreadable. Relative values show throughput (slope), stalls (flat), retransmits (backward step).
- **Empty protocol in left panel** — packets with empty `protocol` string (from fallthrough in certain dissectors) were showing as a nameless swatch in the protocol list. Filtered in `server.py` at store.protocols build time, and in `LeftPanel.jsx` before render.
- **FLAGS tab removed** — flag counts moved into the Advanced collapse in Overview. Tabs are now: OVERVIEW / SEQ/ACK / PAYLOAD / PACKETS.

### Fixed in v0.9.2
- **Merge-by-MAC gateway bug (critical)** — `build_entity_map` was using both `src_mac`
  AND `dst_mac`. The `dst_mac` of outbound packets is the gateway MAC, not the remote
  host. All external IPs that replied through the same router shared the router MAC as
  `src_mac` and union-found into one node, collapsing all external connections.
  Three-layer fix: (1) src_mac only, (2) skip infrastructure vendor MACs (Cisco, Juniper,
  Aruba, Ubiquiti, Palo Alto, Fortinet, Sophos, WatchGuard, Brocade, Extreme, Arista,
  MikroTik, Ruckus, Meraki) via `_is_router_mac()` + OUI lookup, (3) cap groups at 8 IPs.
- **NodeDetail: IPs and MACs always visible** — moved from collapsed Advanced to top-level.
  MACs show vendor inline: `c4:d0:e3:8f:6b:69 (Apple)`. Advanced now has TTLs only.
- **JA3/JA4 inline** — app name on same line as hash in a coloured pill. SessionDetail
  now uses `JA3Badge` (was rendering plain text with no app lookup). Both files identical.

### Fixed in v0.9.1 (this session)
- **mac_vendors never populated** — lookup was imported but never called; parallel array assumption also wrong. Fixed: derived as `[lookup_vendor(mac) for mac in sorted(n["macs"])]` at serialisation.
- **8 malformed OUI keys** — 7–8 char keys that never matched any MAC. Removed.
- **10 duplicate/conflicting JA3 hashes** — real browser hashes (Chrome, Safari, LibreSSL, Tor) overwritten with malware labels (Dridex, Trickbot, Cerberus, NanoCore, etc.) because Python dicts take the last entry. Conflicting malware entries removed.
- **DNS hostnames not showing** — root cause: dpkt was used for files ≥20MB; DNS dissector uses `pkt.haslayer(DNS)` (scapy layer), returns `{}` on dpkt path. Fixed by raising threshold to 500MB so almost all real captures use scapy.
- **IPv6 connections lost when Merge by MAC + Show IPv6 OFF** — `include_ipv6=False` filter ran before entity resolution. A packet from `2a0d:6fc0::1` (local IPv6, resolves to `192.168.1.177`) to `2606:4700::` was dropped because raw src has ':'. Fix: when entity_map active, filter on resolved IPs; only drop when both resolved endpoints are IPv6.
- **Annotations/synthetic/metadata not cleared on new upload** — `store.load()` now resets all three.
- **Research/Timeline rendered in right panel** — fixed in App.jsx rewrite.
- **`prefillValues` missing from ChartCard props** — chart params didn't pre-fill from session link.
- **Hardcoded version strings** in TopBar/HelpPanel — now use `VERSION` from `version.js`.
- **Dead `hiddenNodes` prop on GraphCanvas** — hidden nodes filtered before being passed, prop was ignored. Removed.
- **`mac_vendors` parallel array wrong** — was a `set()` that never sorted in correspondence with `macs`. Fixed.
- **ICMPv6 not handled in dpkt_reader** — added `ip.nxt == 58` fallback.
- **Upload screen too small** — now 460px wide, logo 120px, icon 64px.
- **SeqAck chart squashed** — container needed explicit `height: 300` for Plotly to render correctly.
- **App.jsx split regressions** — TimelinePanel missing props, `onApplyDisplayFilter` not setting `dfExpr`, upload screen layout issues. All fixed by rewriting App.jsx to exactly mirror original structure with `c.` prefix.

### Fixed in v0.9.0
- **Dual-stack merge lost connections** — EdgeDetail session matching only checked the canonical node ID. Fixed: checks all IPs in the merged node's `ips` array.

### Fixed in v0.8.x (see full changelog below)
All v0.8.x bug details preserved in §4a.

---

## 5a. v0.8.x Bug Details (preserved for reference)

- **v0.8.8** — `visibleNodes`/`visibleEdges` memoised; cross-family merge guard added (later removed in v0.9.0)
- **v0.8.7** — JA3 badge, MAC vendor lookup, dissector/plugin error isolation
- **v0.8.6** — SSH/FTP/DHCP/SMB/ICMPv6 dissectors
- **v0.8.5** — Sessions panel local search, search scope badge
- **v0.8.4** — Multicast IPs/MACs excluded from merge
- **v0.8.3** — Payload hexdump, hide node, retransmission plugin, PCAP slice, Seq/Ack chart
- **v0.8.2** — Synthetic node/edge rendering, version string, annotation scaling
- **v0.8.1** — Annotations follow pan/zoom, synthetic edge form NodePicker
- **v0.8.0** — Payload preview, Help page, Research IP pre-fill fix, TopBar wordmark

---

## 6. Roadmap

### Pending
- [ ] **dpkt dissector parity** — port all dissectors to work on raw bytes so dpkt and scapy paths produce identical `pkt.extra` output. DNS is the most important (hostnames rely on it). Once done, lower the dpkt threshold back from 500MB. See note in `dpkt_reader.py` `_PayloadProxy`.
- [ ] **Save/load workspaces** — serialize annotations, synthetic elements, hidden nodes, pinned positions to a JSON file for reload
- [x] **Synthetic node size** (v0.9.5) — synthetic nodes always have `packet_count: 0` so `gR(node)` returns the minimum radius (5px) in `GraphCanvas.jsx`. Fix: give synthetic nodes a configurable `size` field (default e.g. 12px equivalent) set at creation time, and have `gR()` use it when `node.synthetic` is true. The creation form already has color; add a size slider (small / medium / large). Backend: add `size` field to the node object in `create_synthetic()` and expose it via the `PUT /api/synthetic/{id}` update endpoint.
- [x] **Synthetic node detail editing** (v0.9.5) — when a synthetic node is selected, its NodeDetail panel should be editable. Currently shows read-only data. Add inline edit for: `label` (the display name), `ip` (the address it represents), `color`, `size`, and a freeform `notes` field. Changes should PUT to `/api/synthetic/{id}` immediately (no save button needed — same pattern as annotation inline edit). The notes field should render as a small textarea, not a single-line input.
- [x] **Researcher notes on every node** (v0.9.5) — add a collapsible "Notes" section to NodeDetail (and EdgeDetail) for all nodes, not just synthetic ones. A researcher should be able to attach a free-text note to any real node or edge during investigation. Notes are stored in `store.annotations` as a special annotation type (add `annotation_type: "note"` field alongside the existing `node_id`/`edge_id` fields, or use a separate `store.notes` dict keyed by node/edge ID). Notes persist across graph re-fetches (keyed by node ID, same as node annotations) and are included in workspace save/load. This is separate from researcher metadata JSON (which is pre-loaded structured data) — notes are ad-hoc, written during investigation, and not tied to a specific capture file structure.
- [x] **Multi-pcap ingestion** — done in v0.9.15. UI accepts multiple files, TopBar shows "N files". Backend merges by timestamp.
- [ ] **Large pcap support (>500MB)** — profile the pipeline; likely bottlenecks are scapy's per-packet overhead and full-list scans in `build_graph`/`build_sessions`. Candidate approaches in priority order: (1) streaming/chunked parse, (2) background loading with progress API via `/api/status`, (3) indexed packet store by session_key/IP/time for O(1) queries above ~500K packets.
- [ ] **Multi-threaded pcap parsing** — each packet is parsed independently (no cross-packet state in the parser layer), so parsing can be parallelised. Approach: split the raw packet iterator into N chunks, parse each chunk in a separate thread/process via `concurrent.futures.ProcessPoolExecutor`, then concatenate the resulting `PacketRecord` lists and sort by timestamp. Scapy's GIL-bound layer construction likely needs `ProcessPoolExecutor` (not threads). The dpkt path is lighter and may benefit from `ThreadPoolExecutor`. Measure before choosing. *Note:* dissectors that use scapy layer objects (e.g. `pkt.haslayer(DNS)`) are safe to parallelise because each packet's scapy object is independent. *Prerequisites:* large pcap support profiling first to confirm the parser is the bottleneck.
- [x] **Network mapping** — done in v0.9.8 (`plugins/network_map.py`)
- [ ] **Credential viewing** — HTTP Basic, FTP, Telnet, SMTP AUTH
- [x] **Certificate extraction** — done in v0.9.7
- [ ] **SMTP dissector** — not yet written
- [ ] **Kerberos dissector** — not yet written
- [ ] **mDNS/SSDP dissectors** — not yet written
- [ ] **Aggregator/entity-resolution plugin tier** — pre-aggregation plugins that return an IP→canonical map; `build_graph` applies it. Design agreed, not scheduled.
- [ ] **Expand OUI vendor table** — current table has ~700 hand-curated entries; many common MACs (e.g. c4:d0:e3, various Intel/Realtek) are missing. Replace with the full IEEE OUI database (~35,000 entries). Download from https://standards-oui.ieee.org/oui/oui.txt, parse, and embed in `backend/parser/oui.py`.
- [ ] **Interactive research dashboard** — Plotly charts with cross-filtering across sessions/nodes
- [ ] **File extraction** — reconstruct files from HTTP/FTP/SMB streams (FTP dissector already surfaces filenames/credentials)
- [ ] **Multi-capture comparison** — side-by-side or overlay view of two captures
- [ ] **Sysmon log ingestion** — accept Windows Sysmon XML/JSON event logs (process creation ID 1, network connections ID 3, DNS ID 22). Normalize into `EventRecord` structs parallel to `PacketRecord`. Network connections map cleanly to the existing session/edge model. Foundation for host-based threat hunting. *Prerequisites:* `EventRecord` abstraction. Status: very long-term.
- [ ] **Process tree visualization** — once Sysmon data is ingested, render a process tree overlaid on the network graph. Nodes = processes (PID, image path, command line, user); edges = parent→child spawns + network connection edges to IP nodes. *Prerequisites:* Sysmon ingestion. Status: very long-term.
- [ ] **Neo4j graph backend** — replace in-memory node/edge dicts with Neo4j. Benefits: Cypher queries replace Python loops, native graph storage survives restarts, enables multi-capture persistence and cross-capture queries. Architecture: keep in-memory as fallback via `SWIFTEYE_GRAPH_BACKEND=neo4j|memory`; `PacketRecord`→node/edge transform writes to Neo4j at upload time; query endpoints become Cypher; frontend unchanged. *Prerequisites:* large pcap support first. Status: long-term, design not started.
- [ ] **Multi-source log ingestion** — accept Zeek/Bro logs, SIEM exports (CEF/LEEF), syslog, Windows Sysmon XML/JSON. Each source type becomes an ingestion adapter normalising records into `PacketRecord`-equivalent structs. Zeek `conn.log` is the highest-value first target. *Prerequisites:* `EventRecord` abstraction design. Status: long-term.
- [x] **Analysis panel** (v0.9.50) — dedicated full-width panel with plugin-based architecture in `backend/plugins/analyses/`. Each plugin produces a named analysis with `_display` data for generic rendering. Frontend: grid of collapsible insight cards. Node centrality and traffic characterisation implemented. Planned additional analyses:
  - [ ] **Node centrality** — degree centrality (most connected), betweenness (bridges), traffic-weighted PageRank. Ranked table + graph highlight.
  - [ ] **Traffic characterisation** — foreground (interactive: bidirectional, low latency, short) vs background (periodic, one-directional, long). Based on session duration, packet ratio, inter-arrival time.
  - [ ] **Protocol hierarchy** — bytes/packets by protocol layer. Sunburst or treemap. Who generates each protocol.
  - [ ] **Top talker pairs** — ranked directed edge list (who sent most to whom). Complements the per-node top talkers in StatsPanel.
  - [ ] **Temporal patterns** — session count and bytes over time, aggregated. Spot bursts, periodic activity, quiet periods.
  - [ ] **Hostname/cert grouping** — cluster external IPs by cert issuer, TLD, or hostname pattern without geolocation. "Most traffic to AWS infra", etc.
  - [ ] **LLM interpretation panel** — user provides API key (stored in localStorage, never sent to server). Frontend sends a structured JSON summary of the capture (top nodes, session counts, protocol distribution, notable SNIs, DNS queries, OS guesses) to the LLM with a fixed prompt: "Explain what is happening in this network capture in plain language. Focus on understanding activity, not finding threats." Response streams into a chat-style panel. Model choice: any OpenAI-compatible endpoint (user configures). Groundwork: `backend/api/capture_summary.py` that serializes capture state to the structured JSON the LLM receives.
- [ ] **Geolocation** — lowest priority
- [x] **Backend test suite** (v0.9.50) — pytest tests for the critical path: `build_graph()`, `build_mac_split_map()`, `filter_packets()`, `build_sessions()`, `compute_global_stats()`, plugin `analyze_global()` methods, analysis plugin `compute()` methods, and the v0.9.43 session scoping regression. Run: `cd backend && pytest tests/ -v`.
- [ ] **Address type annotation in NodeDetail** — show the type of each IP address in the IPs list in NodeDetail. Known types to detect and label: Private (RFC1918), APIPA (169.254.x.x), Loopback (127.x/::1), Link-local IPv6 (fe80::), Multicast IPv4 (224.x-239.x), Multicast IPv6 (ff00::/8), Broadcast (255.255.255.255), Documentation (198.51.100.x/203.0.113.x/192.0.2.x), Carrier-grade NAT (100.64.x.x). Display as a small coloured badge next to the IP. Pure frontend — no backend needed, all ranges are static.

- [x] **Backend centrality computation** (v0.9.50) — node centrality moved from client-side JavaScript to Python in `plugins/analyses/node_centrality.py`. Same Brandes algorithm, runs in the backend via `/api/analysis/results`. Frontend calls the API instead of computing locally. NetworkX dependency not needed — pure Python implementation scales well. Can upgrade to NetworkX later if graph sizes demand it.

### Done (recent)
- [x] Show Hostnames toggle (v0.9.1)
- [x] Seq/Ack Timeline inline in SessionDetail (v0.9.1)
- [x] App.jsx → useCapture hook refactor (v0.9.1)
- [x] VERSION single source of truth (v0.9.1)
- [x] IPv6 connections preserved after merge (v0.9.1)
- [x] mac_vendors working correctly (v0.9.1)
- [x] Annotations cleared on new upload (v0.9.1)
- [x] MAC vendor lookup (v0.8.7)
- [x] JA3 → app mapping (v0.8.7)
- [x] SSH/FTP/DHCP/SMB/ICMPv6 dissectors (v0.8.6)
- [x] Sessions panel local search + scope badge (v0.8.5)
- [x] Hide node, retransmission, PCAP slice (v0.8.3)

---

## 7. Running

### Production
```bash
cd swifteye && pip install -r requirements.txt
cd frontend && npm install && npm run build && cd ..
cd backend && python server.py
# http://localhost:8642
```

### Development (hot reload)
```bash
# Terminal 1:
cd swifteye/backend && python server.py

# Terminal 2:
cd swifteye/frontend && npm run dev
# http://localhost:5173 (proxies /api → :8642)
```

### Environment
- `SWIFTEYE_PORT` — server port (default: 8642)
- Log file: `backend/swifteye.log`

---

## 8. Documentation
- **README.md** — user-facing quick start, feature overview, changelog
- **docs/DEVELOPERS.md** — full developer docs: architecture, extension points, API reference, patterns
- **HANDOFF.md** — this file: project status, rules, roadmap
