# SwiftEye — Changelog

### v0.15.28 — April 2026
- **Graph Options in right panel** — `GraphOptionsPanel` now renders as a proper right-panel view (`rPanel === 'graph-options'`) instead of overlaying the canvas. Accessible via "Graph Options" in the left-panel nav (same list as Overview, Sessions, etc.). The panel fills the right panel area and uses the existing resize handle; its own resize handle and slide-in animation removed. The canvas-overlay Graph Options button and Export PCAP button both removed.

### v0.15.27 — April 2026
- **Graph Options Panel** — `GraphOptionsPanel.jsx`: slide-in overlay on the right edge of the canvas, opened by ⚙ toolbar button. Resizable drag handle on left edge (220–520px, default 300). Replaces the inline Graph Options block in `LeftPanel.jsx`. Three collapsible sections: Display (Nodes/Edges flip + Size by + Color by + label threshold for nodes), Data (subnet, merge, IPv6, hostnames, broadcasts — now with toggle switches), Clustering (algorithm + resolution unchanged).
- **Node Color modes** — new `nodeColorMode` state ('address'|'os'|'protocol'|'volume'|'custom'). Address=default (RFC1918 private/external). OS reads `node.os_guess`; mode card greyed if no OS data in capture. Protocol uses dominant entry from `node.protocol_set` → `pColors`. Volume maps `node.total_bytes` to a 4-stop heat gradient. Custom: array of `{color, text}` rules matched by CIDR/IP against `node.ips`; first match wins; falls back to Address. GraphCanvas.jsx updated with `resolveNodeColor()` helper; refs pattern used so render loop stays allocation-free.
- **Edge Color modes** — new `edgeColorMode` state ('protocol'|'volume'|'sessions'|'custom'). New `edgeSizeMode` state ('bytes'|'packets'|'sessions') separate from node size mode. `resolveEdgeColor()` and `resolveEdgeWidth()` helpers in GraphCanvas.jsx.
- **Export HTML** — removes `doExportPNG()` / "Export PNG" button. New `doExportHTML()` serialises current `nRef`/`eRef` snapshot with resolved colors, positions, labels → generates a zero-dependency single-file HTML with vanilla-JS canvas renderer: pan (drag), zoom (scroll), hover tooltip. Downloaded as `swifteye-graph.html`.

### v0.15.26 — April 2026
- **Per-chart data filters** — research charts can now declare a `build_data()` + `build_figure()` split instead of a single `compute()`. `build_data()` returns a flat list of entry dicts (one per plotted point/bar); the framework auto-detects filterable fields from those entries (IP, string, numeric, list) and returns a `filter_schema` alongside the figure on every run. The frontend caches this schema and renders per-chart filter controls in the card's filter drawer ("Chart filters" section, separate from the global scope controls). Filter values are sent as `_filter_<field>` params on re-run; the framework applies them to the entries before calling `build_figure()`. Filter changes and scope changes auto-rerun cards that have already been run. Charts that implement only `compute()` continue to work unchanged (legacy path). All 8 built-in charts migrated to `build_data` + `build_figure`. `_chart_template.py` updated with the new pattern. `docs/SCHEMA.md` updated with per-chart filter documentation.
- **Research chart scope pill** — `ScopePill.jsx` + `docs/SCHEMA.md` + `.gitignore` straggler files from the `feat/scope-toggle` merge committed (were untracked on `main`).

### v0.15.25 — April 2026
- **Centralized filter context** — `FilterContext.js` introduces a React context (`FilterContext`) and `useFilterContext()` hook that makes the global filter state observable application-wide without prop drilling. Canonical shape: `{ timeRange, enabledP, search, includeIPv6, protocolList, allProtocolKeysCount }`. Shared helpers: `toProtocolNames(enabledP, allProtocolKeysCount)` converts composite keys to simple protocol names for API calls (takes last `/`-delimited segment, deduplicates); `applyDisplayFilter(sessions, filterCtx)` replaces the duplicated session-filter function that existed identically in both `NodeDetail.jsx` and `EdgeDetail.jsx`. `FilterContext.Provider` added in `App.jsx`; `NodeDetail`, `EdgeDetail`, `ResearchPage`, and `TimelinePanel` now consume the context instead of receiving filter values as props. Removes `filterState` prop from `NodeDetail`/`EdgeDetail`, and `filterProtocols`/`filterSearch`/`filterIncludeIPv6` props from `ResearchPage`/`TimelinePanel`. Fixes silent bug: `SlotGrid` referenced `filterProtocols` etc. as free variables (never passed as props), so SCOPED mode on chart cards was never actually applying the global filter. Also replaces `ALL_PROTOCOLS` hardcoded list in `ResearchPage` with `filterCtx.protocolList` (actual capture protocols from `/api/protocols`). Roadmap item `centralized-filter-state` complete.

### v0.15.24 — April 2026
- **Scope pill reset on capture load** — `loadAll()` clears `swifteye_scope_node`, `swifteye_scope_edge`, and all `swifteye_scope_slot_*` keys from localStorage so scope always resets to SCOPED when a new capture is loaded.

### v0.15.23 — April 2026
- **Scope ALL node stats** — NodeDetail in ALL mode now also uses the full-capture node object (`fullGraphRef.current.nodes`) so packet count, traffic volume, protocols, ports, and top-neighbors all reflect the full capture, not the current time window. `fullGraphEdgesRef` promoted to `fullGraphRef` (stores nodes + edges).

### v0.15.22 — April 2026
- **Scope toggle ALL mode** — ALL now shows truly unfiltered data regardless of time range. `useCapture` stores `fullSessions` (captured at initial load, never updated on time changes) and `fullGraphEdgesRef` (first graph fetch, before any time filter). NodeDetail uses `fullSessions` for session rows and `fullGraphEdgesRef` for the connections list when scope=ALL. EdgeDetail uses `fullSessions` for its session rows.

### v0.15.21 — April 2026
- **Scope toggle bug fix** — `applyDisplayFilter` was comparing `enabledP.size` (composite protocol key count, e.g. 25) against `c.protocols.length` (simple protocol name count, e.g. 10), making the protocol filter condition always false. Fixed by exposing `allProtocolKeysCountRef` from `useCapture` and using `.current` as the `allProtocolCount` in `filterState`.

### v0.15.20 — April 2026
- **Scope toggle** — SCOPED / ALL pill added to NodeDetail, EdgeDetail, and Research chart cards (PlacedCard). SCOPED applies the active global display filter (protocol + search + IPv6) to the panel; ALL shows unfiltered data. Default: SCOPED. Persisted per panel type in `localStorage` (`swifteye_scope_node`, `swifteye_scope_edge`, `swifteye_scope_slot_<slotId>`). NodeDetail and EdgeDetail filter `sessions` client-side (sessions carry protocol, IPs, ports — sufficient for all filter dimensions). Research charts omit filter params from the POST body when ALL.

### v0.15.19 — April 2026
- **Chart category contract** — `ResearchChart` base class gains a `category` attribute (`"host"` | `"session"` | `"capture"` | `"alerts"` | `"other"`). Included in `/api/research` response. All existing charts declare their category. Frontend `inferCategory()` now reads `chart.category` from the API instead of a hardcoded name-lookup table; unknown values fall back to `"other"`. Added `"Other"` palette section as a catch-all for future charts.
- **Custom chart legend fix** — when colour field is categorical (text-split traces), legend moves below the chart horizontally so long labels (e.g. full User-Agent strings) no longer crush the plot area.
- **Chart template** — `backend/research/_chart_template.py` added as a starter file for new charts; not registered, not rendered.
- **Roadmap** — `custom-chart-scalable-sources` added: auto-derive source field lists from `protocol_fields/*.py` instead of maintaining a hardcoded `SOURCE_FIELDS` dict in `custom_chart.py`.

### v0.15.18 — April 2026
- **Custom chart fixes** — timestamp fields on X/Y axes now render as human-readable datetime strings instead of raw Unix epoch floats. Expanded overlay chart fills the full available height. Cleaned up two lint items in `custom_chart.py` (unused `_STATIC_SOURCES` set; dead `for tr in traces: pass` stub).
- **Roadmap additions** — `research-per-chart-filters`, `research-plotly-native-api`, `node-temporal-animation` added to `ROADMAP.md` with full design notes.

### v0.15.17 — April 2026
- **Custom research charts** — researchers can now build ad-hoc Plotly charts from within the Research panel without writing Python. A "Custom chart" button in the palette opens a two-step builder: step 1 picks a data source (Packets, Sessions, DNS, HTTP, TLS, TCP, DHCP, ARP, ICMP — greyed out if the current capture has no matching data); step 2 maps fields to X/Y axes, colour, marker size (scatter only), and hover fields, then picks chart type (Scatter, Bar, Histogram) and sets a title. The backend endpoint `POST /api/research/custom` receives the field-mapping payload and returns a Plotly figure — all aggregation stays server-side, consistent with existing Research chart architecture. Custom chart configs are persisted in `localStorage` keyed by capture filename so they survive page refresh and work across captures (different data, same structure). Placed custom cards show a pencil ✎ button in the header to reopen the builder pre-filled for editing.

### v0.15.16 — April 2026
- **Research panel bug fixes** — six layout and UX fixes to `ResearchPage.jsx`: slot canvas no longer loses scroll when a card is toggled to full-row width; ⇔ wide-toggle button moved into the card header (eliminates overlap with expand/remove/filters buttons); Plotly chart now resizes correctly when its slot goes full-row; category section labels removed from the main slot canvas (categories are palette-only); right palette is now collapsible via a toggle button; each palette category section is individually collapsible.
- **Expanded overlay improvements** — overlay scroll no longer bleeds to the background canvas; duplicate chart title in overlay header removed; chart fills the full overlay height instead of being capped at 380px.
- **Card drag-to-resize** — drag handle at the bottom of each placed card lets the researcher resize card height freely. Height resets to default when collapsing ⇔ back to half-row. Empty slots match the default card height for visual consistency.
- **Single add-slot button** — one "+ add slot" button at the bottom of the canvas replaces the per-category buttons that were cluttering the palette.

### v0.15.15 — March 2026
- **Research panel redesign** — `ResearchPage.jsx` fully rewritten. Slot-based drag-and-drop canvas replaces the old flat list. Charts palette on the right is categorised: Host, Session, Capture, Alerts (placeholder). Each category is collapsible. Slots are in a 2-per-row grid; any slot can be toggled to full-row width. Placed cards have per-chart filters (time range, protocol chips, search query, IPv6 toggle) that override the global scope. Cards can be expanded to cover the Research panel area. Drag a chart name from the palette into a slot, or click an empty slot to pick. Remove a card to return the slot to empty.
- **Self-hosted fonts + offline cleanup** — Google Fonts CDN link removed; JetBrains Mono and Outfit now served from `frontend/public/fonts/` via `@font-face` in `styles.css`. Plotly CDN `<script>` tag removed from `index.html` (Plotly was already bundled by Vite via `plotly.js-dist`).

### v0.15.14 — March 2026
- **Per-packet header detail** — Packets tab in SessionDetail now shows full L3/L4 headers per packet. Each row is expandable: click to reveal IP fields (version, ID, flags, frag offset, DSCP, ECN, TTL, checksum; flow label for IPv6), TCP fields (data offset, urgent pointer, options), and ICMP type/code. Fields are grouped by layer with muted labels. Already-visible summary fields (flags, TTL, window, seq, ack) are omitted from the expanded view to avoid duplication. Backend extended to return `tcp_data_offset`, `urg_ptr`, `icmp_type`, `icmp_code` in the packet detail response.

### v0.15.13 — March 2026
- **Parse performance — Round 2** — second full hot-path audit fixed six additional per-packet inefficiencies: `session_key` property now cached on `PacketRecord` (was recomputing two `sorted()` calls per access); `sessions.py` reuses the cached key instead of re-sorting; `_ARP_OPCODES` dict hoisted to module level (was rebuilt every ARP packet); `_TLS_VERSIONS` dict in `dissect_tls.py` hoisted to module level (was rebuilt every `_ver()` call); TCP flag decoding replaced per-packet loop with a precomputed 256-entry lookup table; stray `import dpkt` inside the IPv6 elif branch in `dpkt_reader.py` removed.

### v0.15.12 — March 2026
- **In-function imports audit (complete)** — all remaining `import` statements inside function bodies moved to module level. Fixed: `aggregator.py` (networkx), `routes/query.py` (resolve_query, parse_query_text, get_graph_schema), `data/query/query_parser.py` (pyspark_translator), `routes/utility.py` (scapy wrpcap/IP/TCP/UDP/ICMP/Raw). Kept lazy: `dpkt` (optional dep, imported once per file-read), `reportlab` (optional, PDF export only).

### v0.15.11 — March 2026
- **Parse performance fix** — `import` statements inside per-packet hot paths moved to module level across `pcap_reader.py`, `dissect_icmp.py`, and `dissect_dhcp.py`. Previously, `from scapy.layers.tls.record import TLS`, `from scapy.layers.http import HTTP`, `from .dpkt_reader import _add_ja_fingerprints`, and ICMPv6/BOOTP imports were re-executed on every packet (tens of thousands of times per file). Python caches modules but still pays the `sys.modules` lookup + attribute access cost per call. All are now imported once at module load and stored as module-level `None`-guarded names.

### v0.15.10 — March 2026
- **Sessions protocol upgrade** — `sessions.py` now promotes the session's protocol when a later packet in the same flow reveals the application-layer protocol. Previously, sessions created from TCP control packets (SYN/ACK, no payload) were locked to `"TCP"` forever; subsequent data packets with TLS payload were stored in the same session but never updated its protocol field. This caused `EdgeDetail` to find 0 sessions on TLS edges because `s.protocol === "TLS"` never matched `"TCP"`. Fix: when `s["protocol"] == s["transport"]` and a later packet has a more specific protocol, promote the session.
- **Graph node spreading** — reduced charge strength from -350 to -200 and tightened `distanceMax` dynamically by node count (<50→300px, 50–200→200px, >200→150px). Previously, -350 charge with 450px range cascaded for large captures causing nodes to spread to the edges of the screen. Link distance tightened 130→100px, link strength 0.4→0.5, center strength 0.04→0.06 to compensate.

### v0.15.9 — March 2026
- **Graph fetch dep cleanup** — removed `stats` from the graph fetch `useEffect` dependency array in `useCapture.js`. `stats` was only used to compute the total protocol key count (to check "are all protocols enabled?"), but changes to `stats` were triggering graph refetches — a circular pattern: stats update → graph refetch → new graph. Moved the key count derivation to a `allProtocolKeysCountRef` ref updated by a separate lightweight effect; the graph fetch effect reads it without depending on it.
- **Set identity fix** — `handleHideNode`, `handleUnhideAll`, `handleUnclusterSubnet`, `handleExpandCluster`, `handleCollapseCluster` now guard no-op updates: if the set already contains / doesn't contain the item, the original set reference is returned unchanged. Prevents spurious graph refetches and re-renders from React seeing a new Set object when contents are identical.
- **Generic edge search evaluator** — `matchEdge()` in `useCapture.js` no longer hardcodes field names (`tls_snis`, `http_hosts`, `dns_queries`, `ja3_hashes`, etc.). Replaced with generic iteration over string and array properties on the edge object (same pattern as `matchSession()`). Protocol-name keyword hints (`has tls`, `has dns`, `has http`, etc.) preserved via a declarative hint table. New edge fields from dissectors are now automatically searchable without code changes.

### v0.15.8 — March 2026
- **AnalysisPage centrality** — `computeCentrality()` kept client-side intentionally (operates on filtered `visibleNodes`/`visibleEdges` so protocol-scoped and time-scoped centrality work correctly). Comment added explaining why. The `node_centrality` analysis plugin continues to provide global rankings in the global plugin results.
- **`gR()` deduplication in GraphCanvas** — node radius formula was defined twice inside two different `useEffect` closures (lines 243 and 579). Hoisted to a single `useCallback` stored in `gRRef`. Both effects call `gRRef.current(n)`. Prevents silent drift if the formula is ever updated.
- **forceCollide fix** — changing graph weight mode (Bytes ↔ Packets) now updates the D3 `forceCollide` radius to match the new visual node sizes and briefly reheats the simulation (alpha 0.15). Previously, physics used old-mode collision radii causing node overlap.

### v0.15.7 — March 2026
- **Graph weight selector** — "Size by: Bytes / Packets" segmented control in Graph Options. Controls both node radius and edge thickness. Bytes uses log scaling; Packets uses sqrt scaling (was the previous default for nodes). State: `graphWeightMode` in `useCapture.js`. UI: `LeftPanel.jsx`. Rendering: `GraphCanvas.jsx` `gR()` and edge width logic.
- **Subgraph-scoped stats** — when investigation is active (`investigationNodes` set), a "Subgraph Focus" banner appears above the stats panel showing node count, connection count, bytes, and packet totals for the investigated subgraph. Computed in `App.jsx` from `c.graph.edges`; passed as `subgraphInfo` prop to `StatsPanel`.
- **Subnet node visual redesign** — subnet mega-nodes now render with rounded rectangle shape (`roundRect`), dashed stroke (4px on, 2px off), member IP count badge inside, and a "/" label when zoomed in. Distinct from gateway (diamond) and cluster (octagon) nodes.

### v0.15.4 — March 2026
- **Follow TCP Stream** — Wireshark-style conversation view in session detail (`StreamView` component). Merges consecutive same-direction payloads into color-coded "turns" (green=client `#7ee787`, blue=server `#79c0ff`). Turn headers show direction arrows, IPs, ports, byte counts. Three display modes: ASCII (default), hex dump, raw bytes. Copy-to-clipboard. Shows first 128 bytes per packet; full stream reassembly deferred to database backend.
- **PySpark translator** — new `analysis/pyspark_translator.py` parses PySpark DataFrame filter expressions (`df.filter(col("x") > y)`, `.contains()`, `.startswith()`, `.isin()`, `.rlike()`, `count()`, `&`/`|` combinators) into the JSON query contract using Python `ast` module. 27 tests. Frontend dialect selector changed from "Spark SQL" to "PySpark" with updated examples and placeholder.
- **Field reference panel** — `SchemaReference` component in QueryBuilder shows available node/edge fields grouped by type (Numeric, Sets, Flags, Text) with dialect-appropriate syntax (Cypher: `n.packets`, SQL: `packets`, PySpark: `col("packets")`).
- **Node statistics** — per-node `top_src_ports`, `top_dst_ports`, `top_neighbors`, `top_protocols` computed during aggregation (top-10 each). New `NodeStatistics` component with `MiniBar` horizontal bar charts. Neighbors tab clickable to navigate graph.
- **Query highlight clearing** — click empty canvas area to clear query highlights. `onClearQueryHighlight` prop on GraphCanvas.
- **Edge click fix in query results** — handled D3 force simulation replacing `source`/`target` strings with node object references, and graph edge IDs including protocol suffix (`A|B|TCP`) vs query returning `A|B`.
- **Time sort** — sessions sortable by `start_time` in SessionsTable and AnalysisPage. Backend `sort_by=time` added to `/api/sessions`.
- **HTTP cookie extraction** — tshark HTTP request adapter extracts `Cookie` header → `http_cookie`, response adapter extracts `Set-Cookie` → `http_set_cookie` (capped at 500 chars).

### v0.15.1 — March 2026
- **Backend query parsing (Phase 1.5)** — `POST /api/query/parse` endpoint parses freehand Cypher/SQL/Spark SQL text into the JSON query contract. Cypher parsed by a custom tokenizer + recursive-descent parser (handles comparisons, AND/OR, CONTAINS, STARTS/ENDS WITH, IS NULL/TRUE/FALSE, IN [...], =~ regex). SQL/Spark SQL parsed by `sqlglot` (v30.1.0) AST walking. `graphglot` evaluated but rejected — it's a GQL/ISO parser that fails on basic openCypher features. 47 pytest tests. Frontend wired to backend parser; frontend regex parsers (`parsers.js`) deleted. Examples updated with valid Cypher/SQL syntax.
- **Gantt chart performance** — capped at 2,000 sessions (top by packet count) to prevent Plotly from freezing the browser with 47K+ session captures.
- **Query UX** — explicit dialect selector (Cypher/SQL/Spark SQL) replaces auto-detect. Debounced error display (errors only appear after 1s of idle, not on every keystroke). `count(field) > N` support in both Cypher and SQL. 52 pytest tests.
- **Two-mode deployment architecture documented** — portable (on-the-go, embedded, zero-setup) vs enterprise (Spark/Databricks integration, petabyte-scale data slicing). PySpark → SQL translation plan using Python `ast` module. Query router abstraction separates parsing from execution. Primary audience is PySpark-fluent; SQL and Cypher serve the wider audience. See HANDOFF.md §6 and DEVELOPERS.md §14.

### v0.15.0 — March 2026
- **Graph query system — Phase 1** — persistent analysis graph built at capture load via `build_analysis_graph()` in `aggregator.py`. Stored on `CaptureStore` alongside sessions/stats/time_buckets. New `POST /api/query` endpoint accepts structured JSON queries with `target` (nodes/edges), `conditions` (field + operator + value), `logic` (AND/OR), `action` (highlight/select). Query resolver supports numeric, count-of, set, string, and boolean operators. Frontend query builder panel in left sidebar with dynamic categorized field dropdown, operator selector, value input, AND/OR combinator. Query results overlay as highlights on the existing view graph — no graph rebuild needed. See DEVELOPERS.md §14 for data structure and API contract.

### v0.14.2 — March 2026
- **Graph query system design** — documented the full plan for a structured query engine over a persistent NetworkX analysis graph. Categorized field dropdown (Counts, Count-of, Contains, Flags, Text, Topology) with dynamic field population. Engine-agnostic `POST /api/query` contract designed for future migration to Neo4j/SQL/PySpark. Three implementation phases: foundation (attribute queries + highlight/select), topology + actions (group/hide/isolate), power user (raw DSL, compound queries, regex). Visual design mockup in `query_system_design.html`. See DEVELOPERS.md §14 and HANDOFF.md §6.
- **Multi-capture platform vision** — documented the long-term vision: SwiftEye grows from single-capture single-user into a multi-capture, multi-user data platform with workspaces, projects, team features, graph DB backend, and SQL/PySpark query layers. Added to HANDOFF.md §6 and DEVELOPERS.md §1.

### v0.14.1 — March 2026
- **MAC split removed** — the `build_mac_split_map()` feature that created `IP::MAC` hybrid node IDs has been removed. IPs are nodes, MACs are metadata. The "Merge by MAC" toggle remains for combining nodes that share a MAC.
- **Hide broadcasts toggle** — new Graph Options toggle that filters broadcast (255.255.255.255, 0.0.0.0) and multicast (224.0.0.0/4, ff00::/8) addresses from the graph. Backend `exclude_broadcasts` param threaded through `filter_packets()` → `build_graph()` → API → frontend.
- **ARP enrichment** — pcap reader now extracts ARP opcode, sender/target MACs and IPs into `pkt.extra`. Tshark ARP adapter updated to include `arp_src_ip`/`arp_dst_ip`. New `protocol_fields/arp.py` accumulates ARP fields into sessions (opcode counts, sender/target MACs and IPs, broadcast count). New `session_sections/arp.jsx` renders ARP data with opcode tags.

### v0.14.0 — March 2026
- **Full tshark CSV adapter suite** — 8 ingestion adapters for tshark `‑T fields` tab-separated exports (hunt-workshop dataset format):
  - `metadata.csv` — base packet adapter producing full L2–L4 PacketRecords (MACs, IPs, ports, TCP flags/seq/ack/window, ICMP type/code, TTL, IP ID/flags). Port-based protocol resolution via `WELL_KNOWN_PORTS`. Parsed 826K packets from the hunt-workshop dataset.
  - `arp.csv` — ARP requests/replies. Opcode name resolution, broadcast detection.
  - `dns_request.csv` — DNS queries with query name, type (A/AAAA/CNAME/MX/etc.), transaction ID.
  - `dns_response.csv` — DNS responses with answers (name/type/data/TTL), response codes (NOERROR/NXDOMAIN/SERVFAIL/REFUSED).
  - `http_request.csv` — HTTP requests with method, URI, version. Extracts Host, User-Agent, Content-Type from headers dict.
  - `http_response.csv` — HTTP responses with status code/phrase. Extracts Server, Content-Type from headers dict.
  - `smb.csv` — SMB commands with command name, hex code, status, version, TID, flags.
  - `dce_rpc.csv` — DCE/RPC endpoints with operation number and ~12 well-known endpoint→UUID resolution (EPM, DRSUAPI, SAMR, LSARPC, NETLOGON, etc.).
- **Metadata join for protocol CSVs** — protocol-specific CSVs (DNS, HTTP, SMB, DCE/RPC) lack IP addresses. They join with `metadata.csv` by `frameNumber` to get the 5-tuple. Shared `load_metadata_index()` in `common.py` reads metadata.csv once and caches the index per directory so multiple adapters don't re-read.
- **`adapters/tshark/` directory** — 7 modules (metadata, arp, dns, http, smb, dce_rpc) plus shared `common.py`, mirroring the `adapters/zeek/` structure.

### v0.13.2 — March 2026
- **Zeek SMB adapters** — two new ingestion adapters for Zeek SMB logs:
  - `smb_files.log` — file access operations (open, read, write, delete, rename). Maps Zeek's `action`, `path`, `name`, `size` to SMB session fields (`smb_command`, `smb_tree_path`, `smb_filename`).
  - `smb_mapping.log` — share tree connects. Maps `path`, `service`, `share_type`, `native_file_system` to SMB session fields. Produces `TREE_CONNECT` operations.
- **Zeek DCE/RPC adapter** — new ingestion adapter for `dce_rpc.log`. Maps Zeek's `endpoint`, `operation`, `named_pipe` to DCE/RPC session fields. Includes a reverse-map from ~12 well-known Zeek endpoint names to interface UUIDs for compatibility with pcap dissector output.
- **Enhanced protocol_fields** — SMB protocol_fields gains `smb_services` and `smb_share_types` (from Zeek smb_mapping.log). DCE/RPC protocol_fields gains `dcerpc_operations` (named function calls) and `dcerpc_named_pipes` (from Zeek dce_rpc.log). Both are accumulated and serialized alongside existing fields.

### v0.13.1 — March 2026
- **Pathfinding** — right-click a node → "Find paths to..." → click a target node. Backend finds all simple paths (up to `max_paths=10`, `cutoff=5` hops) and returns **aggregated** hop-layer and edge-set data — individual paths are never sent to the frontend. The PathDetail panel shows:
  - **Hop layers** — nodes grouped by minimum BFS distance from source. Each node is collapsible: expand to see its edges on the path with protocol tags and byte counts.
  - **All Edges** — flat list of every unique edge across all discovered paths.
  - **IP text inputs** — pre-filled from graph pick, manually editable for direct entry. "Find" button re-runs the query.
  - **Directed/undirected toggle** — directed mode uses `nx.DiGraph` (respects initiator→responder direction), undirected uses `nx.Graph`.
  - Clicking any node/edge in PathDetail opens NodeDetail/EdgeDetail with a "← Back to Path Analysis" link.
  - Summary bar: path count, node count, edge count, max hops.
- **Graph algorithm architecture** — `graph_core.py` is the shared networkx graph builder used by both `clustering.py` and `pathfinding.py`. Adding a new graph algorithm module: create `analysis/your_module.py`, import `build_nx_graph`, add an API endpoint. See DEVELOPERS.md §13.
- **Pathfinding safety** — "Find paths to..." context menu item hidden for cluster/subnet mega-nodes (pathfinding operates on raw IP graph, not cluster-transformed). Pathfind state auto-clears when graph data changes (time range, filters, etc.) to prevent stale overlays.
- **API**: `GET /api/paths?source=X&target=Y&cutoff=5&max_paths=10&directed=false` — returns `{source, target, directed, path_count, hop_layers, edges, nodes}`.

### v0.12.2 — March 2026
- **Expand cluster** — right-click a cluster mega-node → "Expand cluster" to uncollapse it back into individual member nodes with their real edges. Uses a client-side exclusion set in `applyClusterView`; no API call needed. Exclusions reset when the clustering algorithm changes.
- **Manual clustering (lasso group)** — lasso-select nodes → right-click → "Group selected" now creates a real cluster (hexagon mega-node), not a synthetic node. Uses `manualClusters` state merged with backend cluster assignments in the view transform. Manual clusters are expandable, renamable, and work even without an algorithm running.
- **Edge detail cluster fix** — edges between clusters now show cluster names instead of raw `cluster:N` IDs. Session search resolves cluster IDs to real member IPs before querying the API.
- **Cluster detail rename** — click the cluster name in the ClusterDetail panel header to rename it. Dashed underline hint. Custom names display in both ClusterDetail and ClusterLegend. Names reset on algorithm change.
- **Clickable cluster members** — clicking a member IP in ClusterDetail opens NodeDetail for that node. App.jsx merges rawGraph nodes into the detail view so NodeDetail can find members even in clustered view.
- **Lasso union fix** — replaced ray-casting (even/odd rule) with winding number algorithm for point-in-polygon. Self-overlapping lasso paths now produce a union of enclosed regions instead of XOR.
- **Context menu overflow fix** — menu now repositions above/left of click point when it would overflow the canvas bottom or right edge.
- **ClusterLegend simplified** — removed rename/editing from legend overlay; it's now read-only. Rename lives in ClusterDetail panel only.

### v0.12.1 — March 2026
- Graph clustering: 4 algorithms (Louvain, k-core, hub-spoke, shared-neighbor) with hexagon mega-nodes
- Architecture refactor: view transform decoupling — backend returns cluster assignments as metadata, frontend does visual collapse client-side
- Cluster legend overlay with color/label mapping
- Cluster detail panel with member list, protocol breakdown, connections, sessions, notes
- Context menu redesigned into verb-based categories (Inspect/Investigate/Expand/Annotate/Edit)

### v0.11.2 — March 2026
- **Session detail readability overhaul** — improved visual hierarchy in SessionDetail panel. Top metrics (packets, bytes, duration) displayed as summary cards. Collapse sections wrapped in card backgrounds for visual grouping. Layer headers (L3/L4/L5+) use accent color with thicker border. Row labels dimmer, values brighter with font-weight 500 for stronger contrast. Directional traffic as colored direction cards (green →, blue ←). Seq/Ack numbers in labeled cell grid instead of flat text. More breathing room between sections. Chevron size increased. Notes textarea contrast fixed against card body.

### v0.11.1 — March 2026
- **Boundary detection audit** — fixed 3 bugs: TCP sequence wraparound false splits (now wraparound-safe), `last_resp_isn` leaking across session generations, `elif` chain preventing grace period fallback after SYN-ACK ISN check. Removed incorrect `seq_num > 0` guards (TCP seq 0 is valid). Cached TCP flags as frozenset for efficiency.
- **Session boundary documentation** — full developer-facing docs in DEVELOPERS.md covering all four boundary checks, flow state lifecycle, generation tracking, and how to add new protocol boundary checkers. Written for clarity without assumed project jargon.

### v0.10.6 — March 2026
- **Test suite import cleanup** — moved all in-function imports to top level in `test_core.py`. Added roadmap item for full codebase audit of remaining in-function imports.

### v0.10.5 — March 2026
- **Zero data loss alignment** — all 21 `CAP_*` constants removed from protocol field accumulators and `sessions.py`. Data now accumulates unbounded during session building; a shared `cap_list()` applies a generous `SERIALIZE_CAP = 500` at serialization time with `_total` companion keys for frontend "X of Y" display. Dissector-level caps removed from `dissect_dns.py`. Lazy protocol init replaces `all_init()` — protocol fields only appear on sessions that actually contain that protocol's traffic. Uses try/except KeyError pattern in `all_accumulate()`.
- **Session boundary detection** — `build_sessions()` now splits flows that reuse the same 5-tuple into separate sessions using three generic transport signals plus protocol-specific boundary checkers: (1) TCP FIN/RST close + SYN reopen, (2) timestamp gap >60s for UDP / >120s for TCP, (3) TCP seq jump >1M + time gap >5s, (4) protocol-specific `check_boundary()` from protocol_fields modules (OR logic — any signal triggers a split). Split sessions get suffixed IDs (`…#1`, `…#2`). Conservative thresholds — false non-splits preferred over false splits.
- **DHCP transaction ID splitting** — DHCP dissector now extracts `dhcp_xid` (BOOTP transaction ID). DHCP protocol field module provides `check_boundary()` that splits sessions when the xid changes on the same 5-tuple. Separates interleaved DHCP transactions from multiple clients broadcasting on the same subnet.
- **Protocol boundary checker contract** — protocol field modules can now define an optional `check_boundary(flow_state, ex, ts) → bool` function, auto-discovered alongside `init/accumulate/serialize`. Allows application-layer protocols to contribute session split signals without modifying `sessions.py`.
- **Wireshark-style SYN-ACK ISN detection** — after FIN/RST, a SYN-ACK with a new Initial Sequence Number (different from the previous responder ISN) triggers an immediate session split. Catches new connections where the SYN was missed but the responder's SYN-ACK reveals a new ISN. Retransmitted SYN-ACKs (same ISN) are correctly ignored.
- **Zeek-style per-protocol inactivity timeouts** — DNS (10s), HTTP (30s), and DHCP (10s) now define `check_boundary()` with protocol-specific inactivity timeouts, inspired by Zeek's connection tracking defaults. Generic fallback remains 60s for UDP and 120s for TCP. Each protocol owns its timeout — no changes to `sessions.py` needed.
- **5-second grace period after FIN/RST** — after a TCP FIN or RST, a pure SYN splits immediately (unambiguous new connection). Any other packet within 5 seconds stays in the same session (teardown traffic). After 5 seconds, any packet triggers a split (connection is done). Grace window anchored to the first FIN/RST, not subsequent FIN-ACKs.

### v0.10.4 — March 2026
- **Zero data loss documentation** — codified the zero data loss principle in HANDOFF.md §1 and DEVELOPERS.md §3/§4. Documented current violations (silent accumulation caps, eager protocol init), 6-step execution plan, decision tree for when limits are acceptable vs. violations, and memory/compute tradeoffs. Added HIGH PRIORITY roadmap item for the alignment work.
- **Visualize time slider debounce** — slider no longer rebuilds the D3 graph on every frame during drag. Slider position updates instantly; `filteredRows`/`graphData` recompute after a 300ms debounce.
- **OS filter chip consolidation** — OS quick-filter chips now group by family keyword (e.g. one "Windows (3)" chip instead of separate "Windows 10/11", "Windows 7/8", "Windows (likely)" chips). Fixes confusing behavior where multiple chips produced the same filter.

### v0.10.3 — March 2026
- **Dynamic session detail rendering** — `SessionDetail.jsx` gutted from 1171→646 lines. 11 protocol sections (TLS, HTTP, SSH, FTP, DHCP, SMB, ICMP, Kerberos, LDAP, DNS, QUIC) extracted to auto-discovered components in `frontend/src/components/session_sections/`. Vite `import.meta.glob` discovers new sections at build time. Generic fallback renderer auto-displays unclaimed protocol field prefixes (e.g. `smtp_`, `mdns_`) as key-value rows — new backend protocols appear in the UI without any frontend code.
- **DHCP dissector bug fix** — scapy parses DHCP into its own BOOTP/DHCP layer, consuming the Raw layer. The dissector checked `pkt.haslayer("Raw")` which was always False. Fixed to read from scapy's BOOTP layer directly, falling back to Raw for non-scapy paths.

### v0.10.2 — March 2026
- **Session field explosion refactor** — `sessions.py` gutted from 884→280 lines. All protocol-specific field handling (init, accumulate, serialize) extracted to 18 auto-discovered modules in `analysis/protocol_fields/`: TLS (with JA3/JA4), HTTP, SSH, FTP, ICMP, DNS, DHCP, SMB, Kerberos, LDAP, SMTP, mDNS, SSDP, LLMNR, DCE/RPC, QUIC, Zeek metadata. New protocols just drop a file in `protocol_fields/` — auto-registered via `pkgutil.iter_modules`.
- **JA3/JA4 merged into TLS** — JA3/JA4 fingerprint accumulation and `lookup_ja3` enrichment moved from standalone `ja3.py` into `tls.py`. JA3 is a TLS derivative, not a separate protocol.

### v0.10.1 — March 2026
- **Zeek multi-log enrichment** — new adapters for dns.log, http.log, ssl.log that enrich sessions when uploaded alongside conn.log. Shared Zeek utilities extracted to zeek_common.py. 5-tuple matching joins L7 data to existing sessions.
- **Edge session threshold** — edges show 20 sessions initially with "Show more" button that fetches from API. Prevents UI stall on high-traffic edges.
- **Graph brightness** — node and edge colors brightened for better visibility.
- **Timeline bucket cap** — MAX_RAW_BUCKETS=15000 prevents crashes on long captures with small bucket sizes.
- **Zeek DSCP fix** — DSCP/ECN no longer shows for non-pcap sources.

### v0.9.82 — March 2026
- **QUIC dissector (Phase 1)** — new protocol dissector for UDP port 443. Parses QUIC long headers to extract version, Destination/Source Connection IDs, and packet type. Decrypts QUIC Initial packet header protection and payload using HKDF-derived keys from the DCID (RFC 9001 §5), then parses CRYPTO frames to extract TLS ClientHello SNI, ALPN, supported TLS versions, and cipher suites. Payload signature detection works on any UDP port. Session aggregation collects QUIC versions, connection IDs, SNIs, and ALPN protocols. Requires `cryptography` package for decryption; falls back to header-only parsing without it.
- **Changelog split** — detailed version history moved from README.md and HANDOFF.md into standalone CHANGELOG.md.

### v0.9.81 — March 2026
- **HTTP User-Agent timeline** — new Research chart. X = time, Y = source IP, colour = User-Agent string. One trace per unique UA, dot size scaled by request payload bytes. Shows method + URI + host + destination in hover. Useful for spotting automated tools (curl, PowerShell, python-requests), C2 beaconing patterns, UA spoofing, and lateral movement.
- **SMTP dissector** — new protocol dissector for TCP ports 25/587. Extracts EHLO domain, MAIL FROM, RCPT TO, AUTH mechanism (PLAIN/LOGIN/CRAM-MD5), STARTTLS indicator, server banner, response codes. Session aggregation collects all fields.
- **mDNS dissector** — new protocol dissector for UDP port 5353. Parses DNS wire format to extract query names, service types (`_http._tcp.local`), service instance names, SRV target hostnames + ports, TXT records, A/AAAA answers. Uses scapy DNS layer with raw byte fallback.
- **SSDP dissector** — new protocol dissector for UDP port 1900. Extracts M-SEARCH/NOTIFY method, Search Target (ST), Unique Service Name (USN), Location URL, Server header, Notification Sub-Type (NTS).
- **LLMNR dissector** — new protocol dissector for UDP port 5355. Parses DNS wire format to extract query names, query types, answers. LLMNR is commonly abused in Windows AD environments for credential relay attacks (Responder/NTLM relay).
- **DCE/RPC dissector** — new protocol dissector with payload fingerprinting (magic bytes `05 00`/`05 01` + valid packet type). Works on any port — detects RPC on ephemeral ports without needing to track the Endpoint Mapper. Extracts packet type (bind/request/response/fault), interface UUID from bind packets, and maps UUIDs to ~40 known Windows services (DRSUAPI, SAMR, LSARPC, SVCCTL, NETLOGON, WINREG, WMI, DCOM, EventLog, etc.). Also extracts operation numbers from request packets. Port 135 added to WELL_KNOWN_PORTS.
- **OUI vendor table expanded** — from ~688 to ~1050 entries, focused on: Microsoft ecosystem (Intel, Realtek, Dell, HP/HPE, Lenovo, ASUS, Acer, MSI, Gigabyte, Broadcom, Qualcomm, MediaTek), network infrastructure (Cisco, Meraki, Juniper, Aruba, Ubiquiti, Palo Alto, Fortinet, MikroTik, Sophos, WatchGuard, Brocade, Extreme, Arista, Ruckus, Huawei, TP-Link, Netgear), virtual machines (VMware, VirtualBox, QEMU/KVM, Xen, Hyper-V), and printers (HP Printer, Canon, Epson, Brother, Lexmark, Xerox, Ricoh, Konica Minolta).
- **User-Agent text brighter** — the User-Agent strings in SessionDetail HTTP section were rendered with `var(--txD)` (dim text), making them hard to read. Changed to `var(--txM)` (medium) matching other protocol field values.
- **Collapse state carries over all sections between sessions** — previously only sections the user had explicitly toggled were carried over when navigating between sessions on the same edge. Sections with `open` as a default prop (HTTP, DNS) would appear closed on the next session because they weren't in the cloned Set. Root cause: the collapse context used `Set<title>` (in set = open, not in set = closed), ignoring the component's `open` prop default. Fix: changed to `Map<title, boolean>` where entries represent explicit user toggles. Titles not in the Map fall back to the component's `open` prop. Now all collapse state — both user-toggled and default-open sections — carries over correctly.
- **Generic keyword search now matches session-level fields** — searching "mozilla" or "powershell" now finds edges whose sessions contain matching User-Agent strings, URIs, SSH banners, Kerberos principals, LDAP bind DNs, FTP commands, DHCP hostnames, and any other session field. Previously the search only checked edge-level fields (tls_snis, http_hosts, ja3/ja4). The new `matchSession` function iterates all string and array values on session objects generically, so future protocol additions are automatically searchable. Matching sessions are mapped back to their graph edges via IP+protocol matching.
- **Roadmap additions**: QUIC dissector (Phase 1: cleartext header + SNI from Initial packets; Phase 2: SSLKEYLOGFILE decryption), TLS private key decryption (SSLKEYLOGFILE upload for HTTPS/QUIC/LDAPS/SMTPS deep inspection), SQL query layer (expressive queries beyond display filter — Phase 1: filter extensions, Phase 2: full SQL endpoint).

### v0.9.54 — March 2026
- **Client-side search** — the TopBar search box now evaluates client-side against all node and edge fields: IPs, MACs, MAC vendors, hostnames, OS guess, metadata, protocol, TLS SNI, HTTP host, DNS queries, JA3/JA4 hashes, TLS versions, cipher suites. Instant (no backend re-fetch), non-destructive (dims non-matches like the display filter). Backend `search` param remains in the API for programmatic use and pcap export.
- **Protocol hierarchy tree** — the flat protocol list in the left panel is now a collapsible tree: IPv4/IPv6 → Transport (TCP/UDP/ICMP) → Application protocol. Click a branch to toggle all children. Unresolved transport-only packets appear as "Other TCP" / "Other UDP". Packet counts shown at every level.
- **Address type annotation in NodeDetail** — each IP in the IPs list now has a colored badge: Private (RFC1918), Loopback, APIPA (169.254.x), Multicast, Broadcast, CGNAT (100.64.x), Documentation ranges, Unspecified, and IPv6 equivalents (Link-local, ULA, Multicast). Pure frontend — `classifyIp()` function in `NodeDetail.jsx`.
- **Enhanced DNS dissection** — the DNS dissector now extracts: query type name (A/AAAA/CNAME/MX/etc.), response code name (NOERROR/NXDOMAIN/SERVFAIL), DNS flags (AA/TC/RD/RA), transaction ID, structured answer records with per-record type/data/TTL, authority section (NS/SOA), and additional section. Session aggregation passes all new fields through. SessionDetail DNS section redesigned: query/response badges, record type chips, rcode with color coding (green=NOERROR, red=error), structured answer rows with TTL, authority section, flags row with tx ID.
- **Payload entropy** — Shannon entropy computed per packet in the session detail API (minimum 16 bytes). Classified into bands: structured/repetitive (<1.0), low entropy (<3.5), text/markup (<5.0), mixed/encoded (<6.5), high entropy/compressed (<7.5), likely encrypted/compressed (≥7.5). Shown as a colored badge on each payload packet row in the PAYLOAD tab.
- **OS filter now finds gateway nodes** — gateways detected by the Network Map plugin now get `os_guess = "Network device (gateway)"` which **overrides** the OS fingerprint. A Linux-based router that OS Fingerprint classifies as "Linux 4.x/5.x" will show as "Network device (gateway)" in the OS filter chips instead. The OS fingerprint details (TTL, window size, etc.) remain visible in the OS Fingerprint plugin section — nothing is lost. Rationale: researchers filtering by "Network device" expect to find routers regardless of their underlying OS.
- **IPv6 nodes pruned after merge-by-MAC when Show IPv6 is off** — the packet-level IPv6 filter correctly keeps dual-stack traffic where the local host resolves to IPv4 via entity_map, but this left behind graph nodes for external IPv6 endpoints (e.g. `2606:4700::`). Added a post-filter in `build_graph()` that removes nodes whose canonical ID is IPv6 (and their edges) when `include_ipv6=False` and entity_map is active.
- **Known bugs documented**: JA3/JA4 only appears on HTTPS sessions where the ClientHello was captured. Sessions started before the capture begins will not have fingerprints — this is expected behavior, not a bug.

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


### Known limitations — JA3/JA4 fingerprinting
JA3 and JA4 fingerprints are computed **only from TLS ClientHello packets**. Sessions
where the capture started after the TLS handshake completed will not have JA3/JA4 data.
This is inherent to the fingerprinting method — the ClientHello must be present in the pcap.

Additionally, when scapy's TLS layer is installed (via the `cryptography` dependency),
scapy parses TLS records into structured objects and removes the `Raw` layer. The JA3/JA4
computation needs the raw bytes. The code has fallback paths (`lastlayer().load`,
`bytes(tcp.payload)`, `pkt[TLS].original`) but these may not recover raw bytes on all
scapy versions. If a session clearly shows a ClientHello in the Payload tab but has no
JA3/JA4, this is the likely cause. Fix: improve the raw byte recovery in `pcap_reader.py`
JA3/JA4 block.



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
