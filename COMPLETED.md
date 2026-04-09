# SwiftEye — Completed Items

> Items moved here from `ROADMAP.md` when shipped. See `CHANGELOG.md` for full release history.
> Kept for dependency tracing and historical context.

---

## Summary Table

| ID | Version | Summary |
|----|---------|---------|
| [research-panel-redesign](#research-panel-redesign) | v0.15.15 | Full rework of ResearchPage.jsx — slot canvas, drag-and-drop, per-card filters |
| [graph-weight-selector](#graph-weight-selector) | v0.15.x | Node size / edge thickness by bytes or packets |
| [graph-png-export](#graph-png-export) | v0.15.x | One-click canvas screenshot (later replaced by export-html) |
| [per-packet-header-detail](#per-packet-header-detail) | v0.15.14 | Full L3/L4 headers per packet in Packets tab |
| [research-plotly-native-api](#research-plotly-native-api) | v0.15.19 | ResearchChart.run() returns go.Figure; framework injects SwiftEye template |
| [in-function-imports-audit](#in-function-imports-audit) | v0.15.11–12 | All imports hoisted to module level |
| [graph-fetch-dep-cleanup](#graph-fetch-dep-cleanup) | v0.15.9 | Removed stats circular dep from graph fetch useEffect |
| [set-identity-fix](#set-identity-fix) | v0.15.9 | Stable Set identity for React state; guard no-op updates |
| [search-evaluator-generic](#search-evaluator-generic) | v0.15.9 | Generic edge field iteration instead of hardcoded field names |
| [frontend-architecture-audit](#frontend-architecture-audit) | v0.15.x | Audit of oversized components, prop drilling, re-render issues |
| [investigate-subgraph-scoped](#investigate-subgraph-scoped) | v0.15.x | Stats panel scopes to investigated subgraph |
| [session-layer-classification](#session-layer-classification) | v0.15.x | ARP/ICMP correctly classified under L2/L3, not L5+ |
| [dpkt-parity](#dpkt-parity) | v0.17.0 | Unified dpkt reader; all dissectors on raw bytes; no threshold |
| [subnet-node-visual-redesign](#subnet-node-visual-redesign) | v0.17.x | roundRect, dashed stroke, member count badge for subnet nodes |
| [node-color-modes](#node-color-modes) | v0.17.x | Color nodes by OS, protocol mix, volume, or custom rules |
| [export-html](#export-html) | v0.17.x | Self-contained interactive HTML export replacing Export PNG |
| [graph-options-panel](#graph-options-panel) | v0.17.x | Graph Options in dedicated slide-in panel on right edge of canvas |
| [node-temporal-animation](#node-temporal-animation) | v0.18.0 | Animation pane: frame-by-frame replay of session activity for selected nodes |
| [logo-navigates-overview](#logo-navigates-overview) | v0.18.0 | SwiftEye logo in TopBar navigates to overview, clears selection |
| [panel-nav-reorder](#panel-nav-reorder) | v0.18.0 | Graph Options moved above Help in left panel nav order |
| [analysis-node-centrality](#analysis-node-centrality) | v0.19.x | Degree + betweenness + PageRank ranked table + graph highlight |
| [alerts-panel](#alerts-panel) | v0.19.0 | Alerts panel Phase 1: 4 detectors, AlertPluginBase, /api/alerts, AlertsPanel |
| [investigation-pdf-export-bug](#investigation-pdf-export-bug) | v0.20.x | PDF export 405 fixed: GET→POST fetch with blob download |

---

## Graph & Visualization

### research-panel-redesign
Full rework of `ResearchPage.jsx`. Slot-based canvas, right palette categorised as Host/Session/Capture/Alerts, drag-and-drop, per-card filters, expand to full-screen, full-row toggle, collapsible palette.
`status: done (v0.15.15)` · `priority: high` · `term: short` · `effort: medium` · `depends: none`

---

### graph-weight-selector
Let the user choose what drives node size and edge thickness: bytes or packets. Segmented button in LeftPanel. log-scaling for bytes, sqrt-scaling for packets. forceCollide updates on mode switch.
`status: done` · `priority: high` · `term: short` · `effort: low` · `depends: none`
*Details: HANDOFF.md §6 → "Graph weight metric selector"*

---

### graph-png-export
One-click screenshot of the graph canvas via `canvas.toDataURL()` for reports and incident documentation. Later superseded by `export-html`.
`status: done` · `priority: low` · `term: short` · `effort: low` · `depends: none`
*Details: HANDOFF.md §6 → "Graph PNG/SVG export"*

---

### node-color-modes
Dropdown in Graph Options: color nodes by address type (current), OS guess, dominant protocol, traffic volume, cluster membership, or custom metadata field.
`status: done` · `priority: medium` · `term: short` · `effort: low` · `depends: none`
*Details: HANDOFF.md §6 → "Node color mode selector"*

---

### investigate-subgraph-scoped
When "Investigate neighbours" or "Isolate connected component" is active, the right panel stats reflect the investigated subgraph — not the full capture.
`status: done` · `priority: high` · `term: short` · `effort: low` · `depends: none`
*Details: HANDOFF.md §6 → "Investigate subgraph scoped overview"*

---

### subnet-node-visual-redesign
Subnet entity nodes given distinct visual treatment: roundRect with 4px radius, dashed stroke (4px/2px dash), member count badge.
`status: done` · `priority: high` · `term: short` · `effort: low` · `depends: none`

---

### export-html
Replace the "Export PNG" button with "Export HTML". The export produces a self-contained, single-file HTML page containing an interactive D3 force graph of exactly what is currently on the canvas — same nodes, same edges, same cluster/subnet grouping, same visual state after all active filters and graph options. No SwiftEye panels, no controls, no backend dependency. The file can be opened in any browser and shared with anyone.

**What gets exported:** Visible nodes/edges after all current filters; node labels, sizes, and colours as rendered; edge thickness and colour; tooltip on hover; current zoom/pan position.

**What does NOT get exported:** Left/right panels, filter controls, session or packet data, the ability to load a new capture.

**Implementation:** Frontend-only. Serialize `nRef.current` and `eRef.current` to JSON, embed a minimal D3 force simulation + canvas renderer as an inline `<script>`, write as Blob and trigger download. Replaced `canvas.toDataURL` in `GraphCanvas.jsx`.
`status: done`

---

### graph-options-panel
Graph Options moved into a dedicated slide-in panel on the right side of the graph canvas, opened by a toolbar button. Contains all current Graph Options toggles (Size by, clustering algorithm + threshold, subnet grouping, hide broadcasts, IPv6 toggle). Left panel header area freed up.

**Touches:** `LeftPanel.jsx` (remove Graph Options section), `GraphCanvas.jsx` (add toolbar button), `GraphOptionsPanel.jsx` (new component), `App.jsx`, `useCapture.js`.
`status: done` · `priority: medium` · `term: short` · `effort: low` · `depends: none`

---

### node-temporal-animation
Animation pane that replays session activity for selected nodes over time. User selects 1+ nodes → animation fetches session start/end events from `/api/node-animation` → frame-by-frame playback on a dedicated canvas (replaces GraphCanvas while active). Spotlight nodes inherit positions from main graph; neighbours placed via D3 collision sim. Phase 1: playback engine, canvas render, history panel, options popover, tooltips, keyboard shortcuts. Phase 2: focused node filtering (pill row), draggable nodes (pointer-capture), right-click context menu (hide/focus/details), bulk hide inactive neighbours.

Files: `backend/routes/animation.py`, `backend/data/aggregator.py` (`build_node_session_events`, `build_node_animation_response`), `backend/models.py` (`NodeAnimationResponse`), `frontend/src/hooks/useAnimationMode.js`, `frontend/src/components/AnimationPane.jsx`, `frontend/src/api.js` (`fetchNodeAnimation`). Entry points: GraphCanvas context menu, NodeDetail button, MultiSelectPanel button.
`status: done (v0.18.0)` · `priority: medium` · `term: long` · `effort: high` · `depends: none`

---

### logo-navigates-overview
Clicking the SwiftEye logo in TopBar navigates to overview, clears selection, stops animation.
`status: done (v0.18.0)` · `priority: low` · `term: short` · `effort: low` · `depends: none`

---

### panel-nav-reorder
The left-panel navigation array reordered so "Graph Options" appears directly above "Help". Single array element reorder in `frontend/src/components/LeftPanel.jsx`.
`status: done (v0.18.0)` · `priority: low` · `term: short` · `effort: low` · `depends: none`

---

## Session & Data Display

### investigation-pdf-export-bug
`handleExport()` in `InvestigationPage.jsx` used `document.createElement('a')` + `link.click()` to trigger a download, which issues a `GET` request. The backend endpoint `POST /api/investigation/export` only accepts POST, causing a 405 Method Not Allowed. **Fixed in session 16:** replaced the anchor-click approach with `fetch('/api/investigation/export', { method: 'POST' })` → `res.blob()` → `URL.createObjectURL` → anchor download. Also removed the dead `investigationExportUrl()` helper from `api.js` and its import in `InvestigationPage.jsx`.
`status: done` · `priority: critical` · `term: short` · `effort: low` · `depends: none`

---

### per-packet-header-detail
Full L3/L4 headers per packet in the Packets tab: all IP fields, TCP flags, options, window size, seq/ack. Data already returned by `get_packets_for_session()` — frontend rendering task. Expandable per-packet rows show IP fields (version, ID, flags, frag offset, DSCP, ECN, TTL), TCP fields (data offset, urgent pointer, options list), ICMP type/code.
`status: done (v0.15.14)` · `priority: medium` · `term: short` · `effort: low` · `depends: none`

---

### session-layer-classification
ARP and ICMP were rendering under "Application (L5+)" which is wrong. Added optional `layer` property to session section components so ARP renders under "Link (L2)" and ICMP under "Network (L3)".
`status: done` · `priority: medium` · `term: short` · `effort: low` · `depends: none`
*Details: HANDOFF.md §6 → "Session detail layer classification for non-IP protocols"*

---

## Analysis Panel

### analysis-node-centrality
Degree centrality (most connected), betweenness (bridges), traffic-weighted PageRank. Ranked table + graph highlight button. Implemented in `AnalysisPage.jsx` `NodeCentralityPanel`. Client-side Brandes algorithm runs on `visibleNodes`/`visibleEdges` — respects time range and protocol filter. See `centrality-backend-migration` (in ROADMAP.md) for the planned backend migration.
`status: done` · `priority: high` · `term: short` · `effort: medium` · `depends: none`

---

### alerts-panel
Dedicated panel for security-relevant alerts and findings. Phase 1 shipped 4 detectors (ARP spoofing, suspicious UA, malicious JA3, port scanning), `AlertPluginBase` tier, `/api/alerts` endpoint, `AlertsPanel` with severity filtering, search, sort, evidence cards, and "Show in graph" navigation. See `CHANGELOG.md` v0.19.0.
`status: done (v0.19.0)` · `priority: medium` · `term: medium` · `effort: medium` · `depends: none`

---

## Data Ingestion & Protocols

### dpkt-parity
Port all dissectors to work on raw bytes so dpkt and scapy paths produce identical `pkt.extra`. **Done in v0.17.0** — unified dpkt reader uses `l5_dispatch.py` to construct scapy L5 objects from raw bytes, passing them to the same dissectors. One code path for all files, no threshold.
`status: done (v0.17.0)` · `priority: high` · `term: medium` · `effort: medium` · `depends: none`

---

## Scale & Performance

### research-plotly-native-api
Changed `ResearchChart.run()` contract from `-> dict` to `-> go.Figure`. The framework calls `.to_dict()` and injects a shared SwiftEye Plotly template (dark background, consistent colour palette, font) before serialising. Plugin authors write pure Plotly code with no SwiftEye-specific wrapper. Enables any Plotly chart type: 3D, geo maps, Sankey, treemap, sunburst, animations. Existing charts already called `fig.to_dict()` — change was to `return fig`. Added `constants/plotly_template.py`.
`status: done (v0.15.19)` · `priority: medium` · `term: short` · `effort: low` · `depends: none`

---

## Frontend Refactors

### graph-fetch-dep-cleanup
Removed `stats` from the graph fetch `useEffect` dependency array in `useCapture.js`. `stats` is only used to compute `allKeys` (for the "are all protocols enabled?" guard). Moving `allKeys` derivation to a stable ref broke the circular: stats update → graph refetch → new graph → stats update.
`status: done (v0.15.9)` · `priority: high` · `term: short` · `effort: low` · `depends: none`

---

### set-identity-fix
`enabledP`, `hiddenNodes`, `subnetExclusions`, `clusterExclusions` are `Set`s in React state. Every setter that returns `new Set(...)` creates a new reference even if contents are identical, triggering spurious downstream effects. Fixed: guard no-op updates (compare size + contents) and use functional setters with stable refs.
`status: done (v0.15.9)` · `priority: medium` · `term: short` · `effort: low` · `depends: none`

---

### search-evaluator-generic
`matchEdge()` in `useCapture.js` previously hardcoded field names: `tls_snis`, `http_hosts`, `dns_queries`, `ja3_hashes`, `ja4_hashes`, `tls_versions`, `tls_selected_ciphers`. Replaced with generic iteration over string/array properties — same pattern already used in `matchSession()`. Kept keyword hints (has tls, has dns) for protocol-name searches.
`status: done (v0.15.9)` · `priority: medium` · `term: short` · `effort: low` · `depends: none`

---

## Housekeeping

### frontend-architecture-audit
Identified oversized components to split, prop drilling to replace with context, unnecessary re-renders, missing error boundaries, inconsistent patterns. Audit saved at `audits/2026-03-30_frontend_audit.md`. Spawned: graph-fetch-dep-cleanup, set-identity-fix, search-evaluator-generic, usecapture-decomposition, graphcanvas-extraction, react-contexts.
`status: done` · `priority: high` · `term: medium` · `effort: low` · `depends: none`

---

### in-function-imports-audit
Full audit for imports inside function bodies. All moved to top level. Fixed in v0.15.11–0.15.12: `pcap_reader.py` (TLS/HTTP/ICMPv6/JA3), `dissect_icmp.py`, `dissect_dhcp.py`, `aggregator.py` (networkx), `routes/query.py`, `query_parser.py` (pyspark_translator), `routes/utility.py` (scapy wrpcap). Kept lazy: dpkt (optional dep), reportlab (optional/PDF-only).
`status: done (v0.15.11–12)` · `priority: low` · `term: short` · `effort: low` · `depends: none`
