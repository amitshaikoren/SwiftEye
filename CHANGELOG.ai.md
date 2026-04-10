# Changelog — AI Reference

**Format:** `vX.Y.Z | YYYY-MM-DD | type | component | one-line summary`
**Types:** `feat` · `fix` · `refactor` · `perf` · `chore` · `docs`
**Source of truth:** `CHANGELOG.md`. Update both during the session; flush prose to `CHANGELOG.md` at session end.

**Grep recipes:**
- By version: `grep "v0.20" CHANGELOG.ai.md`
- By component: `grep "| animation |" CHANGELOG.ai.md`
- By type: `grep "| fix |" CHANGELOG.ai.md`

---

## Log

v0.23.0 | 2026-04-10 | feat | adapters | adapter-schema-negotiation — new `backend/parser/schema/` package (contracts, inspector, staging) sits before adapters in the pipeline. All Zeek adapters (conn, dns, http, ssl, smb_files, smb_mapping, dce_rpc) and tshark metadata adapter now declare `declared_fields` (required/optional SchemaField list) and implement `get_header_columns()` / `get_raw_rows()` / `_rows_to_packets()` / `parse_with_mapping(mapping)`. Upload flow is two-phase: detect adapter → inspect schema → if clean proceed; if mismatch, stage the file (UUID token), return `schema_negotiation_required: true` + `schema_report` + `staging_token` to the frontend. New `POST /api/upload/confirm-schema` accepts token + user-confirmed `mapping` dict → `parse_with_mapping` → full ingest. Frontend: new `SchemaDialog.jsx` renders the detected-vs-expected columns as a mapping table (dropdowns, required-field warnings, suggested-mapping pre-population, Confirm & Ingest button disabled until all required fields mapped). Wired via `schemaNegotiation` / `handleSchemaConfirm` / `handleSchemaCancel` in useCapture + `confirmSchemaMapping` in api.js + `<SchemaDialog>` in App.jsx upload screen. Test fixtures: zeek conn/dns (clean), zeek conn (renamed cols), tshark metadata (clean + renamed). 25 backend tests — all passing.

v0.22.7 | 2026-04-10 | feat | timeline-graph | shift-select operations popover — shift-clicking up to 2 placed event nodes accumulates them into a new `selectedPair` state (`max 2, FIFO drop-oldest`, click-same-id-again toggles off). Pair-selected nodes get a dashed blue halo (`r = NODE_R + 4`, `strokeDasharray "3 3"`) around the existing severity ring. When length === 2, an operations popover renders anchored to the on-screen midpoint of the pair (canvas-space midpoint × `tRef.current.k` + `tRef.current.{x,y}`, so it tracks zoom/pan). Popover offers "Draw edge" (opens existing label prompt, then clears the pair) and "Clear". The Draw edge button is disabled with a tooltip when `timelineEdges` already contains a manual edge for the pair (uses the new `edgePairKey` helper). Plain (non-shift) click clears `selectedPair`; canvas background click clears it too. Plays nicely with the existing draw-mode button — both reach the same `addTimelineEdge` flow, this just lets the user pick the two nodes first and then commit.

v0.22.6 | 2026-04-10 | feat | timeline-graph | multi-edge parallel arcs — duplicate manual edges between the same pair of placed events used to overlap into a single line. Now they fan out as parallel quadratic-Bezier arcs perpendicular to the chord. New `pairOffsets` memo groups `timelineEdges` by sorted pair-key and assigns each edge an offset of `(i - (n-1)/2) * 22px` so the spread is symmetric around the chord (1 → straight, 2 → ±11, 3 → -22/0/+22, etc.). New helpers `edgePairKey(a, b)` and `arcPath(ax, ay, bx, by, offset)` — the latter returns `{d, midX, midY}` where the midpoint is the actual on-curve midpoint (`mid + perp * offset`) so labels sit on the arc, not on the chord. Manual edges now render as `<path>` instead of `<line>`. Suggested edges left as straight `<line>` for now (they're already merged-per-pair via the ×N badge so don't need fanning). Main GraphCanvas multi-edges deferred — protocol-keyed edges already separate visually and the `(src|dst|protocol)` triple keeps duplicates in different lanes.

v0.22.5 | 2026-04-10 | feat | timeline-graph | back-to-investigation breadcrumb — after the user clicks "View in graph" from inside InvestigationPage, a sticky banner appears in the top-left of the main graph view with `← Back to Timeline Graph` (or `Documentation`, depending on which tab they came from) and a `×` dismiss. Clicking the back link calls `switchPanel('investigation')` AND restores the source tab. (1) `tab` state lifted from local in `InvestigationPage` up to `App.jsx` (`investigationTab` + `setInvestigationTab`); InvestigationPage falls back to local state if the prop isn't passed (so it's still independently usable). (2) New App.jsx state `returnToInvestigationTab` (`null | 'documentation' | 'timeline'`) — set inside `onSelectEntity` to capture the source tab. (3) Banner rendered inside the graph container (`zIndex: 12`, top-left, blue tinted, mirrors the existing pathfind/hidden-nodes banner styling). (4) `useEffect` clears `returnToInvestigationTab` when `c.rPanel === 'investigation'` so the breadcrumb auto-resets if the user returns to investigation by any other route (left-nav button, etc.) — the breadcrumb has nothing to point at once they're already there.

v0.22.4 | 2026-04-10 | feat | timeline-graph | view-in-graph highlight — "View in graph" context menu in TimelineGraph (and the click in NodeDetail/EdgeDetail/SessionDetail mini-view) now actually pulses the entity in the main GraphCanvas. Reuses the existing `queryHighlight` mechanism (orange ring + glow) that was already wired for the AlertsPanel "Show in graph" button. App.jsx `onSelectEntity` rewritten: switches panel FIRST (since `switchPanel` calls `clearSel`), then re-selects the entity, then calls `setQueryHighlight({ nodes, edges })` so React 18 batching keeps the latest selection + highlight. Node case highlights the node ID directly. Edge case highlights the edge in `u|v` form plus both endpoint nodes. Session case fetches `session_detail`, resolves `src_ip`/`dst_ip` to node IDs (direct id match, then fallback to `n.ips.includes(ip)` for subnetted nodes), and highlights both endpoints + the canonical edge id (both orderings, since the GraphCanvas check accepts either). The highlight clears when the user clicks empty canvas (existing `onClearQueryHighlight` path).

v0.22.3 | 2026-04-10 | feat | timeline-graph | entity color coding + legend — distinct fill tint per entity type (node #58a6ff blue, edge #a371f7 purple, session #3fb950 green) at ~13% alpha (`ENTITY_FILL_ALPHA = '22'`). Replaces flat `fill="var(--bgP)"` on the node disc with `entityFill(ev.entity_type)`. New legend in the sub-toolbar (after the Ruler checkbox) renders three swatches (full-saturation border, low-alpha fill) so the color↔type mapping is discoverable. Severity ring (stroke) is unchanged — color now encodes BOTH severity (ring) and entity type (fill). Also tightened `setRulerOn?.()` optional-call so the toggle doesn't crash if the prop is missing during a transient remount.

v0.22.2 | 2026-04-10 | feat | timeline-graph | layout persistence — node positions and ruler state now survive tab navigation. (1) `rulerOn` lifted from TimelineGraph local state to `useEvents` so it persists across mount/unmount. (2) Sync effect locks every node via `fx`/`fy` from canvas_x/canvas_y on creation, so on remount the d3-force charge + collide can no longer drift them from their persisted positions. Sim is `alpha(0).stop()`-ed in ruler-off mode entirely. (3) Drag-end now KEEPS `fx`/`fy` locked at the drop point (was: cleared them, letting the sim drift). (4) Ruler mode releases all `fx`/`fy` locks so the y-force can act; ruler-on→off transition (detected via `prevRulerRef`) walks each node and persists post-ruler positions back to canvas_x/canvas_y via `placeEvent`, so toggling ruler off cements the time-sorted layout. Ruler-mode drag-end keeps `fx` locked but releases `fy` so the y-force resumes pulling.

v0.22.1 | 2026-04-10 | feat | timeline-graph | reject suggested edge — `rejectedSuggestions` Set in useEvents (keyed by unordered pairKey), `rejectSuggestion(from, to)` callback, suggestedEdges memo filters out rejected pairs (depends on the Set so updates are reactive). "Reject all" in the suggestion popup now actually rejects the pair instead of just dismissing the popup. Wired through useCapture → App.jsx → InvestigationPage → TimelineGraph.

v0.22.0 | 2026-04-10 | feat | timeline-graph | zoom + pan canvas — d3.zoom on the SVG, scaleExtent [0.3, 3], wheel-to-zoom, drag-empty-canvas-to-pan. Transform stored in tRef (ref, not state) and applied via a wrapping `<g transform={tRef.current.toString()}>`. Ruler axis is inside the transformed group, so its ticks scale with the canvas. New `canvasPoint(clientX, clientY)` helper inverts the current transform for node-drag and drop handlers — node positions / canvas_x / canvas_y stay in untransformed canvas space. Pan suppressed on node/edge drag via `data-pan-skip="true"` + `filter: e => !e.target.closest('[data-pan-skip]')`. A transparent background `<rect>` covers the SVG so empty-canvas pan works even when no nodes are placed yet.

v0.21.2 | 2026-04-10 | fix | animation | RESCUE — isolate filters timeline events upstream in useAnimationMode (frames, play loop, history, slider, not just edges). The original v0.20.4 commit 95a6c63 was on a dangling `fix/animation-isolate-frames` branch that never reached main; rescued by checking out useAnimationMode.js + AnimationPane.jsx and re-applying the 2-line App.jsx prop pass-through (isIsolated/setIsIsolated). v0.21.0/v0.21.1 had not touched those two files so the checkout was clean.

v0.21.1 | 2026-04-09 | fix | events | EventCard contrast bumped (was using --bgP = panel bg, now rgba(255,255,255,.045) + brighter border + drop shadow + slight padding bump)
v0.21.1 | 2026-04-09 | fix | investigation | Save / Export PDF buttons hidden on Timeline Graph tab — wrapped in `{tab === 'documentation' && ...}` (markdown-only ops)
v0.21.1 | 2026-04-09 | feat | edge-detail | Flag-as-Event button in EdgeDetail header (red #f85149 SVG, calls onFlagEvent prop)
v0.21.1 | 2026-04-09 | feat | node-detail | Flag-as-Event button in NodeDetail header (same pattern as SessionDetail/EdgeDetail)
v0.21.1 | 2026-04-09 | feat | app | wired onFlagEvent in App.jsx for EdgeDetail (selEdge) + NodeDetail (looks up node obj from detailNodes for cluster compat)
v0.21.0 | 2026-04-09 | feat | events | new useEvents hook — event CRUD, in-memory state, suggested-edge engine (same_node/same_subnet/same_protocol), merge-per-pair with ×N badge
v0.21.0 | 2026-04-09 | feat | events | EventFlagModal — flag node/edge/session as event with severity, title, notes
v0.21.0 | 2026-04-09 | feat | events | EventsPanel + EventCard — right-panel events list, sorted by capture_time asc, beta caveat banner
v0.21.0 | 2026-04-09 | feat | events | TimelineGraph SVG canvas — d3-force layout, ruler toggle (forceY time-mapped), drag-to-place from EventsPanel, drag-reposition nodes, suggested edges (dashed/dimmed), draw-edge mode, right-click context menu (View in graph / Unplace), node + edge detail cards
v0.21.0 | 2026-04-09 | feat | graph | GraphCanvas Flag-as-Event context menu items (node + edge) + severity indicator dots overlay (reads tRef.current for zoom transform)
v0.21.0 | 2026-04-09 | feat | session-detail | Flag button in SessionDetail header
v0.21.0 | 2026-04-09 | feat | investigation | InvestigationPage tab bar (Documentation / Timeline Graph), ref-chip render pass (NUL-byte placeholder), drop handler for EventsPanel drag
v0.21.0 | 2026-04-09 | feat | investigation | drag-to-insert event ref chips in markdown editor; ref-chip click-throughs via onSelectEntity in App.jsx
v0.20.4 | 2026-04-09 | docs | planning | event-type-system Opus plan written (docs/plans/event-type-system.md) — full design, phase 1/2 split, 6 open questions, Phenomena concept
v0.20.4 | 2026-04-09 | docs | planning | event-system-mockup.html created (docs/mockups/) — Documentation tab + Timeline Graph tab with suggested edges
v0.20.4 | 2026-04-09 | chore | roadmap | FOR_OPUS.md: added event-type-system
v0.20.4 | 2026-04-09 | chore | roadmap | new item: adapter-schema-negotiation (interactive column mapping for mismatched adapter schemas)
v0.20.4 | 2026-04-09 | chore | roadmap | new item: event-suggested-edges-pluggable (phase 2 — pluggable suggested-edge logic)
v0.20.4 | 2026-04-09 | fix | animation | isolate filters timeline events to spotlight↔spotlight (frames, play loop, history, slider — not just edges)
v0.20.4 | 2026-04-09 | docs | methodology | rewrote intro: scalability + cross-session knowledge retention is the goal; token efficiency is the means
v0.20.4 | 2026-04-09 | chore | gitignore | docs/METHODOLOGY.md ignored (private dogfood doc)
v0.20.4 | 2026-04-09 | chore | slash-cmd | /add_to_roadmap rewritten cache-first: writes to ROADMAP.ai.md + SESSION.md flush stash, never touches ROADMAP.md mid-session
v0.20.3 | 2026-04-08 | feat | animation | isolate toggle, live protocol filter, none=no edges
v0.20.2 | 2026-04-08 | fix | animation | session_detail 422 — clamp packet_limit in api.js (was 0)
v0.20.1 | 2026-04-08 | fix | edges | canonical session↔edge matching (_session_matches_edge in storage/memory.py)
v0.20.1 | 2026-04-08 | feat | api | new GET /api/edge-sessions endpoint
v0.20.1 | 2026-04-08 | feat | frontend | sessionMatch.js — client mirror of backend matcher
v0.20.1 | 2026-04-08 | refactor | edge-detail | removed sessions/fullSessions props, ScopePill, edgeFilter
v0.20.0 | 2026-04-08 | feat | edges | directional edges (src|dst|protocol IDs)
v0.20.0 | 2026-04-08 | feat | edges | separate src_ports/dst_ports on edges
v0.20.0 | 2026-04-08 | feat | edges | http_fwd_user_agents collected on edges
v0.20.0 | 2026-04-08 | feat | analysis | node↔edge cross-references; AnalysisContext lazy node_map/edge_map
v0.20.0 | 2026-04-08 | feat | adapters | Zeek conn_state → has_handshake derivation
v0.19.0 | 2026-04-07 | feat | alerts | new AlertsPanel page + AlertPluginBase tier
v0.19.0 | 2026-04-07 | feat | alerts | 4 detectors: ARP spoofing, suspicious UA, malicious JA3, port scan
v0.19.0 | 2026-04-07 | feat | api | new GET /api/alerts endpoint
v0.19.0 | 2026-04-07 | feat | nav | Alerts in left panel with red badge (high+medium count)
v0.18.0 | 2026-04-06 | feat | animation | node temporal animation (replay session activity)
v0.18.0 | 2026-04-06 | feat | api | new GET /api/node-animation endpoint + routes/animation.py
v0.18.0 | 2026-04-06 | feat | animation | Phase 2: focused filter, draggable nodes, context menu, bulk hide
v0.17.0 | 2026-04-05 | refactor | parser | unified dpkt reader (eliminated dual scapy/dpkt split)
v0.17.0 | 2026-04-05 | feat | parser | new l5_dispatch.py — L5 enrichment + scapy L5 objects
v0.17.0 | 2026-04-05 | perf | parser | parallel_reader.py — multiprocessing pcap (Win+Linux, max 8 workers)
v0.17.0 | 2026-04-05 | chore | parser | MAX_FILE_SIZE raised to 2 GB
v0.17.0 | 2026-04-05 | feat | parser | filled missing PacketRecord fields (ECN, checksums, ICMPv6, ARP)
v0.17.0 | 2026-04-05 | known-gap | parser | ICMPv6 dissector has no raw fallback (extra={})
v0.16.0 | 2026-04-05 | feat | storage | new backend/storage/ — StorageBackend ABC + MemoryBackend
v0.16.0 | 2026-04-05 | perf | storage | O(1) packet/session/time-bucket lookups (was 3× O(N))
v0.16.0 | 2026-04-05 | feat | api | session_detail packet_limit 1000→50000 + offset param
v0.15.28 | 2026-04-04 | feat | ui | GraphOptionsPanel as proper right-panel view
v0.15.27 | 2026-04-04 | feat | ui | GraphOptionsPanel.jsx slide-in overlay + node/edge color modes
v0.15.27 | 2026-04-04 | feat | export | doExportHTML() — single-file HTML graph viewer
v0.15.26 | 2026-04-04 | feat | research | per-chart filters via build_data() + build_figure() split
v0.15.25 | 2026-04-03 | feat | filter | centralized FilterContext (useFilterContext hook)
v0.15.25 | 2026-04-03 | refactor | filter | applyDisplayFilter() shared, removed duplication
v0.15.20–24 | 2026-04-03 | feat | scope | SCOPED/ALL pill on NodeDetail, EdgeDetail, Research cards
v0.15.17 | 2026-04-02 | feat | research | custom research charts (no-Python builder UI)
v0.15.16 | 2026-04-02 | fix | research | 6 ResearchPage layout/UX fixes
v0.15.15 | 2026-03-30 | feat | research | research panel slot-based DnD canvas redesign
v0.15.14 | 2026-03-30 | feat | session | per-packet header detail (L3/L4 expandable rows)
v0.15.13 | 2026-03-30 | perf | parser | round 2 audit — session_key cache, ARP/TLS dict hoist, TCP flag LUT
v0.15.12 | 2026-03-30 | perf | imports | in-function imports audit complete (aggregator, query, utility)
v0.15.11 | 2026-03-30 | perf | parser | parse perf fix — 6× speedup from hoisting in-function imports
v0.15.10 | 2026-03-30 | fix | sessions | promote session protocol when later packet reveals app-layer
v0.15.10 | 2026-03-30 | fix | graph | charge -350→-200, distanceMax by node count, link tightening
v0.15.9 | 2026-03-30 | fix | useCapture | removed stats from graph fetch dep array (circular refetch)
v0.15.9 | 2026-03-30 | refactor | search | matchEdge() generic field iteration (was hardcoded)
v0.15.8 | 2026-03-29 | refactor | analysis | gR() deduplication in GraphCanvas
v0.15.8 | 2026-03-29 | fix | graph | forceCollide updates on weight mode change
v0.15.7 | 2026-03-29 | feat | graph | "Size by: Bytes/Packets" graph weight selector
v0.15.7 | 2026-03-29 | feat | stats | subgraph focus banner during investigation
v0.15.7 | 2026-03-29 | feat | ui | subnet node visual redesign (rounded rect, dashed)
v0.15.4 | 2026-03-29 | feat | session | Follow TCP Stream — Wireshark-style conversation view
v0.15.4 | 2026-03-29 | feat | query | new pyspark_translator.py (27 tests)
v0.15.4 | 2026-03-29 | feat | query | SchemaReference field reference panel
v0.15.4 | 2026-03-29 | feat | analysis | per-node top_src_ports, top_dst_ports, top_neighbors, top_protocols
v0.15.1 | 2026-03-28 | feat | query | POST /api/query/parse — Cypher/SQL/Spark SQL → JSON contract (47 tests)
v0.15.1 | 2026-03-28 | fix | gantt | capped at 2000 sessions to prevent Plotly freeze
v0.15.1 | 2026-03-28 | docs | arch | two-mode deployment documented (portable vs enterprise)

---

## Older versions
For v0.14.x and earlier, grep `CHANGELOG.md` directly. Compressed log above only covers the active development window since v0.15.0.
