# SwiftEye — Changelog

### v0.30.3 — May 2026
- **Pre-load connected-component selection.** The prescan phase now runs union-find over the IP-pair graph (`_build_ip_components`) and returns up to 100 connected components sorted by size, each with node count, edge count, packet count, and the top-5 IPs. The `LoadOptionsPanel` shows a scrollable component picker between the port filters and the Top-K option — selecting nothing loads all components (default); checking one or more isolates only those. The `component_ids` filter field is resolved server-side to an IP whitelist before packet parsing begins, so no re-parse is required. If both a component selection and an explicit IP whitelist are set, the intersection is used.

### v0.30.2 — May 2026
- **Prefilter estimate readjustment.** The bottom estimate section in `LoadOptionsPanel` was renamed "After filters (estimated)" and now shows three live-updating numbers — Packets, Flows, and IPs — instead of just packets. When components are selected their totals are used as the base; top-K caps flows to exactly `topKValue` and adjusts packets by average flow size; IPs shrink as `sqrt(timeFrac × protoFrac)` since hub nodes appear in many flows. A note appears when the IP or port filter text fields are non-empty to indicate that those dimensions cannot be estimated from prescan data alone.

### v0.30.1 — May 2026
- **pcapng prescan scanner.** `.pcapng` files now go through the full two-phase prescan→load flow instead of bypassing directly to single-threaded parse. `_prescan_pcapng()` does a sequential block-header walk (reading only the 8-byte type+length header per block, seeking over bodies) to collect EPB file offsets and IDB interface metadata (link type, timestamp resolution). `_worker_prescan_pcapng_chunk()` runs in parallel spawned workers, processing EPB blocks in each worker's byte range and extracting src/dst IP and L4 protocol via direct struct reads — no dpkt, no scapy. `prescan_capture()` is the new unified entry point: tries legacy pcap first, falls back to pcapng. `_isPcapFile()` in the upload hook extended to include `.pcapng`.

### v0.30.0 — May 2026
- **Pre-load filters (two-phase prescan→load).** Large pcap files (10 M+ packets) are now manageable: a fast L3-only parallel prescan runs first, returning IP inventory, protocol breakdown, time range, node/edge counts, and a session token. The user then narrows the dataset before any session building or graph construction via `LoadOptionsPanel` — dual time-range sliders, protocol checkboxes with packet counts, IP/CIDR include and exclude fields with top-IP suggestion chips, port/range include and exclude fields, and a Top-K flows toggle. The actual load uses the token and `LoadFilter` (time range applied inside parse workers before `_parse_raw` — ~89% CPU savings for narrow windows; protocol, IP/CIDR, port/range, top-K applied post-parse). Filter includes both whitelists and blacklists for IPs and ports.

### v0.29.7 — May 2026
- **Parallel reader byte-range fix + worker registration guard + gc.collect.** Parse workers now use direct `struct` reads over an explicit byte range rather than `dpkt.pcap.Reader` — the dpkt reader buffers the file on creation, making subsequent seeks ineffective and causing all workers to parse the full file. `server.py` wraps 5 `_dynamic_register` calls in a `MainProcess` guard so spawned workers don't re-register plugins on import. `store.py` calls `gc.collect()` after `store.load()` to release the working set promptly.

### v0.29.6 — May 2026
- **Edge flag bug + query schema coverage.** `buildEdgeMatch` in `useEvents.js` now calls `resolveRef()` before comparing edge endpoints — D3 mutates `source`/`target` from string IDs to live node objects after force simulation, so flagging an edge from `AppRightPanel` was throwing in `subnetOf`. `query_engine.py` gains a `_get_attr` dotted-path resolver and `get_graph_schema` now flattens `plugin_data.{slot}.{field}` entries, making plugin-emitted attributes individually queryable in the Query Builder.

### v0.29.5 — May 2026
- **Parallel worker registration spam fix.** `workspaces/__init__.py` now guards the side-effect workspace imports (`network`, `forensic`) behind a `current_process().name == 'MainProcess'` check. Spawned parse workers import `workspaces` to reach `parallel_reader`, but that import was triggering full workspace registration 8× per parse run. The guard eliminates the flood without affecting main-process startup. LLM test patch strings also corrected (`llm.context_builder.*` → `core.llm.context_builder.*`).

### v0.29.4 — May 2026
- **Graph double-fetch on load fixed.** `useCaptureData.js` had `timeline` in E7's dependency array; `setTimeline` returning a new array reference on each `onBucketSecChange` callback caused E7 to abort its in-flight graph request and send a duplicate. Fix: both E7 and E4+E5 use a `timelineRef` (updated each render, stable reference in the dep array); `resetTimeRange` in `useCaptureFilters` uses functional setState to skip updates when values haven't changed. Graph now fetched exactly once per load.

### v0.29.3 — May 2026
- **Adjacency O(1), query-schema dedup, workspace switch without reload.** Per-frame adjacency lookup in `useGraphSim.js` went from O(nodes×edges) to O(1) by replacing `eRef.current.some(...)` with an `adjNodesRef` Set rebuilt on selection change. `api.js fetchQuerySchema` deduplicates concurrent mount-time fetches with an in-flight promise so only one network request goes out. Workspace switch no longer calls `window.location.reload()`; `WorkspaceProvider.switchWorkspace(name)` POSTs select + resets schema state, and a `<React.Fragment key={active}>` forces a clean subtree remount — switch latency drops from ~2 s to ~200 ms.

### v0.29.2 — April 2026
- **Render memory footprint.** Canvas no longer allocates a new pixel buffer on every D3 tick — a dimension guard skips `c.width`/`c.height` assignment when unchanged; `ctx.scale` (additive) replaced with `ctx.setTransform` (absolute) to prevent cumulative DPR drift. `getComputedStyle(document.body)` moved out of the render loop into a mount-time `MutationObserver` cache. Per-frame `new Map(nodes.map(...))` replaced with a `nodeMapRef` rebuilt only when nodes change. `Math.max(...edges.map(...))` replaced with a for-loop. `LogsPanel` auto-poll defaulted to `false`. Forensic research charts fixed to register only once (were registering twice — once at module level, once via `server.py _dynamic_register`).

### v0.29.1 — April 2026
- **Query schema now workspace-aware.** `GET /api/query/schema` derives its node/edge field groups from the active workspace's `WorkspaceSchema` instead of hardcoded network catalogs. Switching to the forensic workspace now surfaces forensic fields (process, file, registry, endpoint nodes; spawned/connected/wrote/set_value edges) in the Query Builder and Guide panel. Session fields remain network-specific and are supplied by `NetworkWorkspace.query_session_groups()`; forensic returns an empty session schema. This removes a layer violation that had `core/data/query/query_engine.py` importing directly from `workspaces.network.*`.

### v0.29.0 — April 2026
- **Workspaces initiative — forensic workspace alongside network.** SwiftEye now hosts multiple workspaces under a single shell. The network workspace (pcap / Zeek / parquet) is now one workspace among several; a forensic workspace ships with v0.29.0 covering Windows endpoint forensics. Pick the workspace at startup or via the top-bar dropdown; each workspace declares its schema, accepted file types, detail panels, research charts, and graph display modes via a descriptor that the shell consumes generically.
- **Forensic workspace v1.** Reads Windows EVTX (Sysmon EIDs 1/3/11/13: ProcessCreate, NetworkConnect, FileCreate, RegistryValueSet) and Velociraptor offline collector artifacts (Pslist + Netstat as zip or bare CSV). Builds a process-centric graph: process / file / registry / endpoint nodes; spawned / connected / wrote / set_value edges. Schema-driven node detail with command-line copy, parsed hash rows (SHA256/MD5/IMPHASH), and an integrity-level color badge. EdgeDetail surfaces the underlying event stream; ForensicEventDetail opens any event with sibling-event navigation. Three research charts (process gantt, registry timeline, network timeline) and three classifier plugins (LOLbin, binary type, registry key category) ship in the box. Animation mode replays event ordering with a recency window.
- **Architecture cleanup that came with the workspaces work.** Engine code moved to `backend/core/` and `frontend/src/core/`; network code moved to `backend/workspaces/network/` and `frontend/src/workspaces/network/`; forensic added at `backend/workspaces/forensic/` and `frontend/src/workspaces/forensic/`. Schema is the single source of truth for field names — `WorkspaceSchema` declares `Field` / `NodeType` / `EdgeType` (with `searchable_fields`) and the shell evaluates whatever the active workspace declares. Annotation primitives consolidated: `core/graphPrimitives.js` owns shape drawing (replaces 4 separate inline drawing systems), `core/annotationStore.js` owns per-frame annotation snapshots (hulls, badges, rings, color overrides). Adopting these primitives in both workspaces means recipe verbs (tag/color/cluster) write the same canvas annotations regardless of which workspace produced the graph.
- **Network workspace preserved end-to-end.** Edge-direction arrows, query pipeline (Recipe / Groups / Guide), graph layouts (Force / Circular / Radial / Hierarchical), legend-as-filter, ClusterDetail bridges, force-simulation sliders, parquet adapter, and session-equality fix all keep their v0.28.33 behavior. The merge resolution preserved network rendering byte-for-byte.

### v0.28.33 — April 2026
- **Parquet upload via picker** — `AppUploadScreen`'s `<input accept>` list now includes `.parquet` so the file picker shows Parquet files alongside pcap/pcapng/cap/log/csv. Drag-drop already accepted them via the parquet adapter.

### v0.28.32 — April 2026
- **Parquet adapter** — `ParquetAdapter` (pyarrow-backed) reads `.parquet` files using the Zeek `conn.log` column shape as the declared baseline. Schema negotiation runs through `get_header_columns()` + `parse_with_mapping()` like the other tabular adapters. Datetime timestamp columns coerce to float epoch automatically. Falls back gracefully if pyarrow isn't installed (server starts; only `.parquet` ingestion is unavailable). 14 new tests, 330 passing.

### v0.28.31 — April 2026
- **Session src/dst now reflects true connection direction** — `src_ip`/`src_port`/`dst_ip`/`dst_port` on session objects now point to the real initiator and responder, not to lexicographically-sorted endpoints. Previously, ports were sorted by numeric value so port 443 would appear as `src_port` on an HTTPS session (lower number), making `col("dst_port") == 443` always return zero matches. The session key used for grouping is unchanged; only the exposed fields are corrected.

### v0.28.30 — April 2026
- **Query panel cleanup** — removed the "Fields ▾" collapsible from the freehand query area. The Guide tab covers field discovery; the duplicate panel was dead weight.

### v0.28.29 — April 2026
- **Freehand session string queries fixed** — `col("field") == "value"` in PySpark freehand mode now correctly matches string fields (protocol, service, IP addresses, etc.). Previously, the translator emitted op `"="` for all equality, which routed to the numeric evaluator; `float("HTTPS")` raised `ValueError` → every string comparison silently returned zero matches. The fix emits op `"equals"` when the right-hand side is a string literal, matching how the Cypher/SQL parser already handled this case.

### v0.28.27 — April 2026
- **Sessions as a query target (Plan 2 complete)** — `target: sessions` is now a first-class query primitive. Visual mode: select "All sessions" in the target picker, filter by any session field (protocol, dst_port, total_bytes, duration, tls_cert, http_uris, etc.), and get blue session result cards showing the 5-tuple, protocol, duration, and bytes. Clicking a card highlights the source node and edge on the graph. Freehand PySpark: `sessions.filter(col("dst_port") == 443)` parses and runs end-to-end. Guide tab "coming soon" banner removed. Pipeline fully supports sessions steps (highlight emits node+edge IDs; group verbs accept sessions target). Examples dropdown now floats over the recipe panel via `position: fixed`. Query+recipe panel scrolls as one unit. 7 new tests; 315 passing.

### v0.28.23 — April 2026
- **Guide tab badge fixes** — the Guide tab now correctly renders "Num" badges for `number`-typed fields (previously showed the raw string "number") and a "List" badge for list fields. Cards are collapsed by default.

### v0.28.22 — April 2026
- **Protocol catalog completeness** — every `protocol_fields/` module now declares a `catalog()` function. The 11 previously-missing modules (arp, ftp, icmp, kerberos, ldap, llmnr, mdns, quic, smtp, ssdp, ssh) each define typed, described entries for all fields they emit. `SESSION_CORE_CATALOG` added to `sessions.py` (20 core fields: id, src/dst ip/port, protocol, transport, packet_count, total_bytes, payload_bytes, start/end time, duration, fwd/rev counts, initiator_ip, responder_ip, ip_version). The query engine now prepends the core catalog as a "core" group in `session_groups` so the Guide tab shows base session fields before protocol-specific ones.

### v0.28.21 — April 2026
- **Dynamic query schema + Guide tab** — `/api/query/schema` now derives node fields from `NODE_FIELD_CATALOG`, edge fields from `EDGE_CORE_FIELD_CATALOG` plus the full `EDGE_FIELD_REGISTRY`, and session fields from each protocol_fields module's `catalog()` call. `build_analysis_graph()` edges now use `init_detail_sets()` + `accumulate_from_extra()` (was 4 hardcoded fields). The Schema tab is replaced by a Guide tab (rightmost, in the Query | Groups | Guide tab row): collapsible cards per group (Nodes / Edges / Sessions), each field showing its type badge and description. Guide re-fetches its schema on every capture load.

### v0.28.20 — April 2026
- **Scoped/All wiring fixed** — the "All" mode toggle in the recipe panel now actually works. Global-scope `hide` steps use the full match set (not just currently-visible nodes), and global-scope `show_only` replaces the entire visibility state — meaning it can restore nodes that were hidden by prior steps. Previously, both verbs silently fell back to viz-scope behaviour when the whole recipe was in "All" mode.

### v0.28.18 — April 2026
- **ClusterDetail bridge nodes** — the Bridges section in ClusterDetail now shows member IPs that have external connections (not cluster-to-cluster edges). Each bridge-node row is expandable to list its outside peers, with clickable navigation. Replaces the old flat bridge-edge list.
- **Cluster edge sessions fix** — clicking a cluster↔cluster edge no longer shows "No sessions found." The session-match path now accepts `src_members` / `dst_members` (comma-separated IP sets) so the backend can match sessions against real member IPs instead of the synthetic `cluster:0` label. Threaded from `session_match.py` → `memory.py` → `routes/data.py` → `api.js` → `EdgeDetail.jsx`.
- **Legend overlap fixed** — ClusterLegend and GraphLegend are now wrapped in a single `position: absolute` flex-column container in `App.jsx`; individual absolute positioning removed from both components.
- **Context menu submenus** — node right-click menu reorganised into hover-expand submenus: Investigate (neighbours / isolate / paths / animate), Layout (radial focus / hierarchy root), Annotate, Edit (hide / draw edge / expand / uncluster / delete). Flyout auto-flips left when near the right edge of the viewport.
- **Dynamic edge legend** — `GraphLegend` now builds edge protocol items from the loaded graph's protocol→color map instead of hardcoded TCP/TLS/DNS/HTTP entries.
- **Legend eye pipeline fix** — toggling a legend eye toggle now auto-switches to the Query panel so RecipePanel is mounted and the pipeline fires immediately.

### v0.28.7 — April 2026
- **Force simulation sliders** — new section in GraphOptionsPanel (Force layout mode only): Charge strength, Link distance, Alpha decay, and Velocity decay sliders with 500 ms debounce. A Reheat button restarts the simulation at full energy; a Freeze toggle stops it. Defaults tuned to chargeStrength −300, linkDistance 160.

### v0.28.6 — April 2026
- **Hierarchical layout (dagre)** — new layout mode using the dagre library for directed top-down tree layouts. Set any node as the hierarchy root via right-click → "Set as hierarchy root"; when no root is set, the highest-in-degree node is chosen automatically. Positions are scaled and centered to fit the canvas. Falls back to force layout if dagre fails. Orange hint in GraphOptionsPanel when no root is set; muted hint showing root ID when one is active.

### v0.28.5 — April 2026
- **Radial layout** — new layout mode that arranges nodes in concentric rings by hop count from a focus node (BFS). Set any node as the radial focus via right-click → "Set as radial focus"; when no focus is set, the highest-degree node is chosen automatically. Disconnected nodes land in the outermost ring. Purple hint in GraphOptionsPanel when no focus is set; muted hint showing focus node ID when one is active.

### v0.28.4 — April 2026
- **Graph layout switcher + Circular mode** — new "Layout" section at the top of GraphOptionsPanel with Force / Circular / Radial / Hierarchical toggle buttons. Circular mode places nodes on one ring (≤20 nodes) or two concentric rings (21–60 nodes), sorted by degree; for >60 nodes it falls back to force layout. The layout registry (`layouts/index.js`) auto-discovers layout modules. `forceLayout.js` exports `LAYOUT_ID / LABEL / WORKSPACE / REQUIRES_FOCUS` and accepts `options.forceParams` for future slider support.

### v0.28.3 — April 2026
- **Legend-as-filter** — graph legend swatches are now interactive. Each swatch gets an eye toggle (👁 / 🚫); toggling one emits a `hide` step into the active recipe (viz scope, auto-named e.g. "Legend: hide external") and dims the swatch to 0.4 opacity. Toggling it back removes that step. `handleRecipeChange` syncs the hidden-label state if the user manually deletes a legend step from the recipe, keeping legend and recipe in sync. `GraphLegend.jsx` rewritten to be mode-aware (`nodeColorMode` / `edgeColorMode` driven) and now replaces the hardcoded inline legend that was embedded in `App.jsx`.
- **Louvain bridge-node expansion** — the Connections section in `ClusterDetail.jsx` now shows the specific node pairs whose edges cross each cluster boundary. Each cluster→cluster connection row gains a ▶ expand caret; expanding it reveals the raw member-pair crossings (from → to, clickable to navigate) sourced from `rawGraph.edges` via a `bridgesByEdgeId` useMemo. Bridge details are visible without forcing a full cluster expansion.

### v0.28.2 — April 2026
- **Hidden-edges wiring** — `hide` pipeline steps now conceal both nodes and edges; `handleUnhideAll` clears both. The hidden-state banner in the graph header shows combined counts ("2 nodes, 3 edges hidden").
- **Scoped / All mode switch** — new pill toggle in the Recipe panel header. "Scoped" (default) runs each step only against currently-visible nodes/edges. "All" opts the whole recipe into global scope, letting steps reach nodes that earlier steps hid.

### v0.28.1 — April 2026
- **Recipe/QueryBuilder layout fix** — QueryBuilder no longer expands to fill all available height, giving RecipePanel the flex space it needs below it.
- **Color override radial gradient** — color-verb overrides now render as a radial gradient (darker centre → lighter edge) instead of a flat 20 %-opacity fill, making colored nodes visually distinct from default nodes and clearly visible on both light and dark backgrounds.
- **Edge color verb** — the `color` pipeline verb now works on edges as well as nodes; `annotationStore.toRenderSnapshot` emits `edgeColorOverrides`; the edge render loop applies stroke-style and line-width overrides.
- **PySpark placeholder corrected** — freehand editor PySpark placeholder text changed from `df.filter` to `nodes.filter` in QueryBuilder, StepEditor, and queryExamples.

### v0.28.0 — April 2026
- **Annotation primitives (Phases 1–4)** — unified annotation layer replacing four separate inline ref systems. New `frontend/src/core/graphPrimitives.js`: canonical canvas draw functions — `drawShapePath` (single authoritative node shape function replacing scattered `if/else` branches), `computeConvexHull` (d3.polygonHull + centroid expansion + smooth quadratic Bézier with circle/capsule fallbacks for 1/2/collinear points), `drawHulls`, `drawRings`, `drawBadges`, `applyColorOverride`. New `frontend/src/core/annotationStore.js`: `AnnotationStore` with full CRUD + four lifetimes (`transient` / `persistent` / `computed` / `flash`), `toRenderSnapshot()` pre-bakes render data with zero per-frame allocation, `toLayoutHints()` feeds hull cohesion forces. New `frontend/src/core/layouts/forceLayout.js`: `buildForceSimulation` extracted from `useGraphSim` — the layout seam for the upcoming graph-layouts initiative. Render loop refactored into two passes for correct z-ordering (0 Grid → 1 Hulls → 2 Edges → 3 Nodes → 4 Rings → 5 Labels → 6 Badges). Pipeline's `RecipePanel` now writes directly to the annotation store instead of calling per-type callbacks; `AppRightPanel` drops the four annotation-setter props.

### v0.27.16 — April 2026
- **Pipeline verbs wired to graph canvas** — `show_only` and `hide` steps now drive `hiddenNodes` state (nodes disappear from the graph). `color` steps apply per-node color overrides in the render loop (custom stroke/fill). `tag` steps draw a `#tagname` purple badge below matching nodes (zoom-guarded, arc-based rounded rect). All overrides are cleared automatically when the recipe has no runnable steps.

### v0.27.15 — April 2026
- **Sub-tab unmount fix** — switching between Query / Schema / Groups sub-tabs no longer unmounts non-active panels. Previously this caused the Groups tab to appear empty (debounced pipeline run was cancelled before `group_store` received the snapshot) and the QueryBuilder form to reset on return.
- **Recipe / Output drag splitter** — a 6 px drag handle between the Recipe section and the Output section lets you resize both regions. Height is clamped to [120, 900 px] and persisted to `localStorage` so it survives reloads.
- **@group scoped steps** — pipeline steps can now target a named group (`@tagname`, `@colorname`, etc.) via the visual-editor TargetPicker. The new `from_group: {kind, name}` step field scopes the step's candidate set to the group's members. Zero-condition steps with a `from_group` are valid — they match all members directly. 7 new backend tests, 306 total passing.

### v0.27.14 — April 2026
- **Step verb editable after creation** — recipe steps previously locked in their verb at creation time. The new `VerbHeader` row at the top of every open StepEditor lets you switch verb, change group name, and pick a color at any time. Switching to a group-requiring verb auto-seeds a name if the field is empty; switching away preserves any custom name the user entered.
- **Groups sub-tab** — third sub-tab in the Query panel (alongside Query and Schema). Shows every tag, color, cluster, and saved set produced by the pipeline, each with the recipe slice that created it, a member list (click any member to navigate to it on the graph), and a delete button. Groups refresh automatically after each pipeline run. 18 new backend tests (`GroupStore` CRUD, suffix behaviour, pipeline wiring), 299 total passing.

### v0.27.13 — April 2026
- **Schema moved under Query** — the Schema view is now the second sub-tab inside the Query panel instead of a standalone left-nav tab. This keeps field reference and query building in the same place.

### v0.27.12 — April 2026
- **Schema tab** — new `SchemaPanel` shows all queryable node and edge fields grouped by type (Numeric / Sets / Flags / Text) with colour-coded chips and counts. Data comes from the existing `/api/query/schema` endpoint.

### v0.27.11 — April 2026
- **Recipe persistence dropped** — recipe state no longer persists to `localStorage`. A fresh browser load or server restart starts with an empty recipe (the previous session's recipe was rarely useful on reload and blocked clean state when switching captures).
- **Recipe scroll container** — the recipe step list now has a `max-height: 40 vh` scroll container so long recipes don't push the Output metrics offscreen.

### v0.27.10 — April 2026
- **Query pipeline — end-to-end recipe UX** — the Query tab now has a full pipeline system. Build a "recipe" — an ordered list of steps that run automatically (300 ms debounce) as you edit. Each step can be Visual (point-and-click field/op/value) or Freehand (Cypher, SQL, or PySpark). Steps are reorderable via drag handle; individual steps can be enabled/disabled. Output section shows live counts: Visible nodes/edges, Hidden, Highlighted, Tags, Coloured, Clusters, Saved sets. Uses dnd-kit for drag-and-drop.

### v0.27.9 — April 2026
- **Query pipeline — Phase B backend: seven verbs + pipeline executor + named sets** — `resolve_query` now validates seven verbs: `highlight`, `show_only`, `hide`, `tag`, `color`, `cluster`, `save_as_set`. New `in_set` op for `IN @name` syntax in Cypher and SQL. New `backend/data/query/pipeline.py` top-to-bottom executor with per-step provenance (matches, removed, skipped, effective_matches) and current-visibility tracking. New `NamedSetStore` (per-capture, non-persistent). New routes: `POST /api/query/pipeline`, `GET/PUT/DELETE /api/query/sets`. 42 new tests, 281 total passing.

### v0.27.8 — April 2026
- **Query pipeline — Phase A backend: translator refactor + new ops** — PySpark translator rewritten around `METHOD_MAP` (adding an op = one row). New `like` op (SQL `%`/`_` wildcard semantics, case-sensitive by default). New `negate` and `case_insensitive` modifiers; Cypher `NOT` and SQL `NOT LIKE` unified on `negate`. `ends_with` silent-zero-match bug fixed (op was missing from the engine's `STRING_OPS` set). 19 new tests.

### v0.27.7 — April 2026
- **Docs audit** — DEVELOPERS.md §9 API table expanded to 57 routes; `analysis/` → `data/` path references corrected throughout; HANDOFF.md §2 directory tree and API table updated; README Features expanded (alerts, LLM panel, animation, query translation).

### v0.27.6 — April 2026
- **Graph direction visualization** — new "Show direction" toggle in Graph Options → Edge tab (default off). When on, a filled arrowhead is drawn at the 70% mark along each edge pointing initiator → responder. Fixed screen-space size (8×10 px) regardless of edge weight or zoom. For bidirectional traffic the two arrows land at different positions (70% and 30% from A), keeping both directions readable without overlap.
- **Legend data extraction** — `NODE_LEGENDS` / `EDGE_LEGENDS` extracted to a shared `graphLegendData.js` module; the Graph Options sidebar legend already synced with the active color mode and continues to do so.
- **Export HTML enriched hover** — node tooltips now show session count and top 3 protocols by volume. Edges are now hoverable (point-to-segment hit detection, 6 px screen tolerance): tooltip shows session count and full protocol list. Hovered edges highlight in white.
- **Export HTML node dragging** — exported graphs are now fully interactive: individual nodes can be dragged and connected edges follow in real time. Empty-space drag still pans the view; cursor changes to reflect state.

### v0.27.5 — April 2026
- **Investigation timeline nodes render immediately** — dragging a node into the investigation timeline now shows it at the drop position immediately, without requiring a zoom or pan event to trigger a re-render.
- **Timeline node/edge editing** — investigation timeline nodes and edges are now fully editable: label, color (via swatch picker), annotation text, and node severity can all be changed inline.
- **Edge hover tooltips** — hovering a graph edge now shows a tooltip with key connection details.
- **Session flag button icon-only** — the flag button in the session detail header is now icon-only, consistent with node and edge detail panels.
- **EventFlagModal source/target fix** — the flag modal was incorrectly storing d3-mutated source/target objects instead of IDs. Fixed by resolving `source.id` / `target.id` before saving.
- **Session title format** — session detail title bar now shows `{ip}--proto→{ip}` (e.g. `10.0.0.1--TCP→10.0.0.2`) for clearer at-a-glance identification.
- **Timeline panel moved to Research** — the standalone Timeline left-nav panel has been removed. The session Gantt chart is now a first-class chart in the Research panel.

### v0.27.4 — April 2026
- **CONTRACTS.md** — added comprehensive extension contract reference covering all 12 SwiftEye extension points: adapters, protocol fields, edge fields, plugins, detectors, analyses, research charts, LLM providers, query contract, wire types, session sections, and source capabilities. Intended as the definitive reference for anyone building extensions.

### v0.27.3 — April 2026
- **Sticky header fix (SessionDetail)** — the connection header, tags, and tabs now stay anchored while the session body scrolls. Root cause was a broken height chain: the right-panel wrapper used `flex: 1` (flex-layout sizing) which isn't inherited by `height: 100%` descendants. Fixed by making the entire chain explicit flexbox — wrapper is now `display: flex; flex-direction: column` and SessionDetail uses `flex: 1; min-height: 0` instead of `height: 100%`.
- **LLM settings moved into the Analysis panel** — provider, base URL, model name, and API key are now configured directly inside the LLM Interpretation panel (click the ⚙ button in the panel header). Removed from the global Settings panel. The LLM panel manages its own settings via `useSettings` internally; `onOpenSettings` prop removed from `LLMInterpretationPanel` and `AnalysisPage`.
- **Build fix** — v0.27.2 code was committed after the dist was built, so users running the pre-built app saw none of v0.27.2's changes. This release includes a fresh build with all v0.27.2 and v0.27.3 changes applied.

### v0.27.2 — April 2026
- **Logo home button** — clicking the logo now correctly navigates home from any panel (Research, Analysis, Animation, etc.) by calling `switchPanel('stats')` instead of `clearAll()`. `clearAll` only reset the selection state and search; it did not reset `rPanel`, so switching from full-width panels like Research left the user stranded.
- **Graceful optional dependency handling** — `plotly` and `sqlglot` import failures in `backend/research/__init__.py` and `backend/research/custom_chart.py` now degrade gracefully at startup. A `try/except` block at module level sets `_PLOTLY_AVAILABLE = False` and logs a warning; research charts are disabled at runtime (raising a `RuntimeError` with a clear `pip install` message) rather than aborting server startup.
- **D3 force simulation tuning** — reduced charge strength (`-280 → -180`), link distance (`160 → 130`), and `alphaDecay` raised (`0.02 → 0.025`) in `useGraphSim.js`. The graph settles faster after dragging a node and nodes are less aggressively repelled on initial layout, giving a tighter, more readable graph for mid-sized captures.
- **Animation frame cursor on timeline strip** — when animation is running, an orange tick mark on the `TimelineStrip` tracks the current frame's capture-relative timestamp. The cursor accounts for the gap-split layout (fixed-pixel gap segments + proportional time segments).
- **Animation back-button breadcrumb** — while animation is active and a session/edge/node detail is open in the right panel, a "← Back to animation" link appears at the top of the right panel. Clicking it clears the selection and returns focus to the animation canvas.
- **Animation node position persistence** — dragged node positions now survive full-width panel switches (Research, Analysis, Timeline, etc.) which cause `AnimationPane` to unmount. Positions are lifted to a `useRef` in `App.jsx` (`animSavedPositionsRef`), passed into both `useAnimationCanvas` (merged on remount) and `useAnimationInteraction` (written on drag).
- **EdgeDetail port pairs** — source and destination ports are now displayed as a single paired row (`src_port → dst_port`) instead of two separate rows. Ports are colour-coded: source in green, destination in default text colour.
- **SessionDetail sticky header** — (introduced here, fixed in v0.27.3 — the CSS approach in v0.27.2 was correct but the build was stale).

### v0.27.1 — April 2026
- **Server-side LLM key storage** — provider configuration (including API keys) is now stored in `backend/llm_keys.json` on the server, not in browser localStorage. New `GET/POST /api/llm/keys` endpoints persist the config. The frontend loads from the server on startup and saves on every change (500 ms debounce). The chat handler silently injects the stored key if a request arrives with an empty `api_key` field. The Settings panel footer and privacy note reflect the new storage location.
- **LLM architecture documentation** — `docs/DEVELOPERS.md §17` covers the full `backend/llm/` package: module-by-module reference table, question tags (all 12 + how to add a new one), providers (Ollama, OpenAI-compatible + how to add a new adapter), NDJSON streaming wire format with event sequence, complete request body schema, and `curl` test examples for the context-preview and chat endpoints.
- **Flat left-panel switcher** — the "Data / Analysis / Workspace / Settings" category headers in the left sidebar have been removed. Panel items are now a flat list, which reduces visual noise and makes the sidebar more compact.

### v0.27.0 — April 2026
- **Version bump to 0.27.** Marks the start of the server-side API key store, LLM developer documentation, and left-panel cleanup work planned for the next session.

### v0.26.9 — April 2026
- **Node role visible to LLM** — `translate_node()` now includes `os_guess` and `network_role` (gateway / lan / external) in the context packet. The LLM can now reason about routers and gateways that the graph renders as diamonds, not just endpoint nodes.
- **Starter prompt chips** — the LLM panel empty state now shows a row of 4 context-aware question chips ("What protocols are in this capture?", "Who are the top talkers?", "Are there any alerts?", "What DNS queries were made?" — different set for selected-entity scope). Clicking a chip sends with `is_simple_question: true`, which suppresses the `## Next Steps` section for cleaner one-shot answers.
- **`is_simple_question` flag** — new `ChatOptions.is_simple_question: bool` field. When true, the backend uses `_OUTPUT_FORMAT_SIMPLE` (no Next Steps section) instead of the standard format.

### v0.26.8 — April 2026
- **LLM question tagger fixes** — self-referential questions ("what is my IP?", "what is my computer doing?") now correctly set `has_capture_ref=True`, preventing mis-tagging as pure background. New `_CAPTURE_CONTEXT_MARKERS` covers open-ended capture-state questions ("what's going on?", "what's happening?"). The step-6 proto-only gate now also applies to mixed tags so "what is DNS tunneling?" resolves to `mixed` not just `dns`.
- **Small-model compact mode** — `is_small_model()` detects sub-8B models by regex. When detected, `_COMPACT_MODE_OVERRIDE` is injected into the system prompt: no preamble, answers ≤ 300 words. Helps models like `qwen2.5:3b` avoid verbose padding.
- **Model name propagation** — `service.py` now passes `request.provider.model` into `build_system_prompt()` so compact mode activates automatically based on the configured model.

### v0.26.7 — April 2026
- **LLM Interpretation Panel (Phase 1)** — Analysis tab now has a live Q&A panel. Load a capture, ask a question in plain English, get a streamed markdown answer grounded in the actual capture data — not a hallucinated summary. Three scope modes: **Full capture** (broad overview), **Current view** (respects active time/protocol/search filters), **Selected entity** (select a node, edge, or session first, then ask about it).
- **Scope-aware context building** — the backend resolves scope, classifies the question into one of 12 deterministic tags (entity_node, entity_edge, http, tls, dns, alert_evidence, attribution_risk, broad_overview, etc.), then builds a targeted context packet from existing structured evidence (node records, edge fields, session metadata, alerts, analysis plugin results). No inference engine — what the parser captured is what the LLM sees.
- **Streaming NDJSON protocol** — `POST /api/llm/chat` streams newline-delimited JSON events: `meta` → `context` → `delta*` → `final` (or `error`). Frontend renders incrementally with a lightweight inline markdown renderer (no external deps).
- **Ollama + OpenAI-compatible providers** — configure in Settings → LLM Provider. Ollama: set model (e.g. `qwen2.5:14b-instruct`), leave base URL blank for localhost. OpenAI-compatible: enter base URL + API key. Provider config is per-request; no server-side key storage.
- **Uncertainty-first policy** — attribution-style questions ("where is the attacker?", "is this malware?") trigger strengthened uncertainty instructions. The panel will not make confident attacker-identity claims from packet data alone.
- **"Explain this" quick action** — one-click button adapts to context: "Explain selected [node/edge/session]" when an entity is selected, "Explain current view" otherwise.
- **Debug seam** — `POST /api/llm/context-preview` returns the built context packet without calling a provider. Useful for prompt iteration and verifying retrieved evidence.
- **4 new backend test files** — `test_llm_question_tags.py`, `test_llm_context_builder.py`, `test_llm_translators.py`, `test_llm_route.py`. All pass.
- **Bug fix** — `context_builder.py` imported `get_analysis_results` from `services.capture` (wrong module); corrected to `plugins.analyses` and hoisted to module level.

### v0.26.6 — April 2026
- **Edge field registry (`edge_fields.py`)** — new `backend/data/edge_fields.py` is the single source of truth for all `pkt.extra` fields that get accumulated onto graph edges (TLS SNIs, HTTP hosts, DNS queries, JA3/JA4 hashes, ciphers, user agents). The 9-field hardcoded accumulation block in `aggregator.py` is replaced by a loop over the registry. Adding a new edge-accumulated field now requires editing only `edge_fields.py`.
- **Lazy edge detail loading** — the `/api/graph` response no longer includes TLS/HTTP/DNS field values on edges; instead each edge carries boolean hints `has_tls`, `has_http`, `has_dns`. Full values are fetched on demand via `GET /api/edge/{id}/detail` (accepts the same filter params as `/api/graph`). `EdgeDetail.jsx` fetches detail when an edge is clicked and shows a loading indicator while in flight. This reduces the graph payload for large captures where most edges are never inspected.
- **Dynamic search keyword hints** — `GET /api/meta/edge-fields` exposes the edge field registry to the frontend. `useCaptureData.js` loads hint keywords on mount and builds `edgeFieldHints` dynamically, replacing the hardcoded `_PROTO_HINTS` array. Boolean-flag matching (`has_tls`, `has_http`, `has_dns`) replaces the old array-length checks.
- **Pre-indexed search** — node and session search indices are now built as `useMemo` computations when graph/session data loads (once per data change), rather than on every keystroke. Fast-reject via `String.indexOf` on the pre-built index before scanning individual fields eliminates per-keystroke O(n) for non-matching entities.
- **React.lazy code splitting** — `AnalysisPage`, `ResearchPage`, and `AnimationPane` are now loaded via `React.lazy` + `Suspense`. Three separate JS chunks (~22 kB / 32 kB / 38 kB gzip) are only downloaded when the user first activates the relevant panel.
- **Tests** — `test_http_user_agents_on_edges` updated to verify the new edge shape: `has_http: True` on the summary, `http_fwd_user_agents` on the detail endpoint result. 57/57 core + 33/33 discovery smoke tests passing.

### v0.26.5 — April 2026
- **Session list virtualized (react-window)** — `SessionsTable.jsx` now uses `FixedSizeList` from `react-window` v1. A `ResizeObserver` hook tracks the flex container height so the virtual list fills the available space exactly. Only the ~10 visible rows are in the DOM at once instead of up to 1,000. Packet table in `SessionDetail` skipped (expandable rows make variable-height virtualization fragile; the existing `maxHeight: 500` cap already bounds DOM nodes there).
- **localStorage key registry (`storageKeys.js`)** — all `localStorage` key strings are now declared in a single `frontend/src/storageKeys.js` module (`SETTINGS`, `CUSTOM_CHARTS`, `SCOPE_NODE`, `SCOPE_EDGE`, `SCOPE_SLOT_PREFIX`, `scopeSlot(id)` helper). Five files updated to import from this registry: `useSettings.js`, `customChartPersistence.js`, `NodeDetail.jsx`, `useCaptureLoad.js`, `PlacedCard.jsx`. Eliminates scattered literal strings and makes key renames a one-file change.
- **Component reorg target mapping** — wrote the complete file → destination table (50 files) into `docs/plans/active/audit-14-directory-refactor.md` Phase 3 output. Covers nine target subdirectories: `graph/`, `timeline/`, `events/`, `detail/`, `investigation/`, `research/`, `animation/`, `alerts/`, `layout/`, `shared/`. Execution (Phase 4) remains blocked on audit-02 Phase 3 splits.
- **Centrality backend plan** — documented the 7-file plan for moving client-side Brandes centrality to `GET /api/analysis/centrality` in `docs/plans/active/centrality-backend.md`. Updated `centrality-backend-migration` roadmap item: status pending (no longer blocked on graph-db-backend). Task deferred.
- **Audit-06 P3–P5 added to QA checklist** — interaction hints for undiscoverable gestures, filter-system labeling, and keyboard panel switching moved to the `qa-test-suite` roadmap item alongside the 10 human QA scenarios from `audits/codex_audits/2026-04-09/13_human_ui_qa_checklist.md`.

### v0.26.4 — April 2026
- **Left panel navigation grouping** — the 12-item flat panel list in `LeftPanel.jsx` is now organized into four labeled sections: **Data** (Overview, Sessions, Timeline), **Analysis** (Query, Research, Analysis, Alerts), **Workspace** (Investigation, Visualize), **Settings** (Graph Options, Server Logs, Help). Section headers are small, dim, non-clickable labels. No collapsing — all items remain visible.
- **Project-wide minimum font size floor** — audited all font sizes across the frontend and raised any `fontSize: 7` or `fontSize: 8` occurrences to a minimum of 9px. Interactive controls (All/None protocol buttons) lifted to 10px. Affected ~20 component files including `LeftPanel.jsx`, `SessionDetail.jsx`, `NodeDetail.jsx`, `AnalysisPage.jsx`, and several `session_sections/` components. The BETA badge in `LeftPanel` raised from 7px to 9px.

### v0.26.3 — April 2026
- **Audit-05 Phase 3: discovery smoke tests** — added `backend/tests/test_discovery_smoke.py` with 33 tests covering auto-discovery of all backend extension points: `protocol_fields` modules, parser adapters, research chart classes, alert detector classes, insight plugin classes, analysis plugin classes, and `session_sections/` frontend components. All 33 pass. Ensures new files dropped into the right directory are picked up automatically.
- **`requirements.txt` fix** — `plotly` promoted from optional to required (research charts need it at startup); `sqlglot` and `pytest` added as required dependencies.
- **Audit-04 Phase 1: state lifetime documentation** — added §16 "State Lifetime & Storage Tiers" to `docs/DEVELOPERS.md`. Table covers all six storage tiers (in-memory parse output, server session state, frontend React state, localStorage, sessionStorage, IndexedDB) with their lifetime, scope, and eviction rules. Added `graceful-optional-deps` roadmap item.

### v0.26.2 — April 2026
- **Audit-05 Phase 2: Philosophy exceptions documented** — added a "Philosophy Exceptions" section to `ARCHITECTURE.ai.md` documenting four intentional trade-offs that violate the stated architecture principles but are kept deliberately: (1) edge display caps (view-layer constants, not data truncation), (2) client-side centrality (filter-aware by design — HTTP vs Kerberos graphs differ), (3) localStorage chart config persistence (user convenience, no server state), (4) frontend search hint hardcoding (performance trade-off, avoids O(n) per render). Each exception includes a "when to revisit" condition.

### v0.26.1 — April 2026
- **Audit-03 Phase 2: fetch batching** — merged the independent `E4` (sessions) and `E5` (stats) effects in `useCaptureData.js` into a single `Promise.all` effect. Both fetches now fire together on time-range change and apply their results in one `setState` batch, reducing re-render cycles from two to one. `E7` (graph) kept separate because it has a wider dependency set (protocol/subnet filters) that differs from the time-range-only deps shared by sessions and stats.

### v0.26.0 — April 2026
- **Audit-14 Phase 1: `tests/` renamed to `captures/`** — the root-level `tests/` directory contained pcap files and capture datasets, not test code (`backend/tests/` has the actual tests). Renamed to `captures/` for clarity. Updated path references in `backend/tests/test_core.py` and `backend/tests/test_dpkt_parity.py`.
- **Audit-14 Phase 2: `.gitignore` policy rewrite** — reorganized `.gitignore` from a flat reactive list into labeled sections: Python, Node/Frontend, local project state (`SESSION.md`, `CLAUDE.md`, `*.ai.md`), private docs, captures, audits, IDE, runtime/logs, and legacy files. Added `CLAUDE.md`, `docs/METHODOLOGY.md`, and `memory.zip` to the ignore list. Same effective rules, better organization.

### v0.25.4 — April 2026
- **SessionDetail + App decomposition** — `SessionDetail.jsx` (948 → 660 lines) split into three focused modules: `SeqAckChart.jsx` (98 lines — sequence/ACK chart with its axis helpers), `StreamView.jsx` (149 lines — stream payload display with decode/copy/expand logic), and `useSessionPackets.js` (40 lines — hook that fetches and paginates per-session packet data). `App.jsx` (941 → 680 lines) split into `AppUploadScreen.jsx` (103 lines — upload dropzone, parse-progress spinner, and standalone-visualize early-return paths) and `AppRightPanel.jsx` (196 lines — right-panel content assembly: sessions, detail, animation, research, events, logs, alerts, help, settings). Coordinators retain only orchestration logic. Pure refactor — identical behavior, Phase 3 items #5 and #6 complete. All six audit-02 Phase 3 frontend splits are now done.

### v0.25.3 — April 2026
- **AnimationPane decomposition** — the 1334-line `AnimationPane.jsx` monolith split into five focused modules: `animationUtils.js` (131 lines — shared constants and pure geometry/hit-test helpers), `useAnimationCanvas.js` (357 lines — zoom setup, fit-to-view, flash-packet tracking, and the main RAF render loop), `useAnimationInteraction.js` (259 lines — click/hover hit-testing, node drag, keyboard shortcuts, and popover dismiss), `AnimationHistoryPanel.jsx` (96 lines — history sidebar with auto-scroll), `AnimationControlsBar.jsx` (265 lines — transport controls, scrubber, options popover, and the `CtrlBtn`/`OptRow`/`OptPill` sub-components). Coordinator `AnimationPane.jsx` reduced to 460 lines. Pure refactor — identical props API, no behavior change. Phase 3 item #4 complete.

### v0.25.2 — April 2026
- **ResearchPage decomposition** — the 1443-line `ResearchPage.jsx` monolith has been split into four focused modules plus a ~384-line coordinator, completing Phase 3 item #3 from the audit-02 frontend readability plan. New files in `frontend/src/components/research/`: `customChartPersistence.js` (12 lines — localStorage helpers for custom chart configs), `CustomChartBuilder.jsx` (249 lines — two-step wizard modal with source picker and field mapping, plus the private `FieldSelect` helper), `PlacedCard.jsx` (611 lines — the chart card component and all its rendering dependencies: `PlotlyChart`, `ChartErrorBoundary`, `IpParamInput`, `ExpandedOverlay`, `useScopeState`), `ResearchSlotBoard.jsx` (199 lines — `SlotGrid`, `EmptySlot`, `ChartPicker`, `PaletteCategory`, category constants and `inferCategory`). The coordinator keeps state management (slots, drag/drop, picker, builder, custom chart logic), time scope UI, and the palette sidebar. Pure refactor — identical props API, no behavior change.

### v0.25.1 — April 2026
- **GraphCanvas decomposition** — the 1665-line `GraphCanvas.jsx` monolith has been split into four hooks (`useGraphSim`, `useGraphViewSync`, `useGraphInteraction`, `useGraphResizePolling`), five components (`GraphContextMenu`, `GraphAnnotationOverlay`, `GraphEventDots`, `SyntheticNodeForm`, `SyntheticEdgeForm`), and `graphColorUtils.js`, plus a ~170-line coordinator. Shared refs (`renRef`, `rafRef`, `hRef`, `tRef`) are declared in the coordinator and passed to hooks. Pure refactor — identical props API, no behavior change. Phase 3 item #2 complete.

### v0.25.0 — April 2026
- **useCapture decomposition** — the 1143-line `useCapture.js` monolith hook has been split into five domain-specific hooks plus a thin coordinator, completing Phase 3 item #1 from the audit-02 frontend readability plan. The new files: `useAnnotationsAndSynthetic.js` (annotations, synthetic elements, alerts — ~130 lines), `useSelectionAndNavigation.js` (selection state, nav history, investigation, pathfinding, hidden nodes, panel resize — ~280 lines), `useCaptureFilters.js` (time range, protocol filter, search, subnet/cluster/display options — ~180 lines), `useCaptureData.js` (server data, all refetch effects, derived graph, display filter, client-side search — ~400 lines), `useCaptureLoad.js` (upload lifecycle, schema negotiation, type picker, loadAll orchestrator — ~220 lines). The coordinator (`useCapture.js`, ~190 lines) wires the slices via a shared callback ref pattern for cross-slice dependencies (E11 rawGraph→clearPathfind, E12 search→clearSelection) and lifts `loaded` state + `visibleNodes`/`visibleEdges` memos to the coordinator level. `handleCreateManualCluster` moved to coordinator since it crosses three slices. The return object shape is identical — pure refactor with no API or visual changes.

### v0.24.2 — April 2026
- **audit-02 phase 2: session↔edge helpers extracted** — `_session_matches_edge`, `_ip_matches_endpoint`, and `_protocol_matches` moved from `storage/memory.py` into a new `backend/data/session_match.py` module. `aggregator.py` and `memory.py` both import from there. Eliminates the data-layer → storage-layer import violation (private `_session_matches_edge` was being imported cross-layer).
- **Filter consolidation** — `flag_filter` and `search_query` were applied manually in `build_graph` after calling `filter_packets`, duplicating logic. `filter_packets` now accepts a `flag_filter` parameter; both parameters are passed through from `build_graph`. The duplicate filtering blocks in `build_graph` are removed.
- **Edge field cap comments** — added inline documentation at the `EDGE_TLS_CIPHER_SUITES` / `EDGE_TLS_CIPHERS` / `EDGE_DNS_QUERIES` constants clarifying these are view-layer display limits on the serialized graph response, not truncation of raw packet data.

### v0.24.1 — April 2026
- **audit-02 phase 1: backend bug fixes** — three targeted fixes in `aggregator.py`: (1) removed a duplicate `IPv4Address` import; (2) corrected a stale comment that said the bucket cap was 5000 when the constant has been 15000 since it was raised; (3) fixed a sort field mismatch — `memory.py` was sorting sessions by `bytes_total` but session records store the field as `total_bytes`, causing incorrect sort order in the sessions list.

### v0.24.0 — April 2026
- **Alerts live-load bug fixed** — alerts panel was always empty after a capture loaded, only populating after a browser refresh. Root cause: `build_analysis_graph_and_run()` (which populates `store.alerts`) fires lazily on the first `/api/graph` call, but `loadAll()` calls `fetchAlerts()` before any graph fetch has happened. Fix: re-fetch alerts inside the `useCapture.js` graph-fetch effect, in the `fullGraphRef` first-set branch — this fires exactly once, after the first graph response that triggered the detector run.
- **SchemaDialog in-app** — `SchemaDialog` was only rendered in the pre-load upload screen. It now also renders in the loaded app view so that re-uploading a mismatched log file while a capture is already loaded shows the mapping dialog correctly.
- **Manual type override** — when automatic format detection fails (no adapter matches the file), the backend now returns `{ detection_failed: true, available_adapters: [...] }` instead of a 400 error. The frontend shows a new `TypePickerDialog.jsx`: a dropdown of all registered adapters (pcap/pcapng, Zeek variants, tshark variants) so the researcher can declare the type manually. The upload then retries with `force_adapter` sent as a form field; the backend skips detection and uses the named adapter directly.
- **Detail panel flag button polish** — the "Flag" text label was removed from the flag buttons in `NodeDetail.jsx` and `EdgeDetail.jsx`; the flag icon alone is now sufficient. Button padding tightened to match the icon-only size.
- **Animation direction mismatch fixed** — the animation pane was drawing arrows using raw `src_ip` / `dst_ip` from session records, which reflects the order of the first captured packet — not necessarily the TCP initiator. `build_node_session_events` in `aggregator.py` now uses `initiator_ip` / `responder_ip` when available (set during TCP SYN tracking in `sessions.py`), falling back to `src_ip` / `dst_ip` for non-TCP or pre-handshake sessions.
- **Timeline graph drag-render bug fixed** — dragging a placed event node while ruler mode was off produced no visual movement until the user zoomed or panned. Root cause: with ruler off, the D3 force simulation is stopped (`alpha = 0`), so its tick callback (which calls `setTick`) never fired during drag. Fix: `onNodePointerMove` now calls `setTick(t => t + 1)` directly, forcing a re-render on every pointer move.

### v0.23.0 — April 2026
- **Adapter schema negotiation** — upload is now two-phase for structured log files (Zeek, tshark). Phase 1: adapter detects the file, inspects its column names against `declared_fields`, and if there's a mismatch (renamed columns, missing required fields) it stages the file under a UUID token and returns `schema_negotiation_required: true` + a `schema_report` (detected columns, missing required, unknown, suggested mappings) to the frontend. Phase 2: the new `SchemaDialog.jsx` presents the detected columns as a mapping table — dropdowns let the researcher map each detected column to the expected field name, required-field warnings highlight gaps, suggested mappings are pre-populated via heuristics (case-insensitive match, underscore/dot normalisation, Zeek→generic alias table, substring containment). "Confirm & Ingest" is disabled until all required fields are covered; confirming calls `POST /api/upload/confirm-schema` with the token + mapping, which calls `parse_with_mapping()` and runs the full ingest pipeline. If columns already match, upload proceeds without interruption.
- **`backend/parser/schema/` package** — three new modules sit between file detection and adapter ingestion: `contracts.py` (dataclasses: `SchemaField`, `SchemaReport`, `StagedFile`, `MappingConfirmation`), `inspector.py` (`inspect_schema` + suggestion heuristics), `staging.py` (in-memory staging area with UUID tokens and file lifecycle management).
- **Adapter method split** — all Zeek adapters (conn, dns, http, ssl, smb_files, smb_mapping, dce_rpc) and tshark metadata adapter now declare a `declared_fields` class attribute and implement `get_header_columns()` (fast header-only read), `get_raw_rows()`, and `_rows_to_packets()` so the base class `parse_with_mapping()` can apply column remapping between row extraction and packet construction. Adapters without `declared_fields` (PcapAdapter) fall back to `parse()` unchanged.
- **Format-based detection** — Zeek conn adapter is now the catch-all for Zeek logs (checked last; requires only the `#fields` header marker, no extension requirement). Tshark metadata adapter is the catch-all for tshark CSVs (checked last; requires `.csv` extension + tab-separated first line with ≥15 columns). Specific adapters (dns, http, ssl, etc.) are tried first.
- **25 backend tests** across inspect_schema (clean + renamed fixtures), get_header_columns, parse_with_mapping (full + partial mapping), and staging lifecycle.

### v0.22.7 — April 2026
- **Timeline Graph: shift-select → operations popover** — shift-clicking up to two placed event nodes in the Timeline Graph canvas accumulates them into a `selectedPair` state (max 2, FIFO drop-oldest; clicking the same node again deselects it). Pair-selected nodes get a dashed blue halo (`r = NODE_R + 4`, `strokeDasharray "3 3"`) around the existing severity ring. When two nodes are selected, an operations popover appears anchored to the on-screen midpoint of the pair — the position tracks zoom/pan via the existing `zoomTick` re-render. Popover offers two actions: **Draw edge** (opens the existing label prompt, clears the pair on confirm) and **Clear**. Draw edge is disabled with a tooltip when a manual edge for the pair already exists (uses the `edgePairKey` helper from v0.22.6). Plain (non-shift) click clears the pair selection, as does clicking empty canvas. Plays nicely with the existing draw-mode toolbar button — both reach `addTimelineEdge` via the same label prompt, giving the user two intuitive routes: pick nodes first then draw, or enter draw mode and pick nodes second.

### v0.22.6 — April 2026
- **Timeline Graph: multi-edge parallel arcs** — multiple manual edges drawn between the same pair of placed event nodes previously rendered stacked on top of each other as a single line. They now fan out as parallel quadratic Bézier arcs offset perpendicular to the chord. New `pairOffsets` memo groups `timelineEdges` by sorted pair-key (`edgePairKey(a, b)`) and assigns each edge an offset of `(i - (n-1)/2) × 22px` so the spread is symmetric (1 edge → straight, 2 → ±11px, 3 → −22/0/+22px, etc.). New `arcPath(ax, ay, bx, by, offset)` helper returns `{d, midX, midY}` where the midpoint is the actual on-curve midpoint (`mid + perp × offset`) so edge labels sit on the arc rather than the chord. Manual edges now render as `<path>` instead of `<line>`. Suggested edges remain straight lines — they are already merged per pair via the `×N` badge and don't need fanning. Main GraphCanvas multi-edges deferred — the `(src|dst|protocol)` triple already keeps duplicate flows in separate lanes.

### v0.22.5 — April 2026
- **Timeline Graph: back-to-investigation breadcrumb** — after clicking "View in graph" from inside InvestigationPage, a sticky banner appears in the top-left of the main graph view (`zIndex: 12`, blue-tinted, mirrors the existing pathfind/hidden-nodes banner styling) offering `← Back to Timeline Graph` (or `← Back to Documentation`, depending on which tab the user came from) and a `×` dismiss. Implementation: (1) `tab` state lifted from local-in-`InvestigationPage` up to `App.jsx` as `investigationTab` / `setInvestigationTab`; `InvestigationPage` falls back to local state if the prop is absent so it remains independently usable. (2) New `App.jsx` state `returnToInvestigationTab` (`null | 'documentation' | 'timeline'`) captures the source tab inside `onSelectEntity` before panel switch. (3) The back link calls `setInvestigationTab(dest)` + `setReturnToInvestigationTab(null)` + `c.switchPanel('investigation')`. (4) `useEffect` auto-clears `returnToInvestigationTab` when `c.rPanel === 'investigation'`, so navigating back by any other route (left-nav button, etc.) also resets the state cleanly.

### v0.22.4 — April 2026
- **Timeline Graph: "View in graph" now highlights the entity** — clicking "View in graph" from a timeline node's context menu (or from the node/edge/session detail cards inside the timeline) previously navigated to the main GraphCanvas but left the entity unselected and unhighlighted. The `onSelectEntity` handler in `App.jsx` is now rewritten to: (a) call `switchPanel('stats')` first (so its internal `clearSel` fires before the re-selection); (b) re-select the entity via `handleGSel` / `selectSession`; (c) call `setQueryHighlight({ nodes, edges })` to apply the existing orange ring + radial glow (the same mechanism used by AlertsPanel's "Show in graph"). Node case: highlights the node ID. Edge case: highlights the edge ID (`u|v` form) plus both endpoint nodes for context. Session case: fetches `session_detail`, resolves `src_ip` / `dst_ip` to node IDs (direct ID match, then fallback to `n.ips.includes(ip)` for subnetted nodes), and highlights both endpoints plus the canonical edge ID in both orderings (`a|b` and `b|a`). The highlight clears when the user clicks empty canvas via the existing `onClearQueryHighlight` path.

### v0.22.3 — April 2026
- **Timeline Graph: entity color coding + legend** — timeline graph nodes now carry a distinct fill tint by entity type: node `#58a6ff` (blue), edge `#a371f7` (purple), session `#3fb950` (green), applied at ~13% alpha (`'22'` hex suffix) so the fill reads without clashing with the severity ring. Replaces the flat `var(--bgP)` fill on node discs; the disc now encodes both severity (ring stroke color) and entity type (fill). A new legend in the sub-toolbar (after the Ruler checkbox) renders three swatches — full-saturation border, low-alpha fill — so the mapping is immediately discoverable. Also tightened the ruler-toggle call to `setRulerOn?.()` (optional-chaining) so it doesn't crash if the prop is momentarily absent during a transient remount.

### v0.22.2 — April 2026
- **Timeline Graph: layout persistence** — node positions and ruler state now survive tab navigation (Documentation ↔ Timeline Graph). Root cause of prior drift: `TimelineGraph` unmounted on tab switch, the d3-force simulation restarted at alpha 0.5 on remount, and charge + collide forces pushed nodes away from their persisted `canvas_x` / `canvas_y`. Fix: (1) `rulerOn` lifted from `TimelineGraph` local state into `useEvents` so it survives unmount. (2) Sync effect seeds every newly-created simulation node with `fx = canvas_x; fy = canvas_y` (locked), and re-locks released nodes when ruler is off. (3) In ruler-off mode, `sim.alpha(0).stop()` entirely — nothing moves unless a drag releases a node. (4) Drag-end persists position AND keeps `fx` / `fy` locked at the drop point (previously cleared them, letting the sim drift). (5) Ruler mode releases all `fx` / `fy` locks so the y-force can act; the ruler-on→off transition (tracked via `prevRulerRef`) walks each node and calls `placeEvent` to persist post-ruler positions back into `canvas_x` / `canvas_y`, cementing the time-sorted layout. Ruler-mode drag-end keeps `fx` locked but releases `fy` so the y-force continues pulling. Threaded `rulerOn` / `setRulerOn` through `useCapture` → `App.jsx` → `InvestigationPage` → `TimelineGraph`.

### v0.22.1 — April 2026
- **Timeline Graph: reject suggested edge** — clicking the ✕ reject button on a dashed suggested edge previously only dismissed the popup without persisting the rejection, so the edge reappeared on re-render. New `rejectedSuggestions` Set state in `useEvents` (keyed by unordered pair so a from/to swap doesn't revive the rejection), `rejectSuggestion(fromId, toId)` callback, and the `suggestedEdges` memo now filters out rejected pairs (Set is in the memo dependency array so updates are reactive). The "Reject all" button in the suggestion popup now calls `rejectSuggestion` instead of being a no-op. Threaded through `useCapture` → `App.jsx` → `InvestigationPage` → `TimelineGraph`.

### v0.22.0 — April 2026
- **Timeline Graph: zoom + pan canvas** — d3.zoom applied to the Timeline Graph SVG with `scaleExtent([0.3, 3])`. Wheel gesture zooms, dragging empty canvas pans. The transform is held in `tRef` (a ref, not state) and applied via a wrapping `<g transform={tRef.current.toString()}>` around all canvas content; the ruler axis is inside the transformed group so its ticks scale with the canvas. New `canvasPoint(clientX, clientY)` helper inverts the current transform for the three places that need canvas-space coordinates (node-drag start, node-drag move, EventsPanel drop) — node positions and persisted `canvas_x` / `canvas_y` remain in untransformed canvas space. Pan suppressed on node and edge gestures via `data-pan-skip="true"` plus a `filter: e => !e.target.closest('[data-pan-skip]')` on the zoom behavior. A transparent background `<rect>` covers the SVG so empty-canvas pan still works when no nodes are placed yet.

### v0.21.2 — April 2026
- **RESCUE: animation isolate now filters frames (not just edges)** — the v0.20.4 work that lifted `isIsolated` into `useAnimationMode` (so that the spotlight filter applied to timeline frames, play-loop, slider, and history — not just to edge visibility) had landed on commit `95a6c63` on branch `fix/animation-isolate-frames` and was never merged into main. Main jumped v0.20.3 → v0.21.0 on a parallel branch, orphaning the fix. Rescued by checking out `useAnimationMode.js` and `AnimationPane.jsx` from the dangling branch (those two files were untouched in v0.21.0 / v0.21.1, so the checkout was clean) and applying a 2-line manual edit to `App.jsx` to pass `isIsolated` / `setIsIsolated` through to `<AnimationPane>`. `useCapture.js` needed no changes — it already spreads `...anim` so the new props from `useAnimationMode` propagate automatically. The dangling branch was deleted after rescue.

### v0.21.1 — April 2026
- **EventCard contrast bump** — flagged events in the right-hand `EventsPanel` were rendering with `var(--bgP)` background, which is the same colour as the panel they sit on, making cards nearly invisible against the panel surface. Replaced with a raised-elevation surface: `rgba(255,255,255,.045)` background, `rgba(255,255,255,.14)` border (still keeping the severity-coloured 3px left border), slightly increased padding (`6px 8px` → `7px 9px`), and a soft `0 1px 2px rgba(0,0,0,.25)` drop shadow. Cards now read clearly without changing the existing layout.
- **PDF export hidden on Timeline Graph tab** — the "Save" and "⬇ Export PDF" buttons in the Investigation toolbar were always visible regardless of which tab was active, but both are markdown-only operations (Save persists the markdown body; Export PDF renders that markdown). On the Timeline Graph tab they were dead UI. Wrapped both buttons in `{tab === 'documentation' && (...)}` so the right side of the toolbar collapses cleanly when on the graph tab. The flex spacer (`<div style={{ flex: 1 }} />`) stays so the toolbar layout doesn't reflow.
- **Flag-as-Event button in EdgeDetail and NodeDetail** — `SessionDetail` already had a "Flag" button in its header (added in v0.21.0) that pre-fills `EventFlagModal` with the session reference, but `EdgeDetail` and `NodeDetail` had no equivalent affordance — the only way to flag an edge or node was via the GraphCanvas right-click context menu, which is not discoverable while the user is reading the detail panel. Both detail components now accept an `onFlagEvent` prop and render a small red flag button (`#f85149`, matching the SessionDetail pattern) in the header next to the close button. Wired in `App.jsx`: `EdgeDetail` gets `onFlagEvent={() => c.openFlagModal('edge', c.selEdge)}`; `NodeDetail` looks up the actual node object from the merged `detailNodes` list (needed because cluster-view member nodes only exist in `rawGraph`) and calls `c.openFlagModal('node', nObj)`. No `useCapture.js` changes — `openFlagModal` was already exposed.

### v0.21.0 — April 2026
- **Event type system Phase 1** — first-class flagged-event primitive for threat-hunt narratives. Researchers can right-click any node, edge, or session in the graph (or click the Flag button in the corresponding detail panel) and create an `Event` with title, description, severity (info/low/medium/high/critical), entity reference, and capture-derived timestamp. Events are managed by a new `useEvents` hook (in-memory only this phase — no backend persistence yet, beta banner in EventsPanel) that exposes CRUD, sorted iteration, and a memoised "suggested edges" engine.
- **`useEvents` hook** — `frontend/src/hooks/useEvents.js`. State: `events` (array, sorted by `capture_time` ascending), `flaggingTarget` (currently-being-flagged entity), `placedEventIds` (set of events placed on the timeline canvas), `timelineNodes` (per-event x/y), `timelineEdges` (manually-drawn edges between placed events), `rulerOn` (timeline y-axis force toggle). Operations: `openFlagModal(entity_type, entity)`, `closeFlagModal`, `createEvent`, `updateEvent`, `removeEvent`, `placeEventOnTimeline(eventId, x, y)`, `unplaceEvent`, `moveTimelineNode`, `addTimelineEdge`, `updateTimelineEdge`, `removeTimelineEdge`. Suggested-edge memo computes ALL pair combinations once but only the rendered list filters to placed-on-both-ends; matching reasons are `same_node` (events on the same IP/host), `same_subnet` (same /24), `same_protocol` (same edge protocol). Multiple reasons for one pair collapse into one merged edge with a `×N` badge and the colour of the highest-priority reason. Capture-time derivation: `node.first_seen` (computed client-side from min incident edge), `edge.first_seen`, `session.start_time`. `SEVERITY_COLOR` exported.
- **`EventFlagModal`** — `frontend/src/components/EventFlagModal.jsx`. Modal mounted in `App.jsx` reads `c.flaggingTarget`. Pre-fills entity-type label and reference; user supplies title, description, severity. Submit calls `createEvent`; cancel clears `flaggingTarget`. Same modal handles all three entity types.
- **`EventsPanel` + `EventCard`** — right-hand panel inside the Investigation page. `EventsPanel` renders the events sorted by `capture_time` ascending, kebab menu for filtering (severity), beta caveat banner ("Beta · session-only until workspace save ships"). `EventCard` is the row: severity-coloured ring/left-border, entity icon, title, target (truncated), description (2 lines clamped), kebab menu with Edit/Remove flag, drag handle on the whole card. Cards are draggable into the markdown editor and into the Timeline Graph canvas via dataTransfer (`application/x-swifteye-event` MIME).
- **`TimelineGraph`** — `frontend/src/components/TimelineGraph.jsx`. Pure SVG canvas using d3-force with `forceManyBody(-40)` (deliberately low push per user feedback) and `forceCollide(34)`. Drop target for events from EventsPanel; drop position becomes the initial node x/y. Placed nodes are draggable to reposition (drag updates `timelineNodes`). Suggested edges render dashed and dimmed; manually-drawn edges render solid. Right-click context menu on nodes: View in graph (highlights the entity in main GraphCanvas — placeholder hook this phase), Unplace (removes from canvas, EventCard's "placed" state clears). Ruler toggle: when on, a `forceY` pulls each node to a y-position mapped from `capture_time` so events sort top-to-bottom by time. Draw-edge mode (toolbar button): click two placed nodes to add a manual edge between them. Node detail card and edge detail card render below the canvas when an item is selected.
- **`InvestigationPage` tab bar** — Documentation tab (existing markdown editor + screenshot paste + autosave) and Timeline Graph tab (new `TimelineGraph` canvas). EventsPanel sits to the right of both tabs. The markdown editor accepts dragged `EventCard`s and inserts a `<event-ref id="…"/>` token at the cursor; on render this token is replaced with a clickable ref-chip (small pill showing event title + severity colour) using a NUL-byte placeholder pass to survive markdown HTML escape. Clicking a ref-chip in the rendered preview calls `onSelectEntity` (`App.jsx` wires this to the appropriate select function based on entity type). PDF export (existing functionality) only operates on the markdown body — graph tab is excluded.
- **`GraphCanvas` indicator dots + Flag-as-Event context menu** — `GraphCanvas.jsx` overlay layer reuses the annotation overlay pattern: reads `tRef.current` (current d3-zoom transform) and projects each event's referenced entity coordinates into screen space, then renders small severity-coloured dots above the node/edge so flagged events are visible in the main graph view. Right-click context menus on nodes and edges gain a "Flag as Event" item that calls `c.openFlagModal('node'|'edge', entity)`.
- **`SessionDetail` Flag button** — header row gains a small red flag button next to the existing nav buttons. Clicking it calls `onFlagEvent` (passed as prop), which `App.jsx` wires to `c.openFlagModal('session', c.selSession)`. Pattern later copied in v0.21.1 to EdgeDetail and NodeDetail.
- **`useCapture.js` events plumbing** — mounts `useEvents`, exposes `events`, `placedEventIds`, `timelineNodes`, `timelineEdges`, `rulerOn`, `flaggingTarget`, `openFlagModal`, `closeFlagModal`, `createEvent`, `updateEvent`, `removeEvent`, `placeEventOnTimeline`, `unplaceEvent`, `moveTimelineNode`, `addTimelineEdge`, `updateTimelineEdge`, `removeTimelineEdge`, `setRulerOn`. No state in `useCapture` itself — it's a thin pass-through to `useEvents`.
- **Phase 2 deferred** — backend persistence (workspace save), pluggable suggested-edge plugins (`event-suggested-edges-pluggable` roadmap item added), Phenomena (typed reusable event templates — needs real-usage data first), edge-label edit wired to TimelineGraph edge detail card. The full Opus design plan lives at `docs/plans/archive/event-type-system.md`.

### v0.20.4 — April 2026
- **Animation isolate now filters frames, not just edges** — toggling Isolate previously hid spotlight↔neighbour edges visually, but the timeline scrubber, history panel, frame counter, and play loop still iterated over every event in the capture. Lifted `isIsolated` state into `useAnimationMode`. New `animEvents` is the effective list, derived from `rawEvents` (the unfiltered API response) filtered to spotlight↔spotlight when `isIsolated`. All downstream state — `frameState`, `currentEvent`, `totalFrames`, `animTimeRange`, `eventsRef`, the play timer, and every transport callback — operates on the effective list. `animFrame` clamps when the effective list shrinks. `AnimationPane.jsx` consumes `isIsolated`/`setIsIsolated` from props (via `c.isIsolated`); the redundant edge filter line in `visibleEdges` was removed since events are pre-filtered upstream.
- **`docs/METHODOLOGY.md` gitignored** — moved to private dogfood doc, not redistributable.
- **METHODOLOGY.md intro rewritten** — methodology's stated goal is **scalability and cross-session knowledge retention** (keeping an LLM coherent with the project's principles, philosophy, and architectural constraints as the codebase grows). Token efficiency is the means, not the end.
- **`/add_to_roadmap` slash command rewritten cache-first** — old version edited `ROADMAP.md` directly mid-session, violating the docs-second flush model. New version reads `ROADMAP.ai.md`, writes the row to that mirror, and stashes the detail block in `SESSION.md → Pending flush` so end-of-session flush inserts it into `ROADMAP.md`. Forbids touching `ROADMAP.md` mid-session.

### v0.20.3 — April 2026
- **Animation isolate toggle** — header pill in `AnimationPane.jsx` toggles "isolate spotlight" mode: hides edges where neither endpoint is a spotlight node. (Frame filtering came in v0.20.4 — this version only filtered edges visually.)
- **Live protocol filter in animation pane** — animation now respects the active global protocol filter at fetch time; toggling protocols in the left panel re-fetches `/api/node-animation` with the active list. Previously the animation pane was fixed to whatever protocols were enabled at start.
- **None=no edges** — when all protocols are deselected, the animation canvas correctly renders zero edges instead of falling back to "all protocols".

### v0.20.2 — April 2026
- **Fix: animation "View session" returns 422** — `fetchSessionDetail(sid, 0)` from `App.jsx`'s animation fallback was rejected by FastAPI: `/api/session_detail` declares `packet_limit: int = Query(default=1000, ge=1, le=50000)`, so `0` failed validation before the handler ran. Regression from v0.20.1's animation fallback (which only fixed the no-op case, not the boundary). Same code path is hit by any other caller that lands on a session outside the local top-1000 list.
- **`fetchSessionDetail()` clamps `packetLimit`** — `frontend/src/api.js` now mirrors the backend constraint at the single frontend gateway: `Math.max(1, Math.min(50000, packetLimit))`. The animation fallback's `0` is normalized to `1`; the response's `d.packets` is still discarded by the caller (it only reads `d.session`), so the wasted work is one packet's worth of serialization. Any future caller that underflows or overflows the bound is silently corrected instead of getting a 422.

### v0.20.1 — April 2026
- **Fix: Edge "No sessions found"** — replaced 3 ad-hoc session↔edge matching implementations with a single canonical function. Root cause: `s.protocol === e.protocol` failed when sessions stayed as transport protocol (e.g. "TCP") while edge was app-layer (e.g. "TLS"). Also failed with subnet grouping (CIDR node IDs) and MAC-split node IDs.
- **Canonical session↔edge matching** — new `_session_matches_edge()` in `storage/memory.py`. Handles: protocol/transport matching (session.protocol OR session.transport matches edge.protocol), bidirectional IP matching (sessions use sorted IPs, edges don't), subnet CIDR containment, MAC-split node IDs. Used by `MemoryBackend.get_sessions_for_edge()`, `build_analysis_graph()`, and frontend `sessionMatch.js`.
- **New `/api/edge-sessions` endpoint** — `GET /api/edge-sessions?edge_id=src|dst|protocol`. Returns all sessions for an edge using the canonical matcher. EdgeDetail now fetches from this endpoint instead of client-side filtering from a capped 1000-session list.
- **Frontend `sessionMatch.js`** — shared client-side mirror of the backend matcher for fast in-memory matching in NodeDetail and search.
- **Fix: animation "View session" does nothing** — the handler looked up sessions in the local 1000-item list. Now falls back to `fetchSessionDetail()` from the API when not found locally.
- **EdgeDetail simplified** — removed `sessions`/`fullSessions` props, `ScopePill`, `edgeFilter`, `nodeIpsMap`, `resolveSearchIp`. Session data comes entirely from the API.

### v0.20.0 — April 2026
- **Directional edges** — graph edges are now directional (source = initiator, target = responder). Edge ID format: `src|dst|protocol`. A→B and B→A are separate edges representing different traffic flows. This enables accurate port scan detection, per-direction port analysis, and proper attribution of HTTP user-agents.
- **Separate src/dst ports on edges** — edges carry `src_ports` and `dst_ports` instead of a mixed `ports` set. The `ports` field (union) is kept for backward compatibility. Port scan detection can now distinguish "many dst_ports from few src_ports" directly from the graph.
- **HTTP user-agents on edges** — edges now carry `http_fwd_user_agents` collected from packet extras. Suspicious UA detection can work from edge data in v0.20.1.
- **Node↔edge cross-references** — nodes gain `edge_ids` (list of connected edge IDs). `AnalysisContext` gains lazy `node_map` and `edge_map` properties for O(1) lookups. Detectors can navigate from edge → node → other edges without scanning.
- **Zeek conn_state → has_handshake** — Zeek conn.log adapter now derives `has_handshake` from `conn_state` field (SF/S1/S2/S3/RSTO/RSTR = handshake complete). Port scan TCP detection is now accurate on Zeek data. Sessions respect adapter-provided `has_handshake` without overwriting.

### v0.19.0 — April 2026
- **Alerts panel** — new full-width `AlertsPanel` page for security-relevant pattern detection. Four Phase 1 detectors: ARP spoofing (IP claimed by multiple MACs, gratuitous ARP floods), suspicious HTTP user-agents (scripting tools, empty UA), malicious JA3 fingerprints (known malware hashes from `ja3_db.py`, deprecated TLS 1.0/1.1), and port scanning (TCP + UDP, threshold-based with handshake ratio analysis).
- **Alert plugin tier** — new `AlertPluginBase` in `plugins/alerts/`. Detectors subclass it, implement `detect(ctx) → List[AlertRecord]`, and register in `server.py`. Detectors run after graph build, reading from the same `AnalysisContext` as analysis plugins. `AlertRecord` dataclass: id, title, subtitle, severity (high/medium/low/info), detector name, source (detector/external), timestamp, src/dst IPs, evidence rows, and node/edge/session ID lists for graph navigation.
- **`/api/alerts` endpoint** — returns all alerts sorted by severity (high→medium→low→info), plus a summary object with per-severity counts. New `routes/alerts.py` router.
- **Alerts in store** — `store.alerts` populated after graph build, cleared on new upload. `run_alert_detectors()` added to `services/capture.py` pipeline.
- **AlertsPanel UI** — severity filter pills (All/High/Medium/Low/Info), smart search (matches IP, detector, title, subtitle, evidence values), sort by severity/time/detector. Expandable alert cards with evidence key/value rows. "Show in graph" button highlights involved nodes/edges using the existing `queryHighlight` mechanism.
- **Nav integration** — Alerts item in left panel with red badge showing high+medium count. Badge only shown when count > 0.

### v0.18.0 — April 2026
- **Node temporal animation** — select one or more nodes on the graph and replay their session activity as a frame-by-frame animation. Backend: `build_node_session_events()` in `aggregator.py`, new `/api/node-animation` endpoint in `routes/animation.py`. Frontend: `useAnimationMode.js` hook (playback state, transport controls, speed 0.5×–5×), `AnimationPane.jsx` (~1100 lines: canvas render, header, scrubber, history panel, options popover, keyboard shortcuts, tooltips). Entry points: right-click context menu on graph nodes ("Animate timeline"), "Animate" button in NodeDetail and MultiSelectPanel.
- **Animation Phase 2** — focused node filtering (pill row in header to filter edges to one spotlight node when multiple selected), draggable nodes (pointer-capture drag with D3 zoom suppression), right-click context menu on animation nodes (hide node, focus, view details), bulk hide inactive neighbours (options popover button + restore-all badge in header).
- **Panel nav reorder** — "Graph Options" moved above "Server Logs" and "Help" in the left panel navigation.
- **Logo navigates overview** — clicking the SwiftEye logo returns to the overview panel (clears selection, stops animation).
- **14 animation backend tests** — single/multi spotlight, event sorting, protocol filter, response shape, hostname passthrough, bytes aggregation, neighbour inclusion.

### v0.17.0 — April 2026
- **Unified dpkt reader** — eliminated the dual scapy/dpkt parser split. All pcap/pcapng files now use dpkt for L2/L3/L4 parsing (Ethernet, IP, TCP/UDP, ARP, ICMP) and scapy L5 objects (`DNS(payload)`, `TLS(payload)`, `Raw(load=payload)`) for application-layer dissection via the existing protocol dissectors. One code path for all file sizes — no threshold constant, no dissector parity problem.
- **New `l5_dispatch.py`** — L5 enrichment module: protocol detection (payload signatures + TLS byte marker), transport-quirk stripping (TCP DNS 2-byte prefix), scapy L5 object construction, dissector dispatch, JA3/JA4 fingerprinting. Clean separation: dpkt owns L2-L4, l5_dispatch owns L5.
- **Multiprocessing for large pcap files** — new `parallel_reader.py` pre-scans pcap packet header offsets (I/O only, no packet data), splits into N chunks (N = cpu_count, capped at 8), spawns workers via `multiprocessing.get_context('spawn')` (Windows + Linux). Falls back to single-threaded for pcapng, small files (<10K packets), or on failure. Configurable via `use_parallel` parameter.
- **MAX_FILE_SIZE raised to 2 GB** — scapy memory limit removed since scapy is no longer used for full-packet parsing.
- **Missing PacketRecord fields filled** — ECN bits (IPv4 + IPv6), `ip_checksum`, `tcp_checksum`, `urg_ptr`, `ip6_flow_label`, SAck TCP option, ARP extra fields (opcode, broadcast flag), ICMP dissector now called via Raw fallback path.
- **pcapng best-effort** — dpkt.pcapng.Reader handles standard captures (EPB/SPB blocks). NRB, DSB, custom blocks silently skipped. Roadmap item `pcapng-battle-test` added.
- **ICMPv6 known gap** — ICMPv6 dissector has no raw fallback path; `extra` stays `{}` for ICMPv6 packets. Documented, not blocking.

### v0.16.0 — April 2026
- **Storage backend Phase 1** — new `backend/storage/` module with `StorageBackend` ABC and `MemoryBackend` implementation. Replaces three O(n) hot-path scans with O(1) indexed lookups: session detail packet fetch (was full 2M packet scan, now dict index), session-by-ID lookup (was linear scan, now dict), and time-range session scoping (was full packet scan, now 15-second bucket index). New `EventRecord` dataclass defined as Phase 2 migration target (not yet wired). `session_key` fixed for non-IP packets (ARP, raw L2) — falls back to MAC-pair grouping with `l2|` prefix. Session detail API: `packet_limit` raised from 1000→50000, `packet_offset` param added. Sessions API: limit raised from 5000→100000, `offset` param added. Payload serialization helpers (`_payload_hexdump`, `_payload_entropy`) moved from `store.py` to `storage/serializers.py`.

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
