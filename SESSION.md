# Session State

**Last updated:** 2026-04-10 · **Current version:** v0.23.0
**Current branch:** feat/adapter-schema-negotiation (not yet merged)
**Mirror sync state:** all mirrors current as of v0.22.7; v0.23.0 on branch only

> Live, per-session cache. Read first after `CLAUDE.md`.
> Write here during the session. Flush to human docs only at merge — not mid-session.

---

## Shipped this session

- v0.23.0 — **adapter-schema-negotiation** on `feat/adapter-schema-negotiation`. New `backend/parser/schema/` package (contracts, inspector, staging) sits as its own layer before any adapter. All Zeek adapters (conn, dns, http, ssl, smb_files, smb_mapping, dce_rpc) and tshark metadata adapter now declare `declared_fields` and implement `get_header_columns()` / `get_raw_rows()` / `_rows_to_packets()` / `parse_with_mapping(mapping)`. Upload flow is two-phase: detect adapter → inspect schema → if clean proceed; if mismatch, stage file (UUID token), return `schema_negotiation_required: true` + `schema_report` + `staging_token`. New `POST /api/upload/confirm-schema` accepts token + confirmed `mapping` → `parse_with_mapping` → full ingest. Frontend: `SchemaDialog.jsx` shows detected-vs-expected columns as a mapping table with dropdowns, required-field banners, suggested-mapping pre-population, and Confirm & Ingest button. Wired via `schemaNegotiation` / `handleSchemaConfirm` / `handleSchemaCancel` in useCapture + `confirmSchemaMapping` in api.js. Test fixtures: zeek_conn_clean, zeek_conn_renamed, zeek_dns_clean, tshark_metadata_clean, tshark_metadata_renamed (10 rows each). 25 backend tests — all passing. Frontend rebuilt.



- v0.22.7 — **timeline-graph-phase2 item 8: shift-select operations popover** on `feat/timeline-graph-phase2`. Shift-clicking up to 2 placed event nodes now accumulates them into a new `selectedPair` state (max 2, FIFO drop-oldest, click-same-id-again toggles off). Pair-selected nodes get a dashed blue halo around the existing severity ring (`r = NODE_R + 4`, `strokeDasharray "3 3"`). When `selectedPair.length === 2`, an operations popover renders anchored to the on-screen midpoint of the pair (canvas-space midpoint × `tRef.current.k` + `tRef.current.{x,y}`, so it tracks zoom/pan via the existing `zoomTick` re-render). Popover offers two actions: "Draw edge" (opens the existing label prompt, then clears the pair) and "Clear". The Draw edge button is disabled with a tooltip when `timelineEdges` already contains a manual edge for the pair (uses the new `edgePairKey` helper from v0.22.6). Plain (non-shift) click clears `selectedPair`, as does the canvas background click handler. Plays nicely with the existing draw-mode button — both reach `addTimelineEdge` via the same label prompt; this is a more direct alternative when the user already knows which two events they want to connect. Frontend rebuilt.

- v0.22.6 — **timeline-graph-phase2 item 7: multi-edge parallel arcs** on `feat/timeline-graph-phase2`. Duplicate manual edges between the same pair of placed events used to draw on top of each other. Now they fan out as parallel quadratic-Bezier arcs. (a) New `pairOffsets` memo groups `timelineEdges` by sorted pair-key (`edgePairKey(a, b)`) and assigns each edge an offset of `(i - (n-1)/2) * 22px` perpendicular to the chord — symmetric around the line. (b) New `arcPath(ax, ay, bx, by, offset)` helper returns `{d, midX, midY}` where the midpoint is the actual ON-CURVE midpoint (`mid + perp * offset`, which is exactly half of where we put the Bezier control point) so labels sit on the arc instead of the chord. (c) Manual edges now render as `<path>` instead of `<line>`. Suggested edges stay as straight `<line>` (they're already merged-per-pair via the `×N` badge so they don't need fanning). (d) Main GraphCanvas multi-edges deferred — protocol-keyed edges already separate visually and the `(src|dst|protocol)` triple keeps duplicates in different lanes. Frontend rebuilt.

- v0.22.5 — **timeline-graph-phase2 item 6: back-to-investigation breadcrumb** on `feat/timeline-graph-phase2`. After "View in graph" navigates the user away from InvestigationPage, a sticky banner appears in the top-left of the main graph view (blue-tinted, mirrors the pathfind/hidden-nodes banner styling) with `← Back to Timeline Graph` (or `Documentation`, depending on which tab they came from) and a `×` dismiss. (a) Lifted `tab` state from local-in-InvestigationPage up to `App.jsx` as `investigationTab` / `setInvestigationTab` — InvestigationPage falls back to local state if the props aren't passed (so it remains independently usable). (b) New App.jsx state `returnToInvestigationTab` (`null | 'documentation' | 'timeline'`); `onSelectEntity` captures the source tab into it before switching panels. (c) Banner rendered inside the graph container at `zIndex: 12`. The "back" button calls `setInvestigationTab(dest)` + `setReturnToInvestigationTab(null)` + `c.switchPanel('investigation')`. (d) `useEffect` auto-clears `returnToInvestigationTab` when `c.rPanel === 'investigation'`, so if the user navigates back to investigation by any OTHER route (left-nav button, breadcrumb back, etc.) the state resets cleanly. Frontend rebuilt.

- v0.22.4 — **timeline-graph-phase2 item 5: view-in-graph highlight** on `feat/timeline-graph-phase2`. The "View in graph" context menu in TimelineGraph (and the same path in the node/edge detail cards inside the timeline) was already wired through `onSelectEntity` in `App.jsx`, but it was a no-op visual: it called `handleGSel` (which then got cleared by `switchPanel`'s internal `clearSel`) and never lit anything up on the main `GraphCanvas`. Rewrote the `onSelectEntity` handler to: (a) call `c.switchPanel('stats')` FIRST so its `clearSel` doesn't wipe what comes next (React 18 batches setStates in order, last write per slot wins); (b) re-select the entity via `handleGSel`/`selectSession`; (c) reuse the existing `queryHighlight` mechanism — same orange ring + radial glow already used by AlertsPanel's "Show in graph" — by calling `setQueryHighlight({ nodes, edges })`. Node case: highlights the node id. Edge case: highlights the edge id (`u|v` form) AND both endpoint nodes for context. Session case: fetches `session_detail`, resolves `src_ip`/`dst_ip` to node ids (direct id match, then fallback to `n.ips.includes(ip)` for subnetted nodes), highlights both endpoints + both orderings of the edge id (`a|b` and `b|a`, since the GraphCanvas comparator accepts either). The highlight clears via the existing `onClearQueryHighlight` path when the user clicks empty canvas. Frontend rebuilt.

- v0.22.3 — **timeline-graph-phase2 item 4: entity color coding + legend** on `feat/timeline-graph-phase2`. Distinct fill tint per entity type — node `#58a6ff` blue, edge `#a371f7` purple, session `#3fb950` green — applied at low alpha (`'22'` ≈ 13%) to the node disc fill, replacing the flat `var(--bgP)`. Severity ring (stroke) is unchanged so the disc now encodes BOTH severity (ring) and entity type (fill). New legend in the sub-toolbar (after the Ruler checkbox, before the right-aligned counters) renders three swatches with full-saturation borders and low-alpha fills so the mapping is discoverable. Also tightened the ruler-on `setRulerOn?.()` optional-call so the toggle doesn't crash if the prop is missing during a transient remount. Frontend rebuilt.

- v0.22.2 — **timeline-graph-phase2 item 3: layout persistence** on `feat/timeline-graph-phase2`. The bug it fixes: switching tabs (Documentation ↔ Timeline Graph) caused node positions to drift because TimelineGraph remounted, the d3-force sim restarted at alpha 0.5, and charge + collide pushed nodes from their persisted canvas_x/canvas_y. Fix: (a) `rulerOn` lifted from TimelineGraph local state into `useEvents` so it survives unmount; (b) sync effect now seeds every newly-created sim node with `fx = canvas_x; fy = canvas_y` (locked in place), and re-locks any released nodes when ruler is OFF; (c) ruler-off mode `sim.alpha(0).stop()` entirely — nothing moves unless a drag releases a node; (d) drag-end persists position AND keeps `fx`/`fy` locked at the drop point (was: cleared them); (e) ruler mode toggles between full-release (so y-force can act) and full-lock; (f) ruler on→off transition (tracked via `prevRulerRef`) walks each node and calls `placeEvent` to persist the post-ruler positions back into canvas_x/canvas_y, so toggling ruler off cements the time-sorted layout. Ruler-mode drag-end keeps `fx` locked but releases `fy` so the y-force keeps pulling. Threaded `rulerOn` / `setRulerOn` through useCapture → App.jsx → InvestigationPage → TimelineGraph. Frontend rebuilt.

- v0.22.1 — **timeline-graph-phase2 item 2: reject suggested edge** on `feat/timeline-graph-phase2`. New `rejectedSuggestions` Set state in `useEvents` (keyed by unordered pair, so reject survives a from/to swap), `rejectSuggestion(fromId, toId)` callback that adds the pair-key, `suggestedEdges` memo dependencies extended to include the Set so updates are reactive, and pair filter at the top of the O(n²) double-loop. The "Reject all" button in the TimelineGraph suggestion popup now calls `rejectSuggestion` (it was previously a no-op `setSuggestionPopup(null)`). Threaded through useCapture, App.jsx, InvestigationPage, TimelineGraph as a prop. Frontend rebuilt.

- v0.22.0 — **timeline-graph-phase2 item 1: zoom + pan canvas** on `feat/timeline-graph-phase2`. d3.zoom on the SVG, scaleExtent `[0.3, 3]`, wheel-to-zoom, drag-empty-canvas-to-pan. Transform held in `tRef` (ref, not state) and applied via a wrapping `<g transform={tRef.current.toString()}>` around all canvas content; the ruler axis is inside that group so its ticks scale with the canvas. New `canvasPoint()` helper inverts the transform for the three places that need canvas-space coords (node-drag start, node-drag move, EventsPanel drop) — node positions and persisted `canvas_x`/`canvas_y` stay in untransformed canvas space. Pan suppressed on node/edge gestures via `data-pan-skip="true"` on those `<g>` elements plus a `filter: e => !e.target.closest('[data-pan-skip]')` on the zoom behavior. A transparent background `<rect>` is rendered first so empty-canvas pan still works when no nodes are placed. Frontend rebuilt.

- v0.21.2 — **RESCUE: animation-isolate filters timeline frames** on `feat/timeline-graph-phase2`. The v0.20.4 work (lift `isIsolated` into `useAnimationMode`, derive `animEvents` from `rawEvents` filtered by spotlight set so frames/play-loop/slider/history all see the filtered list, drop the redundant edge-level filter in `AnimationPane`, App.jsx prop pass-through) was on commit `95a6c63` on dangling branch `fix/animation-isolate-frames` and never made it to main — main jumped v0.20.3 → v0.21.0. Rescue: `git checkout fix/animation-isolate-frames -- frontend/src/components/AnimationPane.jsx frontend/src/hooks/useAnimationMode.js` (clean — those two files were untouched in v0.21.0/v0.21.1) plus a manual 2-line edit to `frontend/src/App.jsx` (passing `isIsolated`/`setIsIsolated` through to `<AnimationPane>`). useCapture.js needed nothing — it already does `...anim` spread, so the new `isIsolated`/`setIsIsolated` from `useAnimationMode` propagate via `c.isIsolated`/`c.setIsIsolated` automatically. Frontend rebuilt. Dangling branch deleted.
- v0.21.1 — **ui-events-polish merged to `main`**. Three quick wins: (1) `EventCard` contrast bumped — replaced `var(--bgP)` with `rgba(255,255,255,.045)` background, `rgba(255,255,255,.14)` border, slight padding increase, and a subtle drop shadow so cards now sit visibly above the panel. (2) `InvestigationPage` Save / Export PDF buttons now wrapped in `{tab === 'documentation' && ...}` so they only appear on the Documentation tab — no more PDF button on Timeline Graph. (3) Flag-as-Event button added to `EdgeDetail` and `NodeDetail` headers, mirroring the SessionDetail pattern (red `#f85149` flag SVG, `onFlagEvent` prop). Wired in `App.jsx`: EdgeDetail gets `onFlagEvent={() => c.openFlagModal('edge', c.selEdge)}`; NodeDetail looks up the node object from `detailNodes` then calls `c.openFlagModal('node', nObj)`. No changes to `useCapture.js` (already exposes `openFlagModal`). Frontend rebuilt.
- v0.21.0 — **event-type-system Phase 1 shipped** on `feat/event-type-system`. New `useEvents` hook (state + CRUD + suggested-edge engine, in-memory), `EventFlagModal`, GraphCanvas right-click "Flag as Event" + severity indicator dots overlay (re-uses annotation overlay pattern, reads `tRef.current` for zoom transform), `SessionDetail` flag button, `EventsPanel` + `EventCard` (sorted by capture_time asc), `InvestigationPage` tab bar (Documentation / Timeline Graph), drag-to-insert ref chips in markdown editor (NUL-byte placeholder pass to survive HTML escape), and full `TimelineGraph` SVG canvas with d3-force `forceManyBody(-40)` + `forceCollide(34)` (low push per user), drag-drop from EventsPanel, drag-reposition placed nodes, suggested edges (dashed/dimmed, merged per pair, ×N badge), draw-edge mode, ruler toggle (`forceY` pulls nodes to time-mapped y), right-click context menu (View in graph / Unplace), node + edge detail cards. Phase 2 (phenomena, pluggable suggested-edge plugins, workspace persistence) deferred. All open questions answered: ALL pairs computed (one memo) but only rendered when both endpoints placed; markdown editor stays a textarea with `<event-ref/>` tokens; pure SVG + existing d3 (no new dep); multiple events per entity allowed (indicator = highest severity); capture_time = node.first_seen (derived client-side from min incident edge) / edge.first_seen / session.start_time.
- 2026-04-09 — **event-type-system Opus plan complete** (`docs/plans/event-type-system.md`). Full Phase 1/2 design, 6 open questions for Opus to resolve with user, Phenomena concept documented as open design question, beta notice. Added to `FOR_OPUS.md`.
- 2026-04-09 — **event system mockup** (`docs/mockups/event-system-mockup.html`). Documentation tab (markdown + event cards + ref chips) + Timeline Graph tab (suggested edges, dashed/dimmed, accept/reject, ×N badge for merged reasons, ruler toggle, manual edges).
- 2026-04-09 — **roadmap: adapter-schema-negotiation** added (high/medium/medium — interactive column mapping for mismatched adapter schemas, two-phase load).
- 2026-04-09 — **roadmap: event-suggested-edges-pluggable** added (medium/medium/medium — phase 2 pluggable suggested-edge logic).
- v0.20.4 — **animation isolate now filters frames, not just edges**. Lifted `isIsolated` state into `useAnimationMode`. New `animEvents` (effective) is derived from `rawEvents` filtered to spotlight↔spotlight when isolated; `frameState`, `currentEvent`, `totalFrames`, `animTimeRange`, the play loop, and all transport callbacks operate on the effective list. `animFrame` clamps when the effective list shrinks. `AnimationPane` consumes `isIsolated`/`setIsIsolated` from props (via `c.isIsolated`); the redundant edge filter line was removed since events are pre-filtered upstream.
- v0.20.4 — **`docs/METHODOLOGY.md` gitignored** (private dogfood doc, not redistributable).
- v0.20.4 — **METHODOLOGY.md intro rewritten**: methodology's goal is **scalability and cross-session knowledge retention** — keeping an LLM coherent with the project's principles, philosophy, and architectural constraints as the codebase grows. Token efficiency is the means, not the end.
- v0.20.4 — **`/add_to_roadmap` slash command rewritten cache-first** (`~/.claude/commands/add_to_roadmap.md`). Reads `ROADMAP.ai.md` (not `ROADMAP.md`), adds the row to the cache mirror, stashes the full detail block in `SESSION.md → Pending flush` for end-of-session insertion into `ROADMAP.md`. Forbids touching `ROADMAP.md` mid-session.
- v0.20.1 — canonical session↔edge matching (`_session_matches_edge` in `storage/memory.py`); new `/api/edge-sessions`; `sessionMatch.js` mirror; EdgeDetail simplified; animation "View session" fallback to `fetchSessionDetail()`
- v0.20.2 — fixed 422 on `/api/session_detail` from animation fallback (clamped `packet_limit` in `frontend/src/api.js`)
- v0.20.3 — animation isolate toggle, live protocol filter, none=no edges
- **Methodology overhaul** — `.ai.md` mirror system + `SESSION.md` cache + docs-second flush model. New files: `HANDOFF.ai.md`, `ROADMAP.ai.md`, `CHANGELOG.ai.md`, `DEVELOPERS.ai.md`, `ARCHITECTURE.ai.md`, `SESSION.md`. `docs/METHODOLOGY.md` rewritten to follow the dual-doc upgrade. `CLAUDE.md` rewritten to point at `.ai.md`. `.gitignore` updated. `METHODOLOGY_UPGRADE.md` deleted.

---

## Do next

### timeline-graph-phase2 — DONE, on `main`

All 8 items shipped v0.22.0–v0.22.7. `feat/timeline-graph-phase2` and `main` are identical (same HEAD commit). Moved to `COMPLETED.md`. Next: pick from roadmap.

---

### event-type-system (v0.21.0) — SHIPPED on `main`

**Opus plan:** `docs/plans/event-type-system.md`. All 6 open questions resolved with user 2026-04-09. Phase 1 complete. Merged into `main` along with v0.21.1.

**Known caveats / Phase 2 follow-on:**
- All event state is in-memory (no backend persistence). Caveat banner in EventsPanel says "Beta · session-only until workspace save ships".
- Roadmap item `event-suggested-edges-pluggable` already added — Phase 2 makes the same_node / same_subnet / same_protocol logic plugin-driven.
- Phenomena (typed reusable event templates) deferred — needs real usage data first.
- Edge label edit in TimelineGraph is read-only in v0.21.0 (`updateTimelineEdge` is exposed but not yet wired to the edge detail card).

**Files added/changed in v0.21.0:**
- New: `frontend/src/hooks/useEvents.js`, `frontend/src/components/EventFlagModal.jsx`, `frontend/src/components/EventsPanel.jsx`, `frontend/src/components/EventCard.jsx`, `frontend/src/components/TimelineGraph.jsx`
- Changed: `frontend/src/hooks/useCapture.js` (mounts `useEvents`, exposes events plumbing + `flaggingTarget`), `frontend/src/components/GraphCanvas.jsx` (Flag-as-Event context menu items + indicator dots overlay), `frontend/src/components/SessionDetail.jsx` (Flag button in header), `frontend/src/components/InvestigationPage.jsx` (tab bar, ref-chip render pass, drop handler), `frontend/src/App.jsx` (mounts EventFlagModal, wires `onSelectEntity` for ref-chip click-throughs), `frontend/src/version.js` (0.20.4 → 0.21.0)

---

## Known issues (not fixed, not blocking)

- **Post-parse pipeline bottleneck** — `build_sessions + build_graph + plugins` ~20s for 440K packets. Roadmap: `post-parse-pipeline-opt`. Needs profiling first.
- **"Size by" graph option** — user considers it poor quality, needs review pass.
- **ICMPv6 dissector** — no raw fallback. Extra stays `{}`. Documented, not blocking.
- **scapy DNS deprecation** — `dns.qd` → `dns.qd[0]`. 39K warnings per test run. Will break when scapy drops old API.
- **dpkt `IP.off` deprecation** — should use new field name.

## Deferred

- **Alerts Phase 2** — design complete in `docs/plans/ALERTS_PHASE2_PLAN.md`. 6 workstreams, all decisions resolved except port-scan handshake ratio (ask user before WS1). Deprioritized in favor of event-type-system.

---

## Do next — priority for next session

**Top priority: `adapter-schema-negotiation`** — user confirmed this as the next feature to work on. Adapters should handle different column names and different ways of detecting formats. Detail block already in `ROADMAP.md`. Start there.

Also queue these short-term bug fixes (all low effort, any session):
- `alerts-live-load-bug` — critical, investigate `loadAll()` / `fetchAlerts()` wiring
- `timeline-graph-phase3` — drag-render bug + node-click detail card
- `detail-panel-polish` — header layout + remove "Flag" text
- `animation-direction-mismatch` — already on roadmap, confirmed real
- `d3-force-tuning` — needs a brief discussion before implementing (ask user: slider vs tweak vs both?)

---

## Pending flush

- [ ] `ROADMAP.md` — append new item `alerts-live-load-bug` to category "Housekeeping":
  <details>
  <summary>Detail block</summary>

  ### alerts-live-load-bug
  After uploading a capture file and waiting for it to process, the AlertsPanel shows an empty list. Alerts only appear after a full browser refresh. The backend `/api/alerts` endpoint is populated (store.alerts is set in `services/capture.py` after `run_all_detectors()`), so this is a frontend timing issue. Investigate: (a) whether `fetchAlerts()` is called inside `loadAll()` in `useCapture.js` after upload completes, (b) whether the alerts fetch is gated behind a state flag that doesn't update, (c) whether the AlertsPanel fetch fires too early (before `run_all_detectors` finishes) and has no retry or invalidation. Key file: `frontend/src/hooks/useCapture.js` — look at the `loadAll` sequence and any `useEffect` that triggers data fetches on capture load.
  `status: pending` · `priority: critical` · `term: short` · `effort: low` · `depends: none`
  </details>

- [ ] `ROADMAP.md` — append new item `detail-panel-polish` to category "Graph & Visualization":
  <details>
  <summary>Detail block</summary>

  ### detail-panel-polish
  The NodeDetail and EdgeDetail panel headers are too condensed — buttons overlap or feel cramped (see screenshot: "NODE DETAIL · ▶ Animate · 🚩 Flag · SCOPED · ALL · ×" all in one tight row). Two fixes: (1) **Remove the "Flag" text label** from the flag button — the red flag icon alone is sufficient and saves ~40px. The button currently renders as a pill with icon + text (`🚩 Flag`); drop the text, keep the icon + red color + tooltip. Pattern already exists in `SessionDetail.jsx` header — confirm consistency. (2) **Fix header layout** — review padding, gap, and flex alignment in `NodeDetail.jsx` and `EdgeDetail.jsx` header sections so the button row breathes. Do not change existing button order or functionality. Also check `SessionDetail.jsx` for the same condensation. Files: `frontend/src/components/NodeDetail.jsx`, `EdgeDetail.jsx`, `SessionDetail.jsx`.
  `status: pending` · `priority: high` · `term: short` · `effort: low` · `depends: none`
  </details>

- [ ] `ROADMAP.md` — append new item `timeline-graph-phase3` to category "Investigation & Events":
  <details>
  <summary>Detail block</summary>

  ### timeline-graph-phase3
  Two timeline graph polish items discovered after Phase 2 (v0.22.x) shipped: **(1) Drag-drop render bug** — dragging an event card from EventsPanel and dropping it onto the TimelineGraph SVG canvas places the node in state (via `placeEvent` / `placeEventOnTimeline` in `useEvents`) but the node does not visually appear until the user zooms or pans (which forces a DOM repaint). Root cause: the drop handler likely updates React state but the SVG `<g>` re-render is not triggered because d3.zoom transform is stored in a ref (`tRef`) rather than state — changing `useEvents` state alone doesn't force the transform-dependent elements to repaint. Fix: after calling `placeEvent` from the drop handler, either force a state tick (e.g. increment a `renderKey` counter in useState) or call `tRef.current` touch to trigger a re-render. File: `frontend/src/components/TimelineGraph.jsx` — drop handler. **(2) Click node → entity detail card** — clicking a placed event node on the timeline canvas should open a lightweight inline detail card (or populate the existing node/edge/session detail panel) showing a summary of the linked entity: for a `node` event, show the IP, top protocols, first_seen; for an `edge`, show src/dst/protocol/session count; for a `session`, show the session summary. Currently click only sets `selectedNode` state with no resulting UI. The detail card can reuse or summarise existing `NodeDetail`/`EdgeDetail`/`SessionDetail` components, or render a compact variant inside the timeline canvas below the selected node. Avoid opening the full right-panel detail (which would navigate away from Investigation).
  `status: pending` · `priority: high` · `term: short` · `effort: low` · `depends: none`
  </details>

- [ ] `ROADMAP.md` — append new item `d3-force-tuning` to category "Graph & Visualization":
  <details>
  <summary>Detail block</summary>

  ### d3-force-tuning
  User reports the main GraphCanvas D3 force simulation is still too strong — nodes are pushed apart too aggressively, making cluster structure hard to read. Current charge is `-200` (reduced from `-350` in v0.15.10 with a distanceMax-by-node-count heuristic). Before implementing: **discuss with user** whether the fix should be (a) reduce the charge constant further, (b) add a "Force strength" slider in the Graph Options panel so the user can tune it per-capture, or (c) tune `distanceMax` / `alphaDecay` instead of charge. The slider option is more flexible but adds UI complexity. Files: `frontend/src/components/GraphCanvas.jsx` — d3.forceManyBody() and forceLink() parameters. See also `HANDOFF.ai.md` constraints (visibleNodes/visibleEdges must stay memoized — don't change that invariant while tuning force params).
  `status: pending` · `priority: high` · `term: short` · `effort: low` · `depends: none`
  </details>

Flushed 2026-04-10 (v0.22.7 doc workflow fix):
- [x] `CHANGELOG.md` — added v0.21.2 + v0.22.0–v0.22.7 prose entries
- [x] `HANDOFF.md` — bumped version header to v0.22.7, added highlights for v0.21.2 and v0.22.x
- [x] `ROADMAP.md` — removed `timeline-graph-phase2` row + detail block; moved to `COMPLETED.md`
- [x] `HANDOFF.ai.md` — version bumped, doc sync rules table rewritten (merge-flush model)
- [x] `ROADMAP.ai.md` — version bumped, timeline-graph-phase2 + event-type-system marked done
- [x] `CLAUDE.md` — ground-truth check added, doc model updated to merge-flush
- [x] `~/.claude/commands/push.md` — feature branch push now defaults to merge-and-push

## Blocked on

- Nothing.
