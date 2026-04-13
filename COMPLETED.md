# SwiftEye — Completed Roadmap Items

> Items that shipped and are no longer in active development. Kept for dependency tracing.
> When an item is done: move its table row and detail block from `ROADMAP.md` here.

---

## Shipped

| ID | Shipped | Notes |
|----|---------|-------|
| `timeline-graph-phase2` | v0.22.0–v0.22.7 (2026-04-10) | All 8 items done. See detail block below. |
| `event-type-system` | v0.21.0+v0.21.1 (2026-04-09) | Phase 1 done. Phase 2 tracked as `event-suggested-edges-pluggable`. |
| `adapter-schema-negotiation` | v0.23.0 (2026-04-10) | Two-phase upload + `backend/parser/schema/` package + `SchemaDialog.jsx`. |
| `alerts-live-load-bug` | v0.24.0 (2026-04-10) | Re-fetch after first graph response; alerts panel no longer empty post-upload. |
| `detail-panel-polish` | v0.24.0 (2026-04-10) | Flag buttons icon-only; header padding/flex fixed in NodeDetail, EdgeDetail, SessionDetail. |
| `schema-dialog-in-app` | v0.24.0 (2026-04-10) | SchemaDialog renders inside the app after upload, not only from the landing screen. |
| `manual-type-override` | v0.24.0 (2026-04-10) | TypePickerDialog lets user declare adapter type when auto-detection fails. |
| `animation-direction-mismatch` | v0.24.0 (2026-04-10) | Animation pane uses `initiator_ip`/`responder_ip` (edge source/target) for direction. |
| `timeline-graph-phase3` | v0.24.0 (2026-04-10) | Drag-drop render bug fixed (`setTick` on pointer move); node click shows inline detail card. |
| `timeline-to-research-gantt` | v0.27.5 (2026-04-13) | Timeline panel removed from left-nav; session Gantt chart moved into Research panel. |
| `animation-pane-timeline-sync` | v0.27.2 (2026-04-12) | Orange tick cursor on TimelineStrip tracks the current animation frame's capture-relative position. |

---

### timeline-graph-phase2

Phase 2 batch of Timeline Graph UX improvements, all descending from v0.21.0 Phase 1 (`event-type-system`). All 8 items shipped across v0.22.0–v0.22.7 on `main`.

| Item | Shipped |
|------|---------|
| Zoom + pan canvas (d3.zoom, `scaleExtent [0.3,3]`, `canvasPoint()` inversion) | v0.22.0 |
| Reject → removes suggested edge (`rejectedSuggestions` Set in `useEvents`) | v0.22.1 |
| Layout persistence (lift `rulerOn` to `useEvents`, lock `fx`/`fy`, stop sim) | v0.22.2 |
| Entity color coding + legend (node blue, edge purple, session green, ~13% alpha) | v0.22.3 |
| Show-in-graph highlight (reused `queryHighlight`, panel-switch-first ordering) | v0.22.4 |
| Back-to-investigation breadcrumb (lifted `tab` state, `returnToInvestigationTab`) | v0.22.5 |
| Multi-edge parallel arcs (`pairOffsets` memo, `arcPath` helper, 22px offset) | v0.22.6 |
| Shift-select → operations popover (Draw edge / Clear, screen-anchored to midpoint) | v0.22.7 |

(Originally also bundled "Flag button in all detail panel headers" — completed early in v0.21.1 as `ui-events-polish`.)

---

### event-type-system

First-class flagged-event primitive for threat-hunt narratives. Phase 1 shipped across v0.21.0 (core) and v0.21.1 (polish). Full Opus design plan: `docs/plans/archive/event-type-system.md`.

Phase 1 shipped: `useEvents` hook, `EventFlagModal`, `EventsPanel` + `EventCard`, `TimelineGraph` SVG canvas, `InvestigationPage` tab bar, ref-chip drag-to-insert in markdown editor, `GraphCanvas` indicator dots + context menu, `SessionDetail`/`EdgeDetail`/`NodeDetail` Flag buttons.

Phase 2 deferred: backend persistence (workspace save), pluggable suggested-edge logic (see `event-suggested-edges-pluggable`), Phenomena templates (needs real-usage data), edge-label edit in TimelineGraph.

---

### adapter-schema-negotiation
Shipped v0.23.0. New `backend/parser/schema/` package (contracts, inspector, staging) sits as its own layer before any adapter. All Zeek adapters (conn, dns, http, ssl, smb_files, smb_mapping, dce_rpc) and tshark metadata adapter now declare `declared_fields` and implement `get_header_columns()` / `get_raw_rows()` / `_rows_to_packets()` / `parse_with_mapping(mapping)`. Upload is two-phase: detect adapter → inspect schema → if clean proceed; if mismatch, stage the file (UUID token), return `schema_negotiation_required: true` + `schema_report` + `staging_token`. `POST /api/upload/confirm-schema` accepts confirmed mapping → `parse_with_mapping` → full ingest. Frontend: `SchemaDialog.jsx` renders detected-vs-expected columns as a mapping table with dropdowns, required-field warnings, suggested-mapping pre-population, and Confirm & Ingest button disabled until all required fields are mapped. Detection made format-based: Zeek conn is a catch-all (checked last, requires only `#fields` marker, no extension required); tshark metadata is a catch-all (checked last, requires `.csv` + tab-separated first line with ≥15 columns). 25 backend tests.
`status: done` · `shipped: v0.23.0`

---

### alerts-live-load-bug
Alerts panel was empty after file upload and only populated after a manual browser refresh. Root cause: `fetchAlerts()` was not called in the `loadAll()` sequence after `run_all_detectors()` completed. Fixed by re-fetching alerts at the end of the graph-load sequence.
`status: done` · `shipped: v0.24.0`

---

### detail-panel-polish
NodeDetail, EdgeDetail, and SessionDetail flag buttons reduced to icon-only (removed the "Flag" text label). Header padding and flex layout fixed for all three panels.
`status: done` · `shipped: v0.24.0`

---

### schema-dialog-in-app
`SchemaDialog` was only rendered in the landing-screen path in `App.jsx`. When the user uploaded a new file from inside the app, the dialog never appeared even if schema negotiation was triggered. Fixed by wiring `schemaNegotiation` state and `<SchemaDialog>` into the in-app upload path.
`status: done` · `shipped: v0.24.0`

---

### manual-type-override
When file detection failed with "Unsupported file type", the user saw a hard error with no recovery path. Added `TypePickerDialog` — a fallback UI that lets the user declare the adapter type (Zeek conn.log, tshark metadata CSV, etc.). The declared adapter is passed as `force_adapter` to the backend, which then proceeds with schema inspection and mapping as normal.
`status: done` · `shipped: v0.24.0`

---

### animation-direction-mismatch
The animation pane was computing edge direction independently from the edge data model, causing mismatches with `EdgeDetail` and `SessionDetail`. Fixed by deriving direction exclusively from `edge["source"]` / `edge["target"]` (i.e. `initiator_ip` / `responder_ip`) set by the v0.20.0 directional edge refactor.
`status: done` · `shipped: v0.24.0`

---

### timeline-graph-phase3
Two issues: (1) Drag-drop render bug — dragged nodes did not move visually until a zoom/pan event fired. Fixed by calling `setTick(t => t+1)` in `onNodePointerMove` to force a re-render on every drag frame. (2) Click node → inline detail card — already present since v0.22.x via the `selectedNodeObj` card mechanism.
`status: done` · `shipped: v0.24.0`

---

### timeline-to-research-gantt
Removed the standalone Timeline panel tab from the left-nav (`LeftPanel.jsx`, `App.jsx`). The session Gantt chart (`session_gantt`) is now enabled as a first-class chart in the Research panel. Bucket-sec slider state remains in `useCapture.js`; `timeRange`/`setTimeRange` props on other panels are unchanged.
`status: done` · `shipped: v0.27.5`

---

### animation-pane-timeline-sync
An orange tick cursor on the `TimelineStrip` component now tracks the current animation frame's capture-relative timestamp. The cursor accounts for the gap-split layout (fixed-pixel gap segments + proportional time segments). Frontend-only change in `TimelineStrip.jsx`; frame timestamp threaded from `useAnimationMode` via `App.jsx`.
`status: done` · `shipped: v0.27.2`
