# SwiftEye — Completed Roadmap Items

> Items that shipped and are no longer in active development. Kept for dependency tracing.
> When an item is done: move its table row and detail block from `ROADMAP.md` here.

---

## Shipped

| ID | Shipped | Notes |
|----|---------|-------|
| `timeline-graph-phase2` | v0.22.0–v0.22.7 (2026-04-10) | All 8 items done. See detail block below. |
| `event-type-system` | v0.21.0+v0.21.1 (2026-04-09) | Phase 1 done. Phase 2 tracked as `event-suggested-edges-pluggable`. |

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

First-class flagged-event primitive for threat-hunt narratives. Phase 1 shipped across v0.21.0 (core) and v0.21.1 (polish). Full Opus design plan: `docs/plans/event-type-system.md`.

Phase 1 shipped: `useEvents` hook, `EventFlagModal`, `EventsPanel` + `EventCard`, `TimelineGraph` SVG canvas, `InvestigationPage` tab bar, ref-chip drag-to-insert in markdown editor, `GraphCanvas` indicator dots + context menu, `SessionDetail`/`EdgeDetail`/`NodeDetail` Flag buttons.

Phase 2 deferred: backend persistence (workspace save), pluggable suggested-edge logic (see `event-suggested-edges-pluggable`), Phenomena templates (needs real-usage data), edge-label edit in TimelineGraph.
