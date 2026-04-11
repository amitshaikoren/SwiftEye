# Session State

**Last updated:** 2026-04-11 · **Current version:** v0.25.3
**Current branch:** refactor/animationpane-decomposition (not yet merged)
**Mirror sync state:** all mirrors current as of v0.25.2; CHANGELOG.ai.md updated to v0.25.3

> Live, per-session cache. Read first after `CLAUDE.md`.
> Write here during the session. Flush to human docs only at merge — not mid-session.

---

## Shipped this session

- v0.25.3 — AnimationPane.jsx decomposition. Split 1334-line monolith into 5 modules: `animationUtils.js` (131, already drafted on branch), `useAnimationCanvas.js` (357, zoom + fit + flash + RAF render loop), `useAnimationInteraction.js` (259, hit-test + drag + keyboard + popover dismiss), `AnimationHistoryPanel.jsx` (96, history panel + auto-scroll), `AnimationControlsBar.jsx` (265, transport + scrubber + options + sub-components). Coordinator 460 lines. Pure refactor, identical props API. Phase 3 item #4 complete.

- v0.25.2 — ResearchPage.jsx decomposition. Split 1443-line monolith into 4 modules: `customChartPersistence.js` (12), `CustomChartBuilder.jsx` (249), `PlacedCard.jsx` (611), `ResearchSlotBoard.jsx` (199). Coordinator ~384 lines. Pure refactor, identical props API. Phase 3 item #3 complete.

- v0.25.1 — GraphCanvas.jsx decomposition. Split 1665-line monolith into 4 hooks + 5 components + graphColorUtils. Coordinator ~170 lines. Shared refs declared in coordinator, passed to hooks. Pure refactor, identical props API. Phase 3 item #2 complete.

- v0.25.0 — useCapture.js decomposition. 5 domain slices + coordinator. Phase 3 item #1.

> Older entries (v0.24.x and below) trimmed — see `CHANGELOG.ai.md` for full history.

---

## Audit-driven work queue (priority over roadmap items)

Batch: `audits/codex_audits/2026-04-09/`. Each session covers one audit. Read companion from `claude/` subfolder first. After all audits are addressed, return to roadmap queue below.

| # | Audit | Status | Notes |
|---|---|---|---|
| 02 | code_readability / maintainability | **done** (v0.24.1–v0.25.2) | Backend fixes + frontend splits done. Remaining Phase 3 splits below. |
| 03 | computational_efficiency | **plan created** | Plan: `docs/plans/active/audit-03-computational-efficiency.md`. Not implemented yet. |
| 04 | storage_efficiency | **plan created** | Plan: `docs/plans/active/audit-04-storage-efficiency.md`. Not implemented yet. |
| 05 | architecture_principles | **plan created** | Plan: `docs/plans/active/audit-05-architecture-principles.md`. Not implemented yet. |
| 06 | ui_ux_accessibility | **plan created** | Plan: `docs/plans/active/audit-06-ui-ux-accessibility.md`. Not implemented yet. |
| 14 | directory_refactor | **plan created** | Plan: `docs/plans/active/audit-14-directory-refactor.md`. Phase 4 blocked on audit-02 Phase 3 splits. |

Second-pass files (07–13) are companions to the above — read alongside relevant audit.

**Execution order for next sessions:**
1. **Finish audit 02 first** — complete the remaining Phase 3 frontend splits. No recon pass needed for ResearchPage or SessionDetail — boundaries are obvious, Sonnet reads and splits in one session. For AnimationPane, read the file first and decide on the spot whether coupling warrants a recon doc or just split directly.
2. **Then** work through audits 03–06 and 14 using the plans in `docs/plans/active/`. All are Sonnet-level. Pick low-effort phases across audits first for quick wins.
3. **Audit 14 Phase 4** (component directory reorg) is blocked on step 1 — do it last.

**No audit requires Opus.** All plans are scoped for Sonnet.

**Rule for future sessions:** before picking up a roadmap item, check this table. If any audit row is "in progress" or "pending," continue it first. Mark "done" when changes are committed.

### Audit 02 — remaining Phase 3 frontend splits (not yet started)

These are the remaining large-file decompositions from audit 02 / second-pass hotspot 09. Items 1–3 are done; items 4–6 remain.

| Priority | Target | Split into | Status |
|---|---|---|---|
| 1 | `useCapture.js` | 5 domain slices + coordinator | ✅ Done (v0.25.0) |
| 2 | `GraphCanvas.jsx` | 4 hooks + 5 components + colorUtils | ✅ Done (v0.25.1) |
| 3 | `ResearchPage.jsx` | `ResearchPage` · `ResearchSlotBoard` · `PlacedCard` · `CustomChartBuilder` · persistence helpers | ✅ Done (v0.25.2) |
| 4 | `AnimationPane.jsx` | renderer · interaction · history/options · state adapters | ✅ Done (v0.25.3) |
| 5 | `SessionDetail.jsx` | packet loader hook · payload/stream viewers · charts panel | — |
| 6 | `App.jsx` | Defer — stable mess, low urgency | — |

---

## Do next (roadmap — after audit queue is cleared)

- `d3-force-tuning` — discuss slider vs constant tweak first
- `timeline-graph-multi-select-features` — box-select, protocol-select, bulk filter
- `timeline-to-research-gantt` — remove Timeline panel, move Gantt to Research
- `save-load-workspaces` — serialize annotations/synthetics/positions
- `subnet-node-visual-redesign` — subnets need distinct look

---

## Known issues (not fixed, not blocking)

- **Post-parse pipeline bottleneck** — `build_sessions + build_graph + plugins` ~20s for 440K packets. Roadmap: `post-parse-pipeline-opt`.
- **"Size by" graph option** — user considers it poor quality, needs review pass.
- **ICMPv6 dissector** — no raw fallback. Extra stays `{}`.
- **scapy DNS deprecation** — `dns.qd` → `dns.qd[0]`. 39K warnings per test run.
- **dpkt `IP.off` deprecation** — should use new field name.

## Deferred

- **Alerts Phase 2** — design complete in `docs/plans/active/ALERTS_PHASE2_PLAN.md`. Deprioritized.

---

## Blocked on

- Nothing.

---

## Pending ROADMAP.md flush

- [ ] `ROADMAP.md` — append new item `timeline-graph-multi-select-features` to category "Investigation & Events":
  <details>
  <summary>Detail block to insert</summary>

  ### timeline-graph-multi-select-features
  Extend the shift-select multi-selection already present in the timeline graph (v0.22.7) with additional selection modes and actions. Planned features: (1) box-select by dragging on the canvas background; (2) select-all-edges-by-protocol (right-click a protocol badge → "Select all [DNS]"); (3) a selection count/edge badge shown while multiple edges are selected; (4) a "Filter graph to selection" bulk action that scopes the main graph view to only the selected node pair(s). Key files: `InvestigationPage.jsx` (TimelineGraph host), `TimelineGraph.jsx` or equivalent component in `frontend/src/components/`. Multi-select state currently lives in `useCapture.js` timeline edge state — extending it should follow the existing `selectedEdgePair` pattern.
  `status: pending` · `priority: high` · `term: short` · `effort: medium` · `depends: timeline-graph-phase2`
  </details>

- [ ] `ROADMAP.md` — append new item `timeline-to-research-gantt` to category "Investigation & Events":
  <details>
  <summary>Detail block to insert</summary>

  ### timeline-to-research-gantt
  Remove the dedicated Timeline panel tab from the left-panel nav and move the session Gantt chart into the Research panel as a first-class chart entry (category: "session" or "capture"). The Timeline tab currently hosts `TimelinePanel.jsx` which renders the Gantt and the bucket-sec slider. At flush: (1) delete or repurpose `TimelinePanel.jsx` as a `ResearchChart` subclass in `backend/research/`; (2) remove the `timeline` nav entry from `LeftPanel.jsx` and `App.jsx`; (3) keep bucket-sec state in `useCapture.js` but only render the control inside the Research chart's filter bar. The `timeRange` / `setTimeRange` props used by other panels (sessions, stats, graph) must remain untouched — only the Gantt display moves. Confirm with user whether the timeline slider in the top bar should also be removed or kept.
  `status: pending` · `priority: medium` · `term: short` · `effort: medium` · `depends: none`
  </details>
