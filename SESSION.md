# Session State

**Last updated:** 2026-04-11 · **Current version:** v0.25.4
**Current branch:** main
**Mirror sync state:** all mirrors current as of v0.25.4 (merged)

> Live, per-session cache. Read first after `CLAUDE.md`.
> Write here during the session. Flush to human docs only at merge — not mid-session.

---

## Shipped this session

> Keep max 3 entries. Drop the oldest when adding a new one. Full history in `CHANGELOG.ai.md`.

- v0.25.4 — SessionDetail + App decomposition. Merged to main. All 6 audit-02 Phase 3 splits done. Audit 14 + 03 work started on new branch.
- v0.25.3 — AnimationPane.jsx decomposition. Split 1334-line monolith into 5 modules: `animationUtils.js` (131), `useAnimationCanvas.js` (357, zoom + fit + flash + RAF render loop), `useAnimationInteraction.js` (259, hit-test + drag + keyboard + popover dismiss), `AnimationHistoryPanel.jsx` (96), `AnimationControlsBar.jsx` (265, transport + scrubber + options + sub-components). Coordinator 460 lines. Phase 3 item #4 complete.

---

## Audit-driven work queue (priority over roadmap items)

Batch: `audits/codex_audits/2026-04-09/`. Each session covers one audit. Read companion from `claude/` subfolder first. After all audits are addressed, return to roadmap queue below.

| # | Audit | Status | Notes |
|---|---|---|---|
| 02 | code_readability / maintainability | **done** (v0.24.1–v0.25.4) | All Phase 3 frontend splits complete. |
| 03 | computational_efficiency | **in progress** | Plan: `docs/plans/active/audit-03-computational-efficiency.md`. Phase 2 started. |
| 04 | storage_efficiency | **plan created** | Plan: `docs/plans/active/audit-04-storage-efficiency.md`. Not implemented yet. |
| 05 | architecture_principles | **plan created** | Plan: `docs/plans/active/audit-05-architecture-principles.md`. Not implemented yet. |
| 06 | ui_ux_accessibility | **plan created** | Plan: `docs/plans/active/audit-06-ui-ux-accessibility.md`. Not implemented yet. |
| 14 | directory_refactor | **in progress** | Plan: `docs/plans/active/audit-14-directory-refactor.md`. Phase 1+2 started. |

Second-pass files (07–13) are companions to the above — read alongside relevant audit.

**Execution order:** pick low-effort phases across audits first for quick wins. Audit 14 Phase 3 (component reorg) unblocked now that all Phase 3 splits are done.

**No audit requires Opus.** All plans are scoped for Sonnet.

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

