# Session State

**Last updated:** 2026-04-13 · **Current version:** v0.27.5
**Current branch:** main
**Mirror sync state:** All mirrors current at v0.27.5. Merged and flushed.

> Live, per-session cache. Read first after `CLAUDE.md`.
> Write here during the session. Flush to human docs only at merge — not mid-session.

---

## Shipped this session (branch feat/quick-wins-batch1)

> Keep max 3 entries. Drop the oldest when adding a new one. Full history in `CHANGELOG.ai.md`.

- v0.27.5 — 6 bug fixes: investigation timeline nodes now show immediately after drag-drop; timeline nodes/edges fully editable (label, color via swatch picker, annotation, node severity); edge hover tooltips; session detail flag button icon-only; EventFlagModal resolves d3-mutated source/target to IDs; session title shows {ip}--proto→{ip}; Timeline panel removed from nav, session_gantt re-enabled in Research.
- v0.27.3 — rebuild fix: sticky header CSS (flex chain, no height:100%); LLM settings moved into LLM panel inline (⚙ toggle); dist now includes all v0.27.2 changes.
- v0.27.2 — quick-wins batch: logo home button fix (switchPanel not clearAll); graceful plotly/sqlglot fallback; SessionDetail sticky header; EdgeDetail port pairs display; d3 force sim tuning (charge -280→-180, alphaDecay 0.025, link distance 160→130); animation back-button breadcrumb in right panel; timeline strip animation frame cursor; animation node position persistence across panel switches.
- v0.27.1 — server-side LLM key store (GET/POST /api/llm/keys, llm_keys.json, key injection in chat handler); LLM section in DEVELOPERS.md (§17: packages, tags, providers, wire format, testing); left-panel category labels removed (flat list); quick-wins roadmap table in SESSION.md.
- v0.27.0 — version bump to minor
- v0.26.8 — Phase 1 bug fixes: self-ref capture markers + capture-context markers + proto-only step-6 gate in question_tags.py; is_small_model() + compact-mode prompt override in prompts.py; model_name wired through service.py. 31/31 tests pass.
- v0.26.7 — LLM interpretation panel Phase 1: POST /api/llm/chat (streaming NDJSON), context-preview debug endpoint, backend/llm/ package (question_tags, translators, context_builder, prompts, service, Ollama+OpenAI providers), LLMInterpretationPanel.jsx (scope selector, streaming transcript, tag badges), useLlmChat.js, settings extended, AnalysisPage placeholder replaced, 4 test files.
- v0.26.6 — Audit-05 P1+P2+P3 done; Audit-04 P3 done; Audit-03 P4+P5 done. Edge field registry (`edge_fields.py`), lazy edge detail (`/api/edge/{id}/detail`), pre-indexed search, React.lazy panels, boolean edge hints (has_tls/has_http/has_dns).

---

## Audit-driven work queue (deprioritised — deferred until after LLM phases)

Batch: `audits/codex_audits/2026-04-09/`. Each session covers one audit. Read companion from `claude/` subfolder first.

| # | Audit | Status | Notes |
|---|---|---|---|
| 02 | code_readability / maintainability | **done** (v0.24.1–v0.25.4) | All Phase 3 frontend splits complete. |
| 03 | computational_efficiency | **deferred** | P1 deferred (centrality, plan: `docs/plans/active/centrality-backend.md`). P2–P5 done (v0.26.5/v0.26.6). |
| 04 | storage_efficiency | **deferred** | P1–P3 done. Remaining: P4 (memory monitoring). Plan: `docs/plans/active/audit-04-storage-efficiency.md`. |
| 05 | architecture_principles | **done** (v0.26.3/v0.26.6) | P1+P2+P3 all done. `edge_fields.py` registry ships. |
| 06 | ui_ux_accessibility | **deferred** | P3–P5 added to `qa-test-suite` checklist. Plan: `docs/plans/active/audit-06-ui-ux-accessibility.md`. |
| 14 | directory_refactor | **deferred** | P4 (execute reorg) high churn — do last, after LLM work settles. |

Second-pass files (07–13) are companions to the above — read alongside relevant audit.

### Deferred audit items (resume after LLM Phase 2 + 3)

| Priority | Audit | Phase | What | Effort |
|---|---|---|---|---|
| 1 | 04 | P4 | Memory pressure monitoring (`/api/status/memory` + status bar indicator) | low |
| 2 | 03 | P1 | Client-side centrality → backend endpoint | medium, plan: `docs/plans/active/centrality-backend.md` |
| — | 14 | P4 | Execute component reorg | **do last** — high churn |

---

## Do next

1. **Graph direction viz** (`graph-direction-viz`) — show traffic direction on edges (particles / arrowheads / color-coding). **Toggleable, default OFF, wired into Graph Options panel.**
2. **Graph legend sync** (`graph-legend-sync`) — canvas legend updates to reflect active color mode (node color by OS/role, edge color by protocol etc.).
3. **Export HTML enriched hover** (`export-html-enriched-hover`) — richer hover tooltips in exported HTML (bytes in/out, packet count, session count, top protocols on nodes; session count, protocol list, duration on edges).
4. **Docs audit** (`docs-audit`) — focus on `docs/DEVELOPERS.md` first (API tables, LLM section, route list). Then HANDOFF.md §2 (directory tree), README feature list.
5. **LLM Phase 2 — Sonnet.** Branch: `feat/llm-phase2`. Plan: `docs/plans/active/llm-interpretation-phase2-3.md § Phase 2`.
   Order: 2.2 (conversation history) → 2.3 (protocol translators) → 2.4 (source-type awareness) → 2.5 (adaptive budgeting).
6. **LLM Phase 3 — mixed.** New branch: `feat/llm-phase3`. Plan § Phase 3.
   - 3.1 tool-use loop → **Opus** (architectural change to service loop + provider layer)
   - 3.2 report mode + 3.3 payload inspection → Sonnet once 3.1 is stable

---

## LLM panel — observed issues

- **Both answers could be one line** — context packet probably has enough info; issue is prompt verbosity instructions + small model compliance. Compact-mode override added (v0.26.8) — retest with qwen2.5:3b after merge.

---

## Known issues (not fixed, not blocking)

- **Post-parse pipeline bottleneck** — `build_sessions + build_graph + plugins` ~20s for 440K packets. Roadmap: `post-parse-pipeline-opt`.
- **"Size by" graph option** — user considers it poor quality, needs review pass.
- **ICMPv6 dissector** — no raw fallback. Extra stays `{}`.
- **scapy DNS deprecation** — `dns.qd` → `dns.qd[0]`. 39K warnings per test run.
- **dpkt `IP.off` deprecation** — should use new field name.

## Deferred

- **Alerts Phase 2** — design complete in `docs/plans/active/ALERTS_PHASE2_PLAN.md`. Deprioritized.
- **Centrality backend migration** — plan at `docs/plans/active/centrality-backend.md`. Not urgent.

---

## Blocked on

- Nothing.

---
