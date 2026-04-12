# Changelog — AI Reference

**Format:** `vX.Y.Z | YYYY-MM-DD | type | component | one-line summary`
**Types:** `feat` · `fix` · `refactor` · `perf` · `chore` · `docs`
**Source of truth:** `CHANGELOG.md`. Update both during the session; flush prose to `CHANGELOG.md` at session end.

**Grep recipes:**
- By version: `grep "v0.20" CHANGELOG.ai.md`
- By component: `grep "| animation |" CHANGELOG.ai.md`
- By type: `grep "| fix |" CHANGELOG.ai.md`

<!-- POLICY: Keep ~7 full-detail entries here. When adding a new entry, compress the
     oldest full entry down into the "Compressed history" section below as a one-liner. -->

---

## Log

v0.26.8 | 2026-04-12 | fix | backend/llm | Phase 1 bug fixes: (1) question_tags — self-referential questions ("my ip", "my computer") now set has_capture_ref=True, preventing mis-tag as background; add _CAPTURE_CONTEXT_MARKERS ("going on", "happening", etc.) for same; extend step-6 gate to proto-only tags so "what is DNS tunneling?" → mixed, not just dns; 5 new tests, all 31 pass; (2) prompts — is_small_model() detects sub-8B models via regex; _COMPACT_MODE_OVERRIDE injected into system prompt for small models (no preamble, ≤300 words); build_system_prompt gains model_name param; service.py passes request.provider.model through.
v0.26.7 | 2026-04-12 | feat | backend+frontend | llm-interpretation-panel Phase 1: POST /api/llm/chat (streaming NDJSON), POST /api/llm/context-preview (debug); backend/llm/ package — contracts, question_tags (12 types, deterministic rule-based), translators (field renaming+caps), context_builder (scope-aware retrieval), prompts (structured markdown output contract), service (orchestration), Ollama + OpenAI-compatible providers; LLMInterpretationPanel.jsx (scope selector, streaming transcript, tag badges, Explain quick action); useLlmChat.js hook; streamLlmChat in api.js; useSettings adds llmProvider+llmBaseUrl; SettingsPanel adds LLM provider section; AnalysisPage replaces placeholder with live panel; App.jsx passes filters+selection; 4 backend test files; build passes.
v0.26.6 | 2026-04-11 | refactor | backend+frontend | audit-05 P1: edge_fields.py registry drives edge accumulation+serialization (replaces 9 hardcoded extra-field blocks in aggregator.py); audit-04 P3: graph summary strips TLS/HTTP/DNS detail, adds has_tls/has_http/has_dns hints, new GET /api/edge/{id}/detail endpoint, EdgeDetail lazy-fetches on click; audit-05 P1 also: GET /api/meta/edge-fields + dynamic edgeFieldHints in useCaptureData; audit-03 P4: pre-built nodeIndex+sessionIndex useMemos reduce search cost per-keystroke to indexOf; audit-03 P5: React.lazy + Suspense for AnalysisPage, ResearchPage, AnimationPane (3 split chunks in dist); test_core updated for new edge shape.
v0.26.5 | 2026-04-11 | perf | frontend | audit-03 P3: session list virtualized with react-window FixedSizeList + ResizeObserver height tracking; audit-04 P2: storageKeys.js created — all localStorage keys centralized, 5 files updated (useSettings, customChartPersistence, NodeDetail, useCaptureLoad, PlacedCard); audit-14 P3: 50-file component reorg target mapping written; centrality backend plan at docs/plans/active/centrality-backend.md; audit-06 P3–P5 deferred to qa-test-suite.
v0.26.4 | 2026-04-11 | feat | frontend | audit-06 P1+P2 — left panel nav grouped into 4 sections (Data/Analysis/Workspace/Settings); project-wide font size floor: fontSize 7/8 → 9 minimum across ~20 component files; interactive buttons (LeftPanel All/None) lifted to 10px; BETA badge lifted to 9px.
v0.26.3 | 2026-04-11 | chore | backend | batch: audit-05 P3 discovery smoke tests (33 tests/33 pass across protocol_fields, adapters, research charts, alert detectors, insight/analysis plugins, frontend session_sections); requirements.txt — plotly promoted to required, sqlglot + pytest added; audit-04 P1 state lifetime §16 in docs/DEVELOPERS.md; graceful-optional-deps added to roadmap.
v0.26.2 | 2026-04-11 | docs | architecture | audit-05 Phase 2 — add Philosophy exceptions section to ARCHITECTURE.ai.md; documents 4 intentional trade-offs (edge caps, client-side centrality, localStorage chart configs, frontend search hint hardcoding) with why/when-to-revisit context.
v0.26.1 | 2026-04-11 | perf | frontend | audit-03 Phase 2 — merge E4+E5 in useCaptureData.js into a single Promise.all effect; sessions + stats now batch-setState on time-range change (2 renders → 1). E7 (graph) kept separate — different dep set (protocol/subnet filters).
v0.26.0 | 2026-04-11 | refactor | project | audit-14 Phase 1+2 — rename `tests/` → `captures/` (pcap data ≠ test code); update path refs in test_core.py + test_dpkt_parity.py; rewrite `.gitignore` with labeled sections (Python / Node / project state / private docs / captures / audits / IDE / runtime / legacy).
v0.25.4 | 2026-04-11 | refactor | frontend | SessionDetail + App decomposition — SessionDetail (948→660 lines) extracts SeqAckChart.jsx (98), StreamView.jsx (149), useSessionPackets.js (40). App (941→680 lines) extracts AppUploadScreen.jsx (103), AppRightPanel.jsx (196). Phase 3 items #5 + #6 complete.
v0.25.3 | 2026-04-11 | refactor | frontend | AnimationPane decomposition — 1334-line monolith → animationUtils.js (131), useAnimationCanvas.js (357), useAnimationInteraction.js (259), AnimationHistoryPanel.jsx (96), AnimationControlsBar.jsx (265); coordinator 460 lines. Phase 3 item #4 complete.
v0.25.2 | 2026-04-11 | refactor | frontend | ResearchPage decomposition — 1443-line monolith → customChartPersistence.js, CustomChartBuilder.jsx, PlacedCard.jsx, ResearchSlotBoard.jsx; coordinator ~384 lines. Phase 3 item #3 complete.

---

## Compressed history

v0.25.1 | 2026-04-11 | refactor | frontend | GraphCanvas decomposition: 4 hooks + 5 components + graphColorUtils.js; coordinator ~170 lines. Phase 3 item #2 complete.
v0.25.0 | 2026-04-11 | refactor | frontend | useCapture decomposition: 5 domain slices + coordinator; identical return shape, zero API change. Phase 3 item #1 complete.
v0.24.2 | 2026-04-10 | refactor | backend | audit-02 phase 2: session_match.py extraction, consolidate filter_packets, edge-cap view-layer comments.
v0.24.1 | 2026-04-10 | fix | backend | audit-02 phase 1: duplicate import, bucket-cap comment drift, sort field mismatch in memory.py.
v0.24.0 | 2026-04-10 | fix | multi | QOL batch: alerts-live-load-bug, schema-dialog-in-app, manual-type-override, detail-panel-polish, animation-direction-mismatch, timeline drag-render.
v0.23.0 | 2026-04-10 | feat | adapters | adapter-schema-negotiation: two-phase upload, SchemaDialog.jsx, schema/ package, 25 backend tests.
v0.22.0–v0.22.7 | 2026-04-10 | feat | timeline-graph | 8 incremental features: zoom+pan, reject-suggestion, layout persistence, entity color coding, back breadcrumb, view-in-graph highlight, parallel arcs, shift-select operations popover.
v0.21.0–v0.21.2 | 2026-04-09 | feat | events | event-type-system phase 1: useEvents, EventFlagModal, EventsPanel, TimelineGraph SVG canvas, Flag-as-Event throughout, InvestigationPage tabs.
v0.20.0–v0.20.4 | 2026-04-08–09 | feat | edges | directional edges, cross-refs, AnalysisContext lazy maps, session↔edge canonical matching, animation isolate rescue.
v0.19.0 | 2026-04-07 | feat | alerts | AlertsPanel + AlertPluginBase, 4 detectors (ARP spoofing, suspicious UA, malicious JA3, port scan).
v0.18.0 | 2026-04-06 | feat | animation | node temporal animation: replay phase 1 + phase 2 (focused filter, draggable nodes, context menu, bulk hide).
v0.17.0 | 2026-04-05 | refactor | parser | unified dpkt reader, l5_dispatch.py, parallel_reader.py, 2 GB cap, full PacketRecord fields.
v0.16.0 | 2026-04-05 | feat | storage | StorageBackend ABC + MemoryBackend: O(1) packet/session/time-bucket lookups; session_detail 50 K packet limit.
v0.15.1–v0.15.28 | 2026-03-28–04-04 | feat | multi | ResearchPage DnD redesign, custom charts, FilterContext, TCP stream follow, query parse endpoint (47 tests), GraphOptionsPanel, export HTML, subnet visual redesign, per-packet header detail.

---

## Older versions
For v0.14.x and earlier, grep `CHANGELOG.md` directly.
