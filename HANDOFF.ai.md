# HANDOFF — AI Reference

**v0.25.0 | 2026-04-11** · Source of truth: `HANDOFF.md` (human, gitignored). Mirrors main state only — branch-local work is not reflected until after merge.

---

## Git rules

| Rule | Value |
|------|-------|
| Branch pattern | `feat/xxx`, `fix/xxx`, `refactor/xxx` |
| Push to main | Never directly. Branch + user merges after testing. |
| Doc-only changes | May go straight to main. |
| Commit style | One line: `vX.Y.Z: short summary`. **No `Co-Authored-By`.** |
| Version bump | Before every commit. `frontend/src/version.js` is the only place. |
| Force/no-verify | Never. Diagnose root cause. |

---

## Doc sync rules (docs-second / merge-flush model)

**Hard rules:**
- Mirrors (`*.ai.md`) reflect **main state only**. Do not update mirror version headers or roadmap status for branch-local work.
- `SESSION.md` is the branch-local scratchpad. Write freely. It is not authoritative about what is on main.
- Flush to human docs happens **at or after merge to main**, not mid-session.
- **Never read** `HANDOFF.md`, `CHANGELOG.md`, `ROADMAP.md`, `docs/DEVELOPERS.md` directly during a session unless the `.ai.md` mirror points you at a specific section.

**Session start:** run `git log --oneline main -3` and compare the top version to `CHANGELOG.ai.md`'s top entry. If they differ, note "mirrors stale since vX.Y.Z" in `SESSION.md` and proceed — mirrors are stale but valid. Do not panic; do not flush before doing any work.

**Per-operation cost (what to touch):**

| When | Touch immediately | Touch at merge-flush |
|---|---|---|
| Any feature / fix committed | `SESSION.md` (log) + `CHANGELOG.ai.md` (one line) | — |
| Architecture constraint added/changed | `HANDOFF.ai.md` (that row only) | `HANDOFF.md` |
| API endpoint added/changed | `DEVELOPERS.ai.md` (that row only) | `docs/DEVELOPERS.md` |
| Roadmap item added | `ROADMAP.ai.md` (add row) + `SESSION.md` (stash detail block for flush) | `ROADMAP.md` |
| Roadmap item: pending → in-progress | `ROADMAP.ai.md` (status cell only) | — |
| Branch merges to main (merge-flush) | Bump all stale `.ai.md` version headers · Mark done items in `ROADMAP.ai.md` | `CHANGELOG.md` · `HANDOFF.md` · `ROADMAP.md` · move done items to `COMPLETED.md` |

**Normal feature work = 2 files touched**: `SESSION.md` + `CHANGELOG.ai.md`. All other mirrors update only when their specific table content changes or at merge-flush.

---

## Change checklists

### Adding a new protocol (port-based)
- [ ] `backend/constants.py` — `WELL_KNOWN_PORTS` (port→name)
- [ ] `backend/constants.py` — `PROTOCOL_COLORS` (name→hex)
- [ ] `frontend/src/components/FilterBar.jsx` — `FIELD_SUGGESTIONS`
- [ ] `SESSION.md` log → flush to `HANDOFF.md` + `CHANGELOG.md`

### Adding payload signature detection
- All steps above
- [ ] `backend/parser/protocols/signatures.py` — `@register_payload_signature("MY_PROTO", priority=N)`
- Priority guide: 10–15 magic bytes · 20–30 banner · 40–60 heuristic

### Adding a protocol dissector
- All steps from "Adding a new protocol"
- [ ] `backend/parser/protocols/dissect_<n>.py` — `@register_dissector("MY_PROTO")` returning extra dict
- [ ] `backend/parser/protocols/__init__.py` — `from . import dissect_<n>  # noqa: F401`
- [ ] `backend/analysis/protocol_fields/<n>.py` — `init()`, `accumulate(s, ex, is_fwd, source_type)`, `serialize(s)` (auto-discovered)
- [ ] If new `pkt.extra` keys should appear in EdgeDetail → collect in `aggregator.py build_graph()`
- [ ] If those fields go in display filter → `frontend/src/displayFilter.js` FIELDS + eval functions
- [ ] If autocomplete → `FilterBar.jsx FIELD_SUGGESTIONS`
- Note: since v0.17.0, dissectors receive scapy L5 objects from `l5_dispatch.py`. `pkt.haslayer(DNS)` works.

### Adding an HTTPS variant (keep TLS fingerprinting working)
- [ ] `backend/parser/l5_dispatch.py` — add to `_TLS_PROTOCOLS` (single source of truth since v0.17.0)

### Adding a Graph Options toggle (reshapes graph build → triggers re-fetch)
- [ ] `frontend/src/hooks/useCapture.js` — `useState` + setter
- [ ] `frontend/src/hooks/useCapture.js` — pass to graph fetch `useEffect` + dependency array
- [ ] `frontend/src/api.js fetchGraph()` — `URLSearchParams`
- [ ] `frontend/src/components/LeftPanel.jsx` — toggle in Graph Options section
- [ ] `frontend/src/App.jsx` — pass `c.myToggle`/`c.setMyToggle` to LeftPanel
- [ ] `backend/server.py /api/graph` — `Query` param
- [ ] `backend/analysis/aggregator.py build_graph()` — implement
- [ ] `SESSION.md` log → flush

### Adding a backend filter (narrows packets, doesn't reshape)
- [ ] `backend/analysis/aggregator.py filter_packets()` — single source of truth
- [ ] `backend/analysis/aggregator.py build_graph()` — pass through
- [ ] `backend/server.py /api/graph` — `Query` param
- [ ] `frontend/src/hooks/useCapture.js` — state + dep array
- [ ] `frontend/src/api.js fetchGraph()` — URLSearchParams

### Adding an insight plugin
- [ ] `backend/plugins/insights/my_plugin.py` — subclass `PluginBase`, implement `get_ui_slots()` + `analyze_global()`
- [ ] `backend/server.py _register_plugins()` — add `("plugins.insights.my_plugin", "MyPlugin")`
- [ ] If per-node IP→data: update `NodeDetail.jsx` to slice global result by current node
- [ ] If adds flat node field (like `os_guess`): update `_enrich_nodes_with_plugins()`, `displayFilter.js`, `FilterBar.jsx FIELD_SUGGESTIONS`

### Adding a graph-wide analysis plugin
- [ ] `backend/plugins/analyses/my_analysis.py` — subclass `AnalysisPluginBase`, `compute(ctx)` returning `_display`
- [ ] `backend/server.py _register_analyses()` — add row
- No frontend changes — Analysis page renders generically from `_display`

### Adding a research chart
- [ ] `backend/research/my_chart.py` — subclass `ResearchChart`, implement `compute()` (or `build_data()`+`build_figure()`), call `fig.update_layout(SWIFTEYE_LAYOUT)`
- [ ] `backend/server.py _register_charts()` — add row
- Use `build_data() + build_figure()` split for per-chart filters (since v0.15.26)

### Adding a new API endpoint
- [ ] `backend/server.py` — route function + `_require_capture()` decision (rule below)
- [ ] `backend/models.py` — Pydantic model if response shape is non-trivial
- [ ] `frontend/src/api.js` — fetch function

**`_require_capture()` rule:**
- **Add it** if endpoint reads `store.packets/sessions/stats/time_buckets/protocols/subnets/annotations/synthetic/metadata_map`
- **Don't add** if it reads only static startup data (plugin/chart registrations, log buffer)

**`.catch()` rule:**
- **Add `.catch(() => fallback)`** only when endpoint has `_require_capture()` AND it's called at capture-load time in `loadAll()`
- **Don't add** if no guard — errors should surface

### Adding an alert detector
- [ ] `backend/plugins/alerts/my_detector.py` — subclass `AlertPluginBase`, `detect(ctx) → List[AlertRecord]`
- [ ] `backend/server.py` detector registration block — add row
- No frontend changes — AlertsPanel renders generically from `AlertRecord`

### Adding a display filter field
- [ ] `frontend/src/displayFilter.js` — add to `FIELDS` set
- [ ] `frontend/src/displayFilter.js` — `case` in `evalNodePred()` and/or `evalEdgePred()`
- [ ] `frontend/src/components/FilterBar.jsx` — `FIELD_SUGGESTIONS` + help table

---

## Architecture constraints (MUST NOT VIOLATE)

| Constraint | Why / Where |
|---|---|
| `visibleNodes`/`visibleEdges` MUST be `useMemo`-ed in `useCapture.js` | Inline `.filter()` in JSX restarts D3 sim every render |
| `_require_capture()` only on per-capture endpoints | Static endpoints must work before any upload |
| `store.annotations/synthetic/metadata_map` cleared on `store.load()` | Per-capture state, not global |
| `VERSION` lives only in `frontend/src/version.js` | Imported elsewhere; never duplicate |
| All state/logic in `useCapture.js`; `App.jsx` is pure layout | God hook is intentional for now (decomp on roadmap) |
| Docs-second flush before merge | `SESSION.md` must be flushed before main merge |
| `mac_vendors` derived as `[lookup_vendor(mac) for mac in sorted(n["macs"])]` at serialization | Parallel to `macs`, not stored |
| IPv6 filter in `build_graph` checks resolved IPs when `entity_map` active | Otherwise dual-stack hosts misfilter |
| **No imports inside functions.** Hoist all imports to module level. | 6× parse slowdown discovered v0.15.11–15.13. Optional deps use module-level `try/except` with `_NAME = None` fallback. |
| **No business logic in `routes/`** | Routes orchestrate; logic lives in `services/` or domain modules |
| `aggregator.py` no new hardcoded protocol field names | Use generic `extra` collection — see HANDOFF §8 coupling problem 1 |
| Frontend changes → run `cd frontend && npm run build` | Don't leave it to user |

---

## Core principles (philosophy)

| Principle | One-line |
|---|---|
| **Viewer, not analyzer** | Core shows what's in the data. Researchers bring expertise. Display→core viewer. Correlation/inference→plugin. |
| **Zero data loss** | Aggregation adds zoom levels, never replaces raw. Drill from aggregate → packets → bytes always works. |
| **Simple obvious; hard possible** | Common case (load + explore) requires zero config. Advanced case (query lang, plugins) is available + powerful. |
| **Four layers, strict boundaries** | parser → data → plugins → research. See `ARCHITECTURE.ai.md`. |
| **Auto-discovery patterns** | Drop a file in the right dir and it works. Dissectors, protocol_fields, session_sections, charts, adapters. |
| **Graph data is never mutated by view options** | Backend returns metadata; frontend does visual collapse. Toggle off = instant, no API call. |

---

## Auto-discovery patterns

| Drop a file in... | And it... | Registration |
|---|---|---|
| `backend/parser/protocols/dissect_*.py` | Becomes a dissector | Add `from . import dissect_<n>` to `protocols/__init__.py` |
| `backend/analysis/protocol_fields/*.py` | Adds session fields | None — auto-discovered |
| `frontend/src/components/session_sections/*.jsx` | Adds a section to SessionDetail | None — Vite `import.meta.glob` |
| `backend/research/*.py` | Adds a research chart | Register in `server.py _register_charts()` |
| `backend/parser/adapters/*.py` | Adds an ingestion adapter | `@register_adapter` decorator |

---

## Known coupling points (HANDOFF §8)

| # | Coupling | Don't make worse |
|---|---|---|
| 1 | `aggregator.py` hardcodes protocol field names on edges | Use generic `extra` collection — don't add new hardcoded names |
| 2 | Frontend has dedicated session sections; fallback handles unknowns | Don't add protocol-specific UI bypassing auto-discovery |
| 3 | `useCapture.js` is a god hook (~970 lines) | Don't add state without considering a sub-hook (decomp on roadmap as `usecapture-decomposition`) |
| 4 | `server.py` was split into `routes/` modules in v0.15.5 | Don't add business logic back to `server.py` |

---

## Current state (subsystems)

| Area | Status | Notes |
|---|---|---|
| Parser (dpkt unified) | ✅ working | All files use dpkt+l5_dispatch since v0.17.0. ICMPv6 has no raw fallback. |
| Multiprocessing pcap | ✅ working | parallel_reader.py since v0.17.0. pcapng falls back to single-thread. |
| Sessions / build_graph | ⚠️ slow | 20s for 440K packets. `post-parse-pipeline-opt` on roadmap. |
| Storage backend | ✅ working | `storage/` Phase 1 (MemoryBackend) since v0.16.0. Phase 2 = persistent. |
| Alerts (Phase 1) | ✅ working | 4 detectors: ARP spoofing, suspicious UA, malicious JA3, port scan. |
| Animation pane | ✅ working | v0.18.0+ — node temporal animation. Several known UX issues on roadmap. |
| Directional edges | ✅ working | v0.20.0 — `src|dst|protocol` IDs. |
| Edge↔session matching | ✅ working | v0.20.1 — canonical `_session_matches_edge()` in `storage/memory.py`. |
| Animation View Session | ✅ fixed v0.20.2 | `packet_limit=0` was 422; clamped in `api.js`. |
| `useCapture.js` god hook | ⚠️ tech debt | ~970 lines. Decomp = Opus task. |
| `GraphCanvas.jsx` | ⚠️ tech debt | ~1300 lines. Extraction on roadmap. |

---

## Scalability strategies (HANDOFF §3 — read full only if relevant)

**Visualization (reduce what user sees):** timeline slider · subnet grouping · protocol filter · display filter · merge by MAC · search · investigate neighbours · hide node · label threshold · clustering (in progress) · large-graph layout (not yet)

**Compute (reduce processing):** unified dpkt reader ✅ · backend analyses ✅ · packet-based session scoping ✅ · lazy analysis ✅ · multiprocessing parse ✅ · post-parse pipeline ❌ bottleneck · streaming parse ❌ · indexed packet store ❌ · graph DB backend ❌ (Opus task)

**Hot path rule:** any new feature must not regress these or introduce O(n²) on the hot path.

---

## Zero Data Loss — Current Violations & Plan

Two violation categories (HANDOFF §1, lines ~321–350):

1. **Silent caps at accumulation** — `CAP_*` constants in `analysis/protocol_fields/*.py` discard data permanently. Dissector caps (`min(dns.ancount, 20)`) are worse. String truncation (User-Agent at 200) is silent.
2. **Eager protocol init noise** — `all_init()` runs every protocol initializer on every session, polluting pure-TCP sessions with empty `smtp_has_auth`, `dns_queries`, etc.

**Plan:** lazy init → remove accumulation caps → cap at serialize with `_total` → frontend "X of Y" display. Read HANDOFF.md §1 lines 321–350 for the table and pitfalls.

---

## When to escalate to full HANDOFF.md (read only the section)

| Need | HANDOFF.md section / lines |
|---|---|
| ETL / multi-source ingestion architecture | §7 (lines 1018–1278) |
| Coupling problem fix proposals | §8 (lines 1280–1465) |
| Graph clustering / view transforms | §9 (lines 1466–1551) |
| Context menu design | §10 (lines 1553–1600) |
| Roadmap item design notes | §6 (lines 673–1017) |
| Zero data loss violation pitfalls | §1 (lines 321–350) |

Use `grep` on the keyword first, then read 100–150 line slices. Never read in full.
