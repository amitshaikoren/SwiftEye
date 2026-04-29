/**
 * useEvents — Researcher-flagged Events + TimelineEdges (v0.21.0).
 *
 * In-memory state for Phase 1. Will be persisted via the workspace save model
 * once `save-load-workspaces` ships. Until then, Events are lost on reload —
 * this is the documented Phase 1 behavior.
 *
 * Contains:
 *   - events[]            researcher-flagged nodes/edges/sessions
 *   - timelineEdges[]     manual + accepted-suggestion edges drawn on the
 *                         Timeline Graph canvas
 *   - suggestedEdges[]    derived (memo) — suggested connections between
 *                         every pair of events. Render only when both
 *                         endpoints are placed on the canvas (`canvas_x/y`).
 *
 * Suggested-edge reasons (Phase 1, hardcoded — pluggable in Phase 2 via
 * `event-suggested-edges-pluggable`). Detection order is fixed; the first
 * matching reason determines the merged edge's primary color.
 */
import { useState, useMemo, useCallback, useRef } from 'react';

// ── Reason metadata (color table — keep in sync with mockup + plan) ───────

export const REASON_ORDER = ['same_node', 'same_edge', 'same_subnet', 'same_protocol'];

export const REASON_META = {
  same_node:     { label: 'Same node',     color: '#58a6ff' }, // blue
  same_edge:     { label: 'Same edge',     color: '#bc8cff' }, // purple
  same_subnet:   { label: 'Same subnet',   color: '#d29922' }, // yellow
  same_protocol: { label: 'Same protocol', color: '#3fb950' }, // green
};

// ── Severity ───────────────────────────────────────────────────────────────

export const SEVERITY_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

export const SEVERITY_COLOR = {
  critical: '#f85149',
  high:     '#f0883e',
  medium:   '#d29922',
  low:      '#58a6ff',
  info:     '#8b949e',
};

function rankOf(sev) { return sev && SEVERITY_RANK[sev] != null ? SEVERITY_RANK[sev] : 0; }
function maxSeverity(a, b) { return rankOf(a) >= rankOf(b) ? a : b; }

// ── Subnet helpers ─────────────────────────────────────────────────────────
//
// node IDs in the SwiftEye graph come in three forms:
//   - bare IPv4   "10.0.0.5"
//   - CIDR group  "10.0.0.0/24"  (when subnet_grouping is on)
//   - IPv6 / ARP  "::1", "ARP", "2606:4700::"  → no subnet
//
// We collapse to /24 for matching. Two events "share a subnet" if any of
// their resolved /24s overlap.

function subnetOf(nodeId) {
  if (!nodeId) return null;
  if (nodeId.includes('/')) return nodeId;     // already a CIDR
  if (nodeId.includes(':')) return null;        // IPv6 / not v4
  if (nodeId === 'ARP' || nodeId === 'BROADCAST') return null;
  const parts = nodeId.split('.');
  if (parts.length !== 4) return null;
  return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}

function uniq(arr) { return Array.from(new Set(arr.filter(x => x != null))); }
function intersects(a, b) { for (const x of a) if (b.includes(x)) return true; return false; }

// ── Match metadata extraction ──────────────────────────────────────────────
//
// Each Event carries the minimal facts the suggested-edge engine needs to
// compare it against other events without re-walking the full graph. This
// snapshot is taken at flag time and never recomputed (Phase 1 acceptable;
// re-flag if the graph changes meaningfully).

function buildNodeMatch(node, graph) {
  const id = node.id;
  // Derive node capture_time as min(first_seen) of incident edges since the
  // serialized node doesn't carry first_seen directly.
  let firstSeen = null;
  if (graph && Array.isArray(graph.edges)) {
    for (const e of graph.edges) {
      if (e.source === id || e.target === id) {
        if (firstSeen == null || (e.first_seen != null && e.first_seen < firstSeen)) {
          firstSeen = e.first_seen;
        }
      }
    }
  }
  return {
    capture_time: firstSeen,
    match_node_ids: [id],
    match_subnets: uniq([subnetOf(id)]),
    match_protocols: Array.isArray(node.protocols) ? [...node.protocols] : [],
  };
}

function buildEdgeMatch(edge) {
  return {
    capture_time: edge.first_seen ?? null,
    match_node_ids: uniq([edge.source, edge.target]),
    match_subnets: uniq([subnetOf(edge.source), subnetOf(edge.target)]),
    match_protocols: edge.protocol ? [edge.protocol] : [],
  };
}

function buildSessionMatch(session) {
  const src = session.src_ip || session.src || null;
  const dst = session.dst_ip || session.dst || null;
  const proto = session.protocol || session.l4_protocol || null;
  return {
    capture_time: session.start_time ?? null,
    match_node_ids: uniq([src, dst]),
    match_subnets: uniq([subnetOf(src), subnetOf(dst)]),
    match_protocols: proto ? [proto] : [],
  };
}

// ── Default titles ─────────────────────────────────────────────────────────

function defaultTitle(entity_type, entity) {
  if (entity_type === 'node')    return entity.id || 'Node';
  if (entity_type === 'edge')    return `${entity.source} → ${entity.target}`;
  if (entity_type === 'session') return `Session ${(entity.id || '').slice(0, 8)}`;
  return 'Event';
}

// ── Hook ───────────────────────────────────────────────────────────────────

// Pair-key helper: rejected suggestions are keyed by the unordered pair so
// rejecting once survives a swap of from/to.
function pairKey(a, b) { return [a, b].sort().join('|'); }

export default function useEvents() {
  const [events, setEvents]                             = useState([]);
  const [timelineEdges, setTimelineEdges]               = useState([]);
  const [rejectedSuggestions, setRejectedSuggestions]   = useState(() => new Set());
  // TimelineGraph view state lives here so it survives tab navigation /
  // panel switches that unmount the TimelineGraph component.
  const [rulerOn, setRulerOn]                           = useState(false);

  // Mirror events into a ref for stable callbacks that need the latest list
  // without re-creating identity (used by getEventByEntityId).
  const eventsRef = useRef(events);
  eventsRef.current = events;

  // ── CRUD: Events ─────────────────────────────────────────────────────────

  const addEvent = useCallback((args) => {
    const {
      entity, entity_type,
      title, severity = null, description = '',
      annotation_snapshot = null,
      graph = null,
    } = args;
    if (!entity || !entity_type) return null;

    let match;
    if (entity_type === 'node')         match = buildNodeMatch(entity, graph);
    else if (entity_type === 'edge')    match = buildEdgeMatch(entity);
    else if (entity_type === 'session') match = buildSessionMatch(entity);
    else return null;

    const id = (typeof crypto !== 'undefined' && crypto.randomUUID) ? crypto.randomUUID() : String(Math.random());
    const ev = {
      id,
      title: title || defaultTitle(entity_type, entity),
      description,
      severity,
      created_at: Date.now() / 1000,
      capture_time: match.capture_time,
      entity_type,
      node_id:    entity_type === 'node'    ? entity.id : null,
      edge_id:    entity_type === 'edge'    ? entity.id : null,
      session_id: entity_type === 'session' ? entity.id : null,
      match_node_ids:    match.match_node_ids,
      match_subnets:     match.match_subnets,
      match_protocols:   match.match_protocols,
      annotation_snapshot,
      // Phase 2 fields
      alert_id: null,
      frame_time: null,
      time_range: null,
      // Canvas placement (null = not yet on the timeline graph)
      canvas_x: null,
      canvas_y: null,
    };
    setEvents(prev => [...prev, ev]);
    return ev;
  }, []);

  const updateEvent = useCallback((id, patch) => {
    setEvents(prev => prev.map(e => e.id === id ? { ...e, ...patch } : e));
  }, []);

  const removeEvent = useCallback((id) => {
    setEvents(prev => prev.filter(e => e.id !== id));
    // Also drop any timeline edges that reference this event
    setTimelineEdges(prev => prev.filter(te => te.from_event_id !== id && te.to_event_id !== id));
  }, []);

  const placeEvent = useCallback((id, x, y) => {
    setEvents(prev => prev.map(e => e.id === id ? { ...e, canvas_x: x, canvas_y: y } : e));
  }, []);

  const unplaceEvent = useCallback((id) => {
    setEvents(prev => prev.map(e => e.id === id ? { ...e, canvas_x: null, canvas_y: null } : e));
  }, []);

  // ── CRUD: TimelineEdges ──────────────────────────────────────────────────

  const addTimelineEdge = useCallback((from_event_id, to_event_id, props = {}) => {
    if (!from_event_id || !to_event_id || from_event_id === to_event_id) return null;
    const id = (typeof crypto !== 'undefined' && crypto.randomUUID) ? crypto.randomUUID() : String(Math.random());
    const te = {
      id,
      from_event_id,
      to_event_id,
      type: props.type || 'manual',
      label: props.label || null,
      color: props.color || '#8b949e',
      annotation: props.annotation || null,
    };
    setTimelineEdges(prev => [...prev, te]);
    return te;
  }, []);

  const updateTimelineEdge = useCallback((id, patch) => {
    setTimelineEdges(prev => prev.map(te => te.id === id ? { ...te, ...patch } : te));
  }, []);

  const removeTimelineEdge = useCallback((id) => {
    setTimelineEdges(prev => prev.filter(te => te.id !== id));
  }, []);

  const acceptSuggestion = useCallback((from_event_id, to_event_id, reason) => {
    const meta = REASON_META[reason?.type] || { label: reason?.label || '', color: '#8b949e' };
    return addTimelineEdge(from_event_id, to_event_id, {
      type: 'accepted_suggestion',
      label: meta.label,
      color: meta.color,
    });
  }, [addTimelineEdge]);

  // Reject a suggestion permanently (for the lifetime of the in-memory store).
  // Stored as a Set of unordered pair-keys so reject survives a from/to swap.
  // Same-events reasons are still computed by the memo, but the pair is
  // filtered out before it's exposed.
  const rejectSuggestion = useCallback((from_event_id, to_event_id) => {
    if (!from_event_id || !to_event_id) return;
    setRejectedSuggestions(prev => {
      const k = pairKey(from_event_id, to_event_id);
      if (prev.has(k)) return prev;
      const next = new Set(prev);
      next.add(k);
      return next;
    });
  }, []);

  // ── Derived: suggested edges (O(n²) over events, n is small) ─────────────
  //
  // Computed for ALL pairs. The Timeline Graph renderer is responsible for
  // only DRAWING those whose endpoints are both placed on the canvas.

  const suggestedEdges = useMemo(() => {
    const out = [];
    for (let i = 0; i < events.length; i++) {
      for (let j = i + 1; j < events.length; j++) {
        const a = events[i];
        const b = events[j];
        // Skip permanently-rejected pairs (unordered key).
        if (rejectedSuggestions.has(pairKey(a.id, b.id))) continue;
        // Order so the earlier capture_time is "from" — falls back to
        // creation order when either is null.
        let from = a, to = b;
        if (a.capture_time != null && b.capture_time != null) {
          if (a.capture_time > b.capture_time) { from = b; to = a; }
        }
        const reasons = [];
        if (intersects(from.match_node_ids, to.match_node_ids)) {
          const shared = from.match_node_ids.find(x => to.match_node_ids.includes(x));
          reasons.push({ type: 'same_node', label: `Same node: ${shared}`, color: REASON_META.same_node.color, evidence: shared });
        }
        if (from.edge_id && from.edge_id === to.edge_id) {
          reasons.push({ type: 'same_edge', label: `Same edge: ${from.edge_id}`, color: REASON_META.same_edge.color, evidence: from.edge_id });
        }
        if (intersects(from.match_subnets, to.match_subnets)) {
          const shared = from.match_subnets.find(x => to.match_subnets.includes(x));
          reasons.push({ type: 'same_subnet', label: `Same subnet: ${shared}`, color: REASON_META.same_subnet.color, evidence: shared });
        }
        if (intersects(from.match_protocols, to.match_protocols)) {
          const shared = from.match_protocols.find(x => to.match_protocols.includes(x));
          reasons.push({ type: 'same_protocol', label: `Same protocol: ${shared}`, color: REASON_META.same_protocol.color, evidence: shared });
        }
        if (reasons.length === 0) continue;
        // Sort reasons by REASON_ORDER so primary_color is deterministic
        reasons.sort((r1, r2) => REASON_ORDER.indexOf(r1.type) - REASON_ORDER.indexOf(r2.type));
        const direction =
          (from.capture_time != null && to.capture_time != null && from.capture_time !== to.capture_time)
            ? 'a_to_b' : 'none';
        out.push({
          from_event_id: from.id,
          to_event_id: to.id,
          reasons,
          primary_color: reasons[0].color,
          direction,
        });
      }
    }
    return out;
  }, [events, rejectedSuggestions]);

  // ── Indicator maps for the main GraphCanvas ──────────────────────────────
  //
  // These are passed to GraphCanvas as props and drive the small severity
  // dot overlay on flagged nodes/edges. Multiple events per entity collapse
  // to the highest severity for display.

  const nodeEventSeverity = useMemo(() => {
    const m = new Map();
    for (const e of events) {
      if (e.entity_type === 'node' && e.node_id) {
        m.set(e.node_id, maxSeverity(m.get(e.node_id) || null, e.severity));
      }
    }
    return m;
  }, [events]);

  const edgeEventSeverity = useMemo(() => {
    const m = new Map();
    for (const e of events) {
      if (e.entity_type === 'edge' && e.edge_id) {
        m.set(e.edge_id, maxSeverity(m.get(e.edge_id) || null, e.severity));
      }
    }
    return m;
  }, [events]);

  // ── Lookups ──────────────────────────────────────────────────────────────

  const getEventsForEntity = useCallback((entity_type, entity_id) => {
    if (!entity_type || !entity_id) return [];
    return eventsRef.current.filter(e =>
      e.entity_type === entity_type && (
        (entity_type === 'node'    && e.node_id    === entity_id) ||
        (entity_type === 'edge'    && e.edge_id    === entity_id) ||
        (entity_type === 'session' && e.session_id === entity_id)
      )
    );
  }, []);

  return {
    events,
    timelineEdges,
    suggestedEdges,

    addEvent,
    updateEvent,
    removeEvent,
    placeEvent,
    unplaceEvent,

    addTimelineEdge,
    updateTimelineEdge,
    removeTimelineEdge,
    acceptSuggestion,
    rejectSuggestion,

    nodeEventSeverity,
    edgeEventSeverity,
    getEventsForEntity,

    // TimelineGraph view state (persisted across tab nav)
    rulerOn,
    setRulerOn,
  };
}
