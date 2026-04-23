// AnnotationStore — per-capture store for all visual annotations.
// Lives at useCapture level. Writers: pipeline RecipePanel, query highlight,
// future: alert clicks, navigate-to-node, plugins, manual context menu.
// The render loop reads toRenderSnapshot() once per frame.

let _nextId = 1;
function genId() { return `ann_${_nextId++}`; }

export class AnnotationStore {
  constructor() {
    this._items = new Map(); // id → annotation
  }

  // ── Write ────────────────────────────────────────────────────────────────────

  /** Add annotation. Returns the assigned id. */
  add(annotation) {
    const id = annotation.id || genId();
    this._items.set(id, { ...annotation, id });
    return id;
  }

  /** Remove a single annotation by id. */
  remove(id) {
    this._items.delete(id);
  }

  /** Patch fields on an existing annotation. */
  update(id, patch) {
    const item = this._items.get(id);
    if (item) this._items.set(id, { ...item, ...patch, id });
  }

  /**
   * Remove all annotations matching the given lifetime.
   * Also prunes expired 'flash' entries regardless of the lifetime argument.
   * Pass 'all' to clear everything.
   */
  clear(lifetime) {
    const now = Date.now();
    for (const [id, ann] of this._items) {
      if (ann.lifetime === 'flash' && ann.expiresAt != null && now > ann.expiresAt) {
        this._items.delete(id);
      } else if (lifetime === 'all' || ann.lifetime === lifetime) {
        this._items.delete(id);
      }
    }
  }

  // ── Query ────────────────────────────────────────────────────────────────────

  byType(type) {
    const result = [];
    for (const ann of this._items.values()) {
      if (ann.type === type) result.push(ann);
    }
    return result;
  }

  byNode(nodeId) {
    const result = [];
    for (const ann of this._items.values()) {
      if (ann.nodeId === nodeId) result.push(ann);
      if (ann.targets?.nodes?.includes(nodeId)) result.push(ann);
    }
    return result;
  }

  // ── Render snapshot ──────────────────────────────────────────────────────────

  /**
   * Returns a pre-baked snapshot for the render loop.
   * Also prunes expired flash annotations.
   *
   * Shape:
   * {
   *   hulls:         [{ name, members, color, label, cohesion }],
   *   badges:        { nodeId: [{ text, color }] },
   *   rings:         { nodes: { nodeId: [{ color, style, width }] }, edges: { edgeId: [...] } },
   *   colorOverrides:{ nodeId: { fill, stroke, priority } },
   * }
   */
  toRenderSnapshot() {
    const now = Date.now();

    const hulls = [];
    const badges = {};              // nodeId → [{text, color}]
    const ringNodes = {};           // nodeId → [{color, style, width}]
    const ringEdges = {};           // edgeId → [{color, style, width}]
    const colorOverrides = {};      // nodeId → {fill, stroke, priority}
    const edgeColorOverrides = {};  // edgeId → {fill, stroke, priority}

    for (const [id, ann] of this._items) {
      // Drop expired flash
      if (ann.lifetime === 'flash' && ann.expiresAt != null && now > ann.expiresAt) {
        this._items.delete(id);
        continue;
      }

      if (ann.type === 'hull') {
        hulls.push({
          name: ann.name,
          members: ann.members,
          color: ann.color,
          label: ann.label ?? ann.name,
          cohesion: ann.cohesion ?? 0,
        });

      } else if (ann.type === 'badge') {
        if (!badges[ann.nodeId]) badges[ann.nodeId] = [];
        badges[ann.nodeId].push({ text: ann.text, color: ann.color });

      } else if (ann.type === 'ring') {
        const ringEntry = { color: ann.color, style: ann.style ?? 'solid', width: ann.width ?? 2 };
        for (const nid of (ann.targets?.nodes ?? [])) {
          if (!ringNodes[nid]) ringNodes[nid] = [];
          ringNodes[nid].push(ringEntry);
        }
        for (const eid of (ann.targets?.edges ?? [])) {
          if (!ringEdges[eid]) ringEdges[eid] = [];
          ringEdges[eid].push(ringEntry);
        }

      } else if (ann.type === 'color_override') {
        const priority = ann.lifetime === 'persistent' ? 'persistent' : 'transient';
        if (ann.nodeId) {
          const existing = colorOverrides[ann.nodeId];
          if (!existing || (ann.lifetime === 'persistent' && existing.priority !== 'persistent')) {
            colorOverrides[ann.nodeId] = { fill: ann.fill, stroke: ann.stroke, priority };
          }
        } else if (ann.edgeId) {
          const existing = edgeColorOverrides[ann.edgeId];
          if (!existing || (ann.lifetime === 'persistent' && existing.priority !== 'persistent')) {
            edgeColorOverrides[ann.edgeId] = { fill: ann.fill, stroke: ann.stroke, priority };
          }
        }
      }
    }

    return {
      hulls,
      badges,
      rings: { nodes: ringNodes, edges: ringEdges },
      colorOverrides,
      edgeColorOverrides,
    };
  }

  // ── Layout hints ─────────────────────────────────────────────────────────────

  /**
   * Returns cohesion targets for forceLayout.js.
   * Shape: { hullCohesion: [{ members: string[], strength: number }] }
   */
  toLayoutHints() {
    const hullCohesion = [];
    for (const ann of this._items.values()) {
      if (ann.type === 'hull' && ann.cohesion > 0) {
        hullCohesion.push({
          members: ann.members,
          strength: ann.cohesion,
        });
      }
    }
    return { hullCohesion };
  }

  // ── Lifecycle ────────────────────────────────────────────────────────────────

  /** Full reset — called by useCapture on store.load() to clear all capture-local state. */
  reset() {
    this._items.clear();
  }

  get size() {
    return this._items.size;
  }
}

/** Factory — creates a fresh AnnotationStore. */
export function createAnnotationStore() {
  return new AnnotationStore();
}
