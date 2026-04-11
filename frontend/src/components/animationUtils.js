/**
 * animationUtils.js — constants and pure helper functions for AnimationPane.
 *
 * Extracted from AnimationPane.jsx (v0.25.3 decomposition).
 */

import * as d3 from 'd3';

// ── Constants ────────────────────────────────────────────────────────────────

export const FLASH_DURATION_MS = 900;
export const GRID_SIZE = 60;
export const NODE_RADIUS = 12;
export const SPOTLIGHT_RING_R = 18;

// ── Helpers ──────────────────────────────────────────────────────────────────

export function formatAnimTime(ts) {
  if (!ts) return '--:--:--.---';
  const d = new Date(ts * 1000);
  const h = String(d.getHours()).padStart(2, '0');
  const m = String(d.getMinutes()).padStart(2, '0');
  const s = String(d.getSeconds()).padStart(2, '0');
  const ms = String(d.getMilliseconds()).padStart(3, '0');
  return `${h}:${m}:${s}.${ms}`;
}

/** Build a session map from events for quick lookup. */
export function buildSessionMap(events) {
  const map = {};
  for (const ev of events) {
    if (ev.type === 'start') {
      map[ev.session_id] = ev;
    }
  }
  return map;
}

/** Compute node positions: spotlight inherit from mainGraph, neighbours via D3 collision. */
export function computePositions(animNodeMeta, mainNodes, canvasW, canvasH) {
  const positions = {};
  const mainMap = {};
  for (const n of (mainNodes || [])) {
    if (n.x != null && n.y != null) mainMap[n.id] = { x: n.x, y: n.y };
  }

  // Place all animation nodes
  const allIps = Object.keys(animNodeMeta);
  const spotlightIps = allIps.filter(ip => animNodeMeta[ip]?.is_spotlight);
  const neighbourIps = allIps.filter(ip => !animNodeMeta[ip]?.is_spotlight);

  // Spotlight nodes: inherit main graph positions
  for (const ip of spotlightIps) {
    if (mainMap[ip]) {
      positions[ip] = { x: mainMap[ip].x, y: mainMap[ip].y };
    } else {
      // Fallback: place in center area
      const angle = (spotlightIps.indexOf(ip) / spotlightIps.length) * Math.PI * 2;
      const r = Math.min(canvasW, canvasH) * 0.15;
      positions[ip] = {
        x: canvasW / 2 + Math.cos(angle) * r,
        y: canvasH / 2 + Math.sin(angle) * r,
      };
    }
  }

  // Neighbour nodes: inherit main graph positions, then D3 collision resolve
  const simNodes = [];
  for (const ip of neighbourIps) {
    if (mainMap[ip]) {
      simNodes.push({ id: ip, x: mainMap[ip].x, y: mainMap[ip].y, fx: null, fy: null });
    } else {
      // Random placement near center
      simNodes.push({
        id: ip,
        x: canvasW / 2 + (Math.random() - 0.5) * canvasW * 0.5,
        y: canvasH / 2 + (Math.random() - 0.5) * canvasH * 0.5,
        fx: null, fy: null,
      });
    }
  }

  // Add spotlight as fixed obstacles
  const fixedNodes = spotlightIps.map(ip => ({
    id: ip, ...positions[ip], fx: positions[ip].x, fy: positions[ip].y,
  }));

  if (simNodes.length > 0) {
    const allSimNodes = [...fixedNodes, ...simNodes];
    const sim = d3.forceSimulation(allSimNodes)
      .force('collision', d3.forceCollide().radius(NODE_RADIUS * 2.5))
      .force('charge', d3.forceManyBody().strength(-30))
      .stop();

    // Run a brief tick to resolve overlaps
    for (let i = 0; i < 50; i++) sim.tick();

    for (const n of allSimNodes) {
      if (!positions[n.id]) {
        positions[n.id] = { x: n.x, y: n.y };
      }
    }
  }

  return positions;
}

/** Build edge list from events for rendering. */
export function buildEdgeList(sessionMap) {
  const edges = [];
  const pairCount = {}; // track multi-edges between same pair
  for (const [sid, ev] of Object.entries(sessionMap)) {
    const pairKey = [ev.src, ev.dst].sort().join('|');
    pairCount[pairKey] = (pairCount[pairKey] || 0) + 1;
    edges.push({
      session_id: sid,
      src: ev.src,
      dst: ev.dst,
      protocol: ev.protocol,
      bytes: ev.bytes,
      packets: ev.packets,
      pairKey,
      pairIndex: pairCount[pairKey] - 1,
    });
  }
  // Set pairTotal for curvature
  for (const e of edges) {
    e.pairTotal = pairCount[e.pairKey];
  }
  return edges;
}
