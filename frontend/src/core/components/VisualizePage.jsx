/**
 * VisualizePage — Upload any tabular data and visualize as a force-directed graph.
 *
 * The user maps columns to graph elements:
 *   Required: source node, target node
 *   Optional: edge label, edge color (categorical), edge weight (numeric),
 *             node color (categorical), node size (numeric),
 *             hover data (any columns), node group (categorical),
 *             timestamp (enables time slider)
 *
 * Supports CSV, TSV, and JSON (array of objects).
 * Max 10K rows / 50MB file.
 *
 * Entirely frontend — no backend endpoint needed. Data never touches the server.
 */
import React, { useState, useRef, useEffect, useMemo, useCallback } from 'react';
import * as d3 from 'd3';

const MAX_ROWS = 10000;
const MAX_FILE_MB = 50;
const TIME_SLIDER_DEBOUNCE_MS = 300;

// ── CSV/TSV/JSON parser ────────────────────────────────────────────────────

function parseTabular(text, fileName) {
  const name = (fileName || '').toLowerCase();
  // Try JSON first
  if (name.endsWith('.json') || text.trim().startsWith('[')) {
    try {
      const arr = JSON.parse(text);
      if (Array.isArray(arr) && arr.length > 0 && typeof arr[0] === 'object') {
        return { columns: Object.keys(arr[0]), rows: arr };
      }
    } catch {}
  }
  // CSV or TSV — quote-aware parser
  const sep = name.endsWith('.tsv') || (text.indexOf('\t') < text.indexOf(',') && text.indexOf('\t') > -1) ? '\t' : ',';
  const allRows = _parseCsvLines(text, sep);
  if (allRows.length < 2) return null;
  const headers = allRows[0].map(h => h.trim());
  const rows = [];
  for (let i = 1; i < allRows.length && rows.length < MAX_ROWS; i++) {
    const vals = allRows[i];
    if (vals.length >= headers.length) {
      const obj = {};
      headers.forEach((h, j) => { obj[h] = (vals[j] || '').trim(); });
      rows.push(obj);
    }
  }
  return rows.length > 0 ? { columns: headers, rows } : null;
}

/** Parse CSV/TSV text into array of arrays, handling quoted fields with commas/newlines. */
function _parseCsvLines(text, sep) {
  const rows = [];
  let row = [];
  let field = '';
  let inQuote = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inQuote) {
      if (ch === '"') {
        if (i + 1 < text.length && text[i + 1] === '"') { field += '"'; i++; }  // escaped quote
        else inQuote = false;
      } else {
        field += ch;
      }
    } else {
      if (ch === '"') { inQuote = true; }
      else if (ch === sep) { row.push(field); field = ''; }
      else if (ch === '\n' || (ch === '\r' && text[i + 1] === '\n')) {
        if (ch === '\r') i++; // skip \n in \r\n
        row.push(field); field = '';
        if (row.some(f => f.trim())) rows.push(row);
        row = [];
      } else {
        field += ch;
      }
    }
  }
  // Last row (no trailing newline)
  if (field || row.length) { row.push(field); if (row.some(f => f.trim())) rows.push(row); }
  return rows;
}

// ── Color palette ──────────────────────────────────────────────────────────

const PALETTE = [
  '#58a6ff', '#3fb950', '#f0883e', '#bc8cff', '#f778ba',
  '#2dd4bf', '#fbbf24', '#ef4444', '#64748b', '#8b5cf6',
  '#06b6d4', '#84cc16', '#fb923c', '#e879f9', '#38bdf8',
];

function buildColorMap(values) {
  const unique = [...new Set(values)].sort();
  const map = {};
  unique.forEach((v, i) => { map[v] = PALETTE[i % PALETTE.length]; });
  return map;
}

// ── Dropdown ───────────────────────────────────────────────────────────────

function ColSelect({ label, value, onChange, columns, required, placeholder }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
      <span style={{ fontSize: 10, color: required ? 'var(--tx)' : 'var(--txD)', minWidth: 90, textAlign: 'right' }}>
        {label}{required && <span style={{ color: 'var(--acR)' }}> *</span>}
      </span>
      <select value={value} onChange={e => onChange(e.target.value)}
        style={{ flex: 1, background: 'var(--bgH)', border: '1px solid var(--bd)', borderRadius: 5, padding: '4px 8px', fontSize: 10, color: 'var(--tx)', outline: 'none', maxWidth: 200 }}>
        <option value="">{placeholder || '— none —'}</option>
        {columns.map(c => <option key={c} value={c}>{c}</option>)}
      </select>
    </div>
  );
}

function MultiSelect({ label, values, onChange, columns }) {
  function toggle(col) {
    onChange(values.includes(col) ? values.filter(v => v !== col) : [...values, col]);
  }
  return (
    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 6, marginBottom: 6 }}>
      <span style={{ fontSize: 10, color: 'var(--txD)', minWidth: 90, textAlign: 'right', paddingTop: 3 }}>{label}</span>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3, flex: 1 }}>
        {columns.map(c => (
          <button key={c} className={'btn' + (values.includes(c) ? ' on' : '')}
            onClick={() => toggle(c)} style={{ fontSize: 9, padding: '1px 6px' }}>{c}</button>
        ))}
      </div>
    </div>
  );
}

// ── Force graph ────────────────────────────────────────────────────────────

function ForceGraph({ graphData, mapping, colorMaps, width, height }) {
  const svgRef = useRef(null);
  const simRef = useRef(null);

  useEffect(() => {
    if (!svgRef.current || !graphData.nodes.length) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const g = svg.append('g');

    // Zoom
    svg.call(d3.zoom().scaleExtent([0.1, 8]).on('zoom', e => g.attr('transform', e.transform)));

    const sim = d3.forceSimulation(graphData.nodes)
      .force('link', d3.forceLink(graphData.edges).id(d => d.id).distance(80))
      .force('charge', d3.forceManyBody().strength(-120))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collide', d3.forceCollide(20));

    // Clustering force — nudge nodes toward their group centroid
    const hasGroups = graphData.nodes.some(n => n.group);
    if (hasGroups) {
      const groupCentroids = {};
      sim.force('cluster', () => {
        // Compute centroids
        const sums = {};
        graphData.nodes.forEach(n => {
          const g = n.group || '';
          if (!sums[g]) sums[g] = { x: 0, y: 0, count: 0 };
          sums[g].x += n.x || 0; sums[g].y += n.y || 0; sums[g].count++;
        });
        for (const g in sums) groupCentroids[g] = { x: sums[g].x / sums[g].count, y: sums[g].y / sums[g].count };
        // Nudge toward centroid
        graphData.nodes.forEach(n => {
          const c = groupCentroids[n.group || ''];
          if (c) { n.vx += (c.x - n.x) * 0.005; n.vy += (c.y - n.y) * 0.005; }
        });
      });
    }

    simRef.current = sim;

    // Edges
    const link = g.selectAll('.link').data(graphData.edges).enter().append('line')
      .attr('class', 'link')
      .attr('stroke', d => d.color || '#484f58')
      .attr('stroke-width', d => d.weight || 1.5)
      .attr('stroke-opacity', 0.6);

    // Edge labels
    if (mapping.edgeLabel) {
      g.selectAll('.elabel').data(graphData.edges).enter().append('text')
        .attr('class', 'elabel')
        .attr('font-size', 8).attr('fill', '#8b949e').attr('text-anchor', 'middle')
        .text(d => d.label || '');
    }

    // Nodes
    const node = g.selectAll('.node').data(graphData.nodes).enter().append('circle')
      .attr('class', 'node')
      .attr('r', d => d.size || 6)
      .attr('fill', d => d.color || '#58a6ff')
      .attr('stroke', 'var(--bg, #0d1117)').attr('stroke-width', 1)
      .call(d3.drag()
        .on('start', (e, d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on('drag', (e, d) => { d.fx = e.x; d.fy = e.y; })
        .on('end', (e, d) => { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; })
      );

    // Node labels
    const label = g.selectAll('.nlabel').data(graphData.nodes).enter().append('text')
      .attr('class', 'nlabel')
      .attr('font-size', 9).attr('fill', 'var(--tx, #e6edf3)').attr('dx', 10).attr('dy', 3)
      .text(d => d.label);

    // Tooltip
    node.append('title').text(d => d.tooltip || d.label);

    sim.on('tick', () => {
      link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
          .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
      node.attr('cx', d => d.x).attr('cy', d => d.y);
      label.attr('x', d => d.x).attr('y', d => d.y);
      if (mapping.edgeLabel) {
        g.selectAll('.elabel')
          .attr('x', d => (d.source.x + d.target.x) / 2)
          .attr('y', d => (d.source.y + d.target.y) / 2);
      }
    });

    return () => sim.stop();
  }, [graphData, mapping, width, height]);

  return <svg ref={svgRef} width={width} height={height} style={{ background: 'var(--bg)', borderRadius: 8 }} />;
}

// ── Build graph from data + mapping ────────────────────────────────────────

function buildGraph(rows, mapping, colorMaps) {
  const nodeMap = new Map();
  const edgeMap = new Map();

  // Numeric range for node size
  let sizeMin = Infinity, sizeMax = -Infinity;
  let weightMin = Infinity, weightMax = -Infinity;

  if (mapping.nodeSize) {
    rows.forEach(r => {
      const v = parseFloat(r[mapping.nodeSize]);
      if (!isNaN(v)) { sizeMin = Math.min(sizeMin, v); sizeMax = Math.max(sizeMax, v); }
    });
  }
  if (mapping.edgeWeight) {
    rows.forEach(r => {
      const v = parseFloat(r[mapping.edgeWeight]);
      if (!isNaN(v)) { weightMin = Math.min(weightMin, v); weightMax = Math.max(weightMax, v); }
    });
  }

  const scaleSize = (v) => {
    if (sizeMin === sizeMax) return 8;
    return 4 + ((v - sizeMin) / (sizeMax - sizeMin)) * 16;
  };
  const scaleWeight = (v) => {
    if (weightMin === weightMax) return 1.5;
    return 0.5 + ((v - weightMin) / (weightMax - weightMin)) * 5;
  };

  rows.forEach(r => {
    const src = r[mapping.source];
    const tgt = r[mapping.target];
    if (!src || !tgt) return;

    // Nodes
    if (!nodeMap.has(src)) {
      nodeMap.set(src, { id: src, label: src, count: 0, color: '#58a6ff', size: 6 });
    }
    if (!nodeMap.has(tgt)) {
      nodeMap.set(tgt, { id: tgt, label: tgt, count: 0, color: '#58a6ff', size: 6 });
    }
    nodeMap.get(src).count++;
    nodeMap.get(tgt).count++;

    // Edge key for aggregation
    const ek = `${src}→${tgt}`;
    if (!edgeMap.has(ek)) {
      edgeMap.set(ek, { source: src, target: tgt, count: 0, label: '', color: '#484f58', weight: 1.5 });
    }
    const edge = edgeMap.get(ek);
    edge.count++;

    // Edge label (take first)
    if (mapping.edgeLabel && !edge.label) edge.label = r[mapping.edgeLabel] || '';

    // Edge color
    if (mapping.edgeColor && colorMaps.edge) {
      edge.color = colorMaps.edge[r[mapping.edgeColor]] || '#484f58';
    }

    // Edge weight
    if (mapping.edgeWeight) {
      const v = parseFloat(r[mapping.edgeWeight]);
      if (!isNaN(v)) edge.weight = scaleWeight(v);
    }
  });

  // Node color
  if (mapping.nodeColor && colorMaps.node) {
    rows.forEach(r => {
      const src = r[mapping.source];
      const tgt = r[mapping.target];
      const val = r[mapping.nodeColor];
      if (src && nodeMap.has(src)) nodeMap.get(src).color = colorMaps.node[val] || '#58a6ff';
      if (tgt && nodeMap.has(tgt)) nodeMap.get(tgt).color = colorMaps.node[val] || '#58a6ff';
    });
  }

  // Node size
  if (mapping.nodeSize) {
    rows.forEach(r => {
      const src = r[mapping.source];
      const tgt = r[mapping.target];
      const v = parseFloat(r[mapping.nodeSize]);
      if (!isNaN(v)) {
        if (src && nodeMap.has(src)) nodeMap.get(src).size = scaleSize(v);
        if (tgt && nodeMap.has(tgt)) nodeMap.get(tgt).size = scaleSize(v);
      }
    });
  }

  // Hover/tooltip
  if (mapping.hover?.length) {
    rows.forEach(r => {
      const src = r[mapping.source];
      const tgt = r[mapping.target];
      const tip = mapping.hover.map(h => `${h}: ${r[h]}`).join('\n');
      if (src && nodeMap.has(src) && !nodeMap.get(src).tooltip) nodeMap.get(src).tooltip = tip;
      if (tgt && nodeMap.has(tgt) && !nodeMap.get(tgt).tooltip) nodeMap.get(tgt).tooltip = tip;
    });
  }

  // Node group — assign group ID for clustering force
  if (mapping.nodeGroup) {
    rows.forEach(r => {
      const src = r[mapping.source];
      const tgt = r[mapping.target];
      const grp = r[mapping.nodeGroup] || '';
      if (src && nodeMap.has(src) && !nodeMap.get(src).group) nodeMap.get(src).group = grp;
      if (tgt && nodeMap.has(tgt) && !nodeMap.get(tgt).group) nodeMap.get(tgt).group = grp;
    });
  }

  return {
    nodes: [...nodeMap.values()],
    edges: [...edgeMap.values()],
  };
}

// ── Main page ──────────────────────────────────────────────────────────────

export default function VisualizePage() {
  const [data, setData] = useState(null);       // { columns, rows }
  const [fileName, setFileName] = useState('');
  const [error, setError] = useState('');
  const [mapping, setMapping] = useState({
    source: '', target: '', edgeLabel: '', edgeColor: '', edgeWeight: '',
    nodeColor: '', nodeSize: '', hover: [], nodeGroup: '', timestamp: '',
  });
  const [timeRange, setTimeRange] = useState([0, 1]);
  const [debouncedTimeRange, setDebouncedTimeRange] = useState([0, 1]);
  const timeRangeTimer = useRef(null);
  const updateTimeRange = useCallback((val) => {
    setTimeRange(val);
    clearTimeout(timeRangeTimer.current);
    timeRangeTimer.current = setTimeout(() => setDebouncedTimeRange(val), TIME_SLIDER_DEBOUNCE_MS);
  }, []);
  const containerRef = useRef(null);
  const [dims, setDims] = useState({ w: 800, h: 500 });

  // Resize observer
  useEffect(() => {
    if (!containerRef.current) return;
    const ro = new ResizeObserver(entries => {
      for (const e of entries) {
        setDims({ w: e.contentRect.width, h: Math.max(400, e.contentRect.height - 40) });
      }
    });
    ro.observe(containerRef.current);
    return () => ro.disconnect();
  }, []);

  function handleFile(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > MAX_FILE_MB * 1024 * 1024) { setError(`File too large (max ${MAX_FILE_MB}MB)`); return; }
    setError('');
    const reader = new FileReader();
    reader.onload = ev => {
      const parsed = parseTabular(ev.target.result, file.name);
      if (!parsed || !parsed.columns.length) { setError('Could not parse file. Supported: CSV, TSV, JSON (array of objects).'); return; }
      if (parsed.rows.length > MAX_ROWS) { setError(`Too many rows (${parsed.rows.length}). Max ${MAX_ROWS}.`); return; }
      setData(parsed);
      setFileName(file.name);
      setMapping(m => ({ ...m, source: '', target: '', edgeLabel: '', edgeColor: '', edgeWeight: '', nodeColor: '', nodeSize: '', hover: [], nodeGroup: '', timestamp: '' }));
    };
    reader.readAsText(file);
  }

  function handleDrop(e) {
    e.preventDefault();
    const file = e.dataTransfer?.files?.[0];
    if (file) handleFile({ target: { files: [file] } });
  }

  const setMap = (key, val) => setMapping(m => ({ ...m, [key]: val }));

  // Time filtering
  const filteredRows = useMemo(() => {
    if (!data || !mapping.timestamp) return data?.rows || [];
    const col = mapping.timestamp;
    const vals = data.rows.map(r => {
      const v = parseFloat(r[col]);
      return isNaN(v) ? new Date(r[col]).getTime() / 1000 : v;
    }).filter(v => !isNaN(v));
    if (!vals.length) return data.rows;
    const min = Math.min(...vals), max = Math.max(...vals);
    const tStart = min + (max - min) * debouncedTimeRange[0];
    const tEnd = min + (max - min) * debouncedTimeRange[1];
    return data.rows.filter(r => {
      const v = parseFloat(r[col]);
      const ts = isNaN(v) ? new Date(r[col]).getTime() / 1000 : v;
      return ts >= tStart && ts <= tEnd;
    });
  }, [data, mapping.timestamp, debouncedTimeRange]);

  // Color maps
  const colorMaps = useMemo(() => {
    const maps = {};
    if (mapping.edgeColor && data) maps.edge = buildColorMap(data.rows.map(r => r[mapping.edgeColor]));
    if (mapping.nodeColor && data) maps.node = buildColorMap(data.rows.map(r => r[mapping.nodeColor]));
    return maps;
  }, [data, mapping.edgeColor, mapping.nodeColor]);

  // Graph
  const graphData = useMemo(() => {
    if (!data || !mapping.source || !mapping.target) return { nodes: [], edges: [] };
    return buildGraph(filteredRows, mapping, colorMaps);
  }, [filteredRows, mapping, colorMaps]);

  const ready = data && mapping.source && mapping.target;
  const cols = data?.columns || [];

  return (
    <div ref={containerRef} style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0, overflowY: 'auto', padding: '24px 32px', background: 'var(--bg)' }}>
      {/* Header */}
      <div style={{ marginBottom: 16, flexShrink: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
          <div style={{ fontSize: 22, fontWeight: 700, fontFamily: 'var(--fd)', color: 'var(--tx)' }}>Visualize</div>
          <span style={{ fontSize: 9, padding: '2px 8px', borderRadius: 8, letterSpacing: '.06em', background: 'rgba(251,191,36,.12)', color: '#fbbf24', border: '1px solid rgba(251,191,36,.3)' }}>BETA</span>
        </div>
        <div style={{ fontSize: 12, color: 'var(--txM)', lineHeight: 1.6, maxWidth: 600 }}>
          Upload any tabular data (CSV, TSV, JSON) and map columns to a force-directed graph.
          {data && <span style={{ color: 'var(--ac)', marginLeft: 6 }}>{fileName} — {data.rows.length} rows, {data.columns.length} columns</span>}
        </div>
      </div>

      {/* Upload area */}
      {!data && (
        <div onDrop={handleDrop} onDragOver={e => e.preventDefault()}
          style={{ border: '2px dashed var(--bd)', borderRadius: 12, padding: '40px 20px', textAlign: 'center', marginBottom: 20, cursor: 'pointer', background: 'var(--bgP)' }}
          onClick={() => document.getElementById('viz-file-input').click()}>
          <input id="viz-file-input" type="file" accept=".csv,.tsv,.json,.txt" onChange={handleFile} style={{ display: 'none' }} />
          <div style={{ fontSize: 28, marginBottom: 8 }}>📂</div>
          <div style={{ fontSize: 13, color: 'var(--txM)', marginBottom: 4 }}>Drop a file here or click to browse</div>
          <div style={{ fontSize: 10, color: 'var(--txD)' }}>CSV, TSV, or JSON · max {MAX_ROWS.toLocaleString()} rows · max {MAX_FILE_MB}MB</div>
        </div>
      )}

      {error && <div style={{ color: 'var(--acR)', fontSize: 11, marginBottom: 12, padding: '6px 10px', background: 'rgba(255,80,80,.08)', borderRadius: 6 }}>{error}</div>}

      {/* Column mapping + graph */}
      {data && (
        <div style={{ display: 'flex', gap: 16, flex: 1, minHeight: 0 }}>
          {/* Mapping panel */}
          <div style={{ width: 280, flexShrink: 0, background: 'var(--bgP)', border: '1px solid var(--bd)', borderRadius: 10, padding: '14px 16px', overflowY: 'auto' }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--tx)', marginBottom: 10 }}>Column Mapping</div>

            <div style={{ fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: '.06em', marginBottom: 4, marginTop: 8 }}>Required</div>
            <ColSelect label="Source node" value={mapping.source} onChange={v => setMap('source', v)} columns={cols} required placeholder="— select —" />
            <ColSelect label="Target node" value={mapping.target} onChange={v => setMap('target', v)} columns={cols} required placeholder="— select —" />

            <div style={{ fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: '.06em', marginBottom: 4, marginTop: 12 }}>Edge options</div>
            <ColSelect label="Edge label" value={mapping.edgeLabel} onChange={v => setMap('edgeLabel', v)} columns={cols} />
            <ColSelect label="Edge color" value={mapping.edgeColor} onChange={v => setMap('edgeColor', v)} columns={cols} />
            <ColSelect label="Edge weight" value={mapping.edgeWeight} onChange={v => setMap('edgeWeight', v)} columns={cols} />

            <div style={{ fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: '.06em', marginBottom: 4, marginTop: 12 }}>Node options</div>
            <ColSelect label="Node color" value={mapping.nodeColor} onChange={v => setMap('nodeColor', v)} columns={cols} />
            <ColSelect label="Node size" value={mapping.nodeSize} onChange={v => setMap('nodeSize', v)} columns={cols} />
            <ColSelect label="Node group" value={mapping.nodeGroup} onChange={v => setMap('nodeGroup', v)} columns={cols} />

            <div style={{ fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: '.06em', marginBottom: 4, marginTop: 12 }}>Data</div>
            <MultiSelect label="Hover data" values={mapping.hover} onChange={v => setMap('hover', v)} columns={cols} />
            <ColSelect label="Timestamp" value={mapping.timestamp} onChange={v => { setMap('timestamp', v); setTimeRange([0, 1]); setDebouncedTimeRange([0, 1]); }} columns={cols} />

            {/* Time slider */}
            {mapping.timestamp && (
              <div style={{ marginTop: 10, padding: '8px 0' }}>
                <div style={{ fontSize: 9, color: 'var(--txD)', marginBottom: 4 }}>Time window</div>
                <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                  <span style={{ fontSize: 9, color: '#378ADD' }}>Start</span>
                  <input type="range" min={0} max={1} step={0.01} value={timeRange[0]}
                    onChange={e => updateTimeRange([Math.min(+e.target.value, timeRange[1]), timeRange[1]])}
                    style={{ flex: 1 }} />
                </div>
                <div style={{ display: 'flex', gap: 4, alignItems: 'center', marginTop: 2 }}>
                  <span style={{ fontSize: 9, color: '#1D9E75' }}>End</span>
                  <input type="range" min={0} max={1} step={0.01} value={timeRange[1]}
                    onChange={e => updateTimeRange([timeRange[0], Math.max(+e.target.value, timeRange[0])])}
                    style={{ flex: 1 }} />
                </div>
                <div style={{ fontSize: 9, color: 'var(--txD)', marginTop: 4 }}>
                  Showing {filteredRows.length} of {data.rows.length} rows
                </div>
              </div>
            )}

            <div style={{ marginTop: 16, borderTop: '1px solid var(--bd)', paddingTop: 10 }}>
              <button className="btn" onClick={() => { setData(null); setFileName(''); setError(''); }}
                style={{ fontSize: 9, padding: '3px 10px', width: '100%' }}>Clear &amp; upload new file</button>
            </div>

            {/* Legend */}
            {mapping.edgeColor && colorMaps.edge && (
              <div style={{ marginTop: 12 }}>
                <div style={{ fontSize: 9, color: 'var(--txD)', marginBottom: 4 }}>Edge colors</div>
                {Object.entries(colorMaps.edge).slice(0, 15).map(([k, v]) => (
                  <div key={k} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 9, marginBottom: 2 }}>
                    <span style={{ width: 8, height: 8, borderRadius: '50%', background: v, flexShrink: 0 }} />
                    <span style={{ color: 'var(--txM)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{k}</span>
                  </div>
                ))}
              </div>
            )}
            {mapping.nodeColor && colorMaps.node && (
              <div style={{ marginTop: 12 }}>
                <div style={{ fontSize: 9, color: 'var(--txD)', marginBottom: 4 }}>Node colors</div>
                {Object.entries(colorMaps.node).slice(0, 15).map(([k, v]) => (
                  <div key={k} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 9, marginBottom: 2 }}>
                    <span style={{ width: 8, height: 8, borderRadius: '50%', background: v, flexShrink: 0 }} />
                    <span style={{ color: 'var(--txM)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{k}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Graph area */}
          <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column' }}>
            {!ready ? (
              <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--txD)', fontSize: 12 }}>
                Select <strong style={{ margin: '0 4px' }}>Source node</strong> and <strong style={{ margin: '0 4px' }}>Target node</strong> columns to render the graph.
              </div>
            ) : graphData.nodes.length === 0 ? (
              <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--txD)', fontSize: 12 }}>
                No nodes produced. Check your column selections.
              </div>
            ) : (
              <>
                <div style={{ fontSize: 10, color: 'var(--txD)', marginBottom: 6, flexShrink: 0 }}>
                  {graphData.nodes.length} nodes · {graphData.edges.length} edges
                  {mapping.timestamp && ` · ${filteredRows.length} rows in window`}
                </div>
                <div style={{ flex: 1, minHeight: 400, border: '1px solid var(--bd)', borderRadius: 10, overflow: 'hidden' }}>
                  <ForceGraph graphData={graphData} mapping={mapping} colorMaps={colorMaps} width={dims.w - 320} height={dims.h} />
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
