import { useRef, useEffect } from 'react';
import * as d3 from 'd3';
import { CLUSTER_COLORS } from '../../../clusterView';
import { resolveNodeColor, resolveEdgeColor } from '../utils/graphColorUtils';

export default function useGraphSim({ nodes, edges, cRef, containerRef, graphWeightMode, tRef,
  renRef, rafRef, hRef,
  selNRef, selERef, pcRef, invNodesRef, dfNodesRef, dfEdgesRef, qhRef,
  labelThreshRef, edgeSizeModeRef, nodeColorModeRef, edgeColorModeRef,
  nodeColorRulesRef, edgeColorRulesRef, showEdgeDirectionRef }) {

  const simRef = useRef(null);
  const nRef = useRef([]);
  const eRef = useRef([]);
  const graphWeightModeRef = useRef(graphWeightMode);

  // Single authoritative node-radius function — reads graphWeightModeRef dynamically.
  const gRRef = useRef(null);
  if (!gRRef.current) {
    gRRef.current = function gR(n) {
      if (n.is_cluster) return Math.max(14, Math.min(36, Math.sqrt(n.member_count) * 6 + 8));
      if (n.synthetic) return Math.max(8, Math.min(28, n.size || 14));
      if (graphWeightModeRef.current === 'bytes') {
        return Math.max(5, Math.min(28, Math.log(Math.max(1, n.total_bytes)) * 2));
      }
      return Math.max(5, Math.min(28, Math.sqrt(n.packet_count) * 2 + 3));
    };
  }

  // Update collision radius when graphWeightMode changes
  useEffect(() => {
    graphWeightModeRef.current = graphWeightMode;
    if (simRef.current) {
      const gR = gRRef.current;
      simRef.current
        .force('collision', d3.forceCollide().radius(d => d.is_cluster ? gR(d) * 1.8 + 15 : gR(d) + 10))
        .alpha(0.15).restart();
    }
    if (renRef.current) renRef.current();
  }, [graphWeightMode]);

  function getSize() {
    const el = containerRef?.current;
    if (!el) return { width: 800, height: 600 };
    return { width: el.clientWidth, height: el.clientHeight };
  }

  function doRelayout() {
    if (!simRef.current) return;
    nRef.current.forEach(n => { delete n.fx; delete n.fy; });
    const nn = nRef.current;
    const nodeCount = nn.length;
    const hasAnyClusters = nn.some(n => n.is_cluster);
    const chargeDistMax = hasAnyClusters ? 450
      : nodeCount > 200 ? 180
      : nodeCount > 50  ? 300
      : 400;
    simRef.current.force('charge')
      .strength(d => d.is_cluster ? -350 - (d.member_count || 0) * 18 : -180)
      .distanceMax(chargeDistMax);
    simRef.current.alpha(0.9).alphaTarget(0).restart();
  }

  function doExportHTML() {
    const gR = gRRef.current;
    const pc = pcRef.current;
    const t  = tRef.current;
    const nColorMode  = nodeColorModeRef.current;
    const nColorRules = nodeColorRulesRef.current;
    const eColorMode  = edgeColorModeRef.current;
    const eColorRules = edgeColorRulesRef.current;

    const cs = getComputedStyle(document.body);
    const cv = k => cs.getPropertyValue(k).trim();
    const nodePrivate   = cv('--node-private')   || '#264060';
    const nodePrivateS  = cv('--node-private-s') || '#5a9ad5';
    const nodeExternal  = cv('--node-external')  || '#3d2855';
    const nodeExternalS = cv('--node-external-s')|| '#9060cc';
    const bgColor       = cv('--bg')             || '#08090d';

    const snapshotNodes = nRef.current.map(n => {
      const r = gR(n);
      const [fill, stroke] = n.is_cluster || n.is_subnet || n.synthetic
        ? [n.color || '#f0883e', n.color || '#f0883e']
        : resolveNodeColor(n, nColorMode, nColorRules, pc, nodePrivate, nodePrivateS, nodeExternal, nodeExternalS);
      const topProtos = (n.top_protocols || []).slice(0, 3).map(p => p[0]).join(', ');
      return {
        x: n.x, y: n.y, r,
        fill, stroke,
        label: n.hostname || n.id || '',
        id: n.id || '',
        bytes: n.total_bytes || 0,
        packets: n.packet_count || 0,
        sessions: n.session_count || 0,
        topProtos,
      };
    });

    const snapshotEdges = eRef.current.map(e => {
      const src = typeof e.source === 'object' ? e.source : nRef.current.find(n => n.id === e.source);
      const tgt = typeof e.target === 'object' ? e.target : nRef.current.find(n => n.id === e.target);
      if (!src || !tgt) return null;
      const color = resolveEdgeColor(e, eColorMode, eColorRules, pc);
      const metric = edgeSizeModeRef.current === 'packets' ? (e.packet_count || 0)
        : edgeSizeModeRef.current === 'sessions' ? (e.session_count || 0)
        : (e.total_bytes || 0);
      const maxMetric = Math.max(...eRef.current.map(ex =>
        edgeSizeModeRef.current === 'packets' ? (ex.packet_count || 0)
          : edgeSizeModeRef.current === 'sessions' ? (ex.session_count || 0)
          : (ex.total_bytes || 0)
      ), 1);
      const protocols = (e.protocols && e.protocols.length)
        ? e.protocols.join(', ')
        : (e.protocol || '');
      const srcId = typeof src === 'object' ? src.id : src;
      const tgtId = typeof tgt === 'object' ? tgt.id : tgt;
      return {
        sx: src.x, sy: src.y, tx: tgt.x, ty: tgt.y,
        color, width: Math.max(0.6, (metric / maxMetric) * 10),
        protocols, bytes: e.total_bytes || 0, packets: e.packet_count || 0,
        sessions: e.session_count || 0,
        srcId, tgtId,
      };
    }).filter(Boolean);

    const data = JSON.stringify({ nodes: snapshotNodes, edges: snapshotEdges, bg: bgColor, tx: t.x, ty: t.y, tk: t.k });

    const html = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>SwiftEye Graph Export</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{background:#08090d;overflow:hidden}
canvas{display:block;width:100vw;height:100vh}
#tip{position:fixed;pointer-events:none;background:rgba(14,17,23,.95);border:1px solid #30363d;
border-radius:6px;padding:6px 10px;font:11px/1.6 "JetBrains Mono",monospace;color:#e6edf3;
display:none;z-index:10;max-width:240px}
.tl{color:#8b949e;font-size:9px;text-transform:uppercase;letter-spacing:.06em;margin-top:5px;margin-bottom:1px}
</style></head><body>
<canvas id="c"></canvas><div id="tip"></div>
<script>
const D=${data};
const canvas=document.getElementById('c');
const ctx=canvas.getContext('2d');
const tip=document.getElementById('tip');
// Build node lookup so dragging updates connected edges automatically
const NM={};for(const n of D.nodes)NM[n.id]=n;
let tx=D.tx,ty=D.ty,tk=D.tk,panDrag=false,nodeDrag=null,lx=0,ly=0,hover=null,hoverE=null;
function resize(){canvas.width=window.innerWidth;canvas.height=window.innerHeight;}
function fB(b){if(b>=1e9)return(b/1e9).toFixed(1)+'GB';if(b>=1e6)return(b/1e6).toFixed(1)+'MB';if(b>=1e3)return(b/1e3).toFixed(1)+'KB';return b+'B';}
function fN(n){return n>=1e6?(n/1e6).toFixed(1)+'M':n>=1e3?(n/1e3).toFixed(1)+'K':String(n);}
function draw(){
  const w=canvas.width,h=canvas.height;
  ctx.fillStyle=D.bg||'#08090d';ctx.fillRect(0,0,w,h);
  ctx.save();ctx.translate(tx,ty);ctx.scale(tk,tk);
  for(const e of D.edges){
    const s=NM[e.srcId],t=NM[e.tgtId];
    if(!s||!t)continue;
    const isHe=hoverE===e;
    ctx.beginPath();ctx.moveTo(s.x,s.y);ctx.lineTo(t.x,t.y);
    ctx.strokeStyle=isHe?'#fff':e.color;ctx.lineWidth=(isHe?e.width+2:e.width)/tk;ctx.globalAlpha=isHe?1:0.7;ctx.stroke();
    ctx.globalAlpha=1;
  }
  for(const n of D.nodes){
    const isH=hover===n||nodeDrag===n;
    ctx.beginPath();ctx.arc(n.x,n.y,n.r,0,Math.PI*2);
    ctx.fillStyle=n.fill;ctx.fill();
    ctx.strokeStyle=isH?'#fff':n.stroke;ctx.lineWidth=(isH?2.5:1.5)/tk;ctx.stroke();
    if(n.label&&tk>0.5){
      ctx.font=\`\${Math.max(8,10/tk)}px JetBrains Mono,monospace\`;
      ctx.textAlign='center';ctx.textBaseline='top';
      ctx.fillStyle='rgba(0,0,0,0.7)';
      const tw=ctx.measureText(n.label).width;
      ctx.fillRect(n.x-tw/2-2,n.y+n.r+2,tw+4,12/tk);
      ctx.fillStyle=isH?'#fff':'#8b949e';
      ctx.fillText(n.label,n.x,n.y+n.r+3);
    }
  }
  ctx.restore();
}
function ptSegDist2(px,py,ax,ay,bx,by){
  const dx=bx-ax,dy=by-ay;
  if(dx===0&&dy===0)return(px-ax)**2+(py-ay)**2;
  const t=Math.max(0,Math.min(1,((px-ax)*dx+(py-ay)*dy)/(dx*dx+dy*dy)));
  return(px-ax-t*dx)**2+(py-ay-t*dy)**2;
}
function hitNode(cx,cy){
  const wx=(cx-tx)/tk,wy=(cy-ty)/tk;
  for(let i=D.nodes.length-1;i>=0;i--){
    const n=D.nodes[i];const ddx=wx-n.x,ddy=wy-n.y;
    if(ddx*ddx+ddy*ddy<=n.r*n.r)return n;
  }return null;
}
function hitEdge(cx,cy){
  const wx=(cx-tx)/tk,wy=(cy-ty)/tk;
  const thresh=(6/tk)**2;
  for(let i=D.edges.length-1;i>=0;i--){
    const e=D.edges[i];const s=NM[e.srcId],t=NM[e.tgtId];
    if(!s||!t)continue;
    if(ptSegDist2(wx,wy,s.x,s.y,t.x,t.y)<=thresh)return e;
  }return null;
}
function nodeTip(n){return\`<b>\${n.id}</b><div class="tl">Traffic</div>\${fB(n.bytes)} · \${fN(n.packets)} pkts\${n.sessions?' · '+fN(n.sessions)+' sess':''}\${n.topProtos?'<div class="tl">Top protocols</div>'+n.topProtos:''}\`;}
function edgeTip(e){return\`<b>\${e.srcId} → \${e.tgtId}</b><div class="tl">Traffic</div>\${fB(e.bytes)} · \${fN(e.packets)} pkts · \${fN(e.sessions)} sess\${e.protocols?'<div class="tl">Protocols</div>'+e.protocols:''}\`;}
function showTip(x,y,html){tip.style.display='block';tip.style.left=(x+14)+'px';tip.style.top=(y-8)+'px';tip.innerHTML=html;}
window.addEventListener('resize',()=>{resize();draw();});
canvas.addEventListener('wheel',e=>{
  e.preventDefault();const f=e.deltaY<0?1.12:1/1.12;
  const ox=e.clientX,oy=e.clientY;
  tx=ox+(tx-ox)*f;ty=oy+(ty-oy)*f;tk*=f;draw();
},{passive:false});
canvas.addEventListener('mousedown',e=>{
  const n=hitNode(e.clientX,e.clientY);
  if(n){nodeDrag=n;hover=n;canvas.style.cursor='grabbing';draw();}
  else{panDrag=true;lx=e.clientX;ly=e.clientY;canvas.style.cursor='grabbing';}
});
canvas.addEventListener('mousemove',e=>{
  if(nodeDrag){
    nodeDrag.x=(e.clientX-tx)/tk;nodeDrag.y=(e.clientY-ty)/tk;
    draw();showTip(e.clientX,e.clientY,nodeTip(nodeDrag));return;
  }
  if(panDrag){tx+=e.clientX-lx;ty+=e.clientY-ly;lx=e.clientX;ly=e.clientY;draw();return;}
  const n=hitNode(e.clientX,e.clientY);
  const ed=n?null:hitEdge(e.clientX,e.clientY);
  const changed=n!==hover||ed!==hoverE;
  hover=n;hoverE=ed;
  canvas.style.cursor=n?'pointer':'default';
  if(changed)draw();
  if(n){showTip(e.clientX,e.clientY,nodeTip(n));}
  else if(ed){showTip(e.clientX,e.clientY,edgeTip(ed));}
  else{tip.style.display='none';}
});
canvas.addEventListener('mouseup',()=>{panDrag=false;nodeDrag=null;canvas.style.cursor=hover?'pointer':'default';});
canvas.addEventListener('mouseleave',()=>{panDrag=false;nodeDrag=null;tip.style.display='none';hover=null;hoverE=null;canvas.style.cursor='default';draw();});
resize();draw();
</script></body></html>`;

    const blob = new Blob([html], { type: 'text/html' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'swifteye-graph.html';
    a.click();
    URL.revokeObjectURL(a.href);
  }

  // ── Simulation setup ─────────────────────────────────────────────
  useEffect(() => {
    const { width, height } = getSize();

    if (!nodes.length) {
      const c = cRef.current;
      if (c) {
        const dpr = window.devicePixelRatio || 1;
        c.width = width * dpr;
        c.height = height * dpr;
        c.style.width = width + 'px';
        c.style.height = height + 'px';
        const x = c.getContext('2d');
        x.scale(dpr, dpr);
        x.fillStyle = getComputedStyle(document.body).getPropertyValue('--bg').trim() || '#08090d';
        x.fillRect(0, 0, width, height);
      }
      if (simRef.current) simRef.current.stop();
      nRef.current = [];
      eRef.current = [];
      return;
    }

    // Preserve positions from previous nodes
    const em = new Map();
    for (const n of nRef.current) em.set(n.id, n);

    const nn = nodes.map(n => {
      const e = em.get(n.id);
      return {
        ...n,
        x: e?.x ?? width / 2 + (Math.random() - 0.5) * 300,
        y: e?.y ?? height / 2 + (Math.random() - 0.5) * 300,
        vx: e?.vx ?? 0,
        vy: e?.vy ?? 0,
        fx: e?.fx ?? null,
        fy: e?.fy ?? null,
      };
    });

    const ids = new Set(nn.map(n => n.id));
    const ne = edges
      .filter(e => ids.has(e.source?.id || e.source) && ids.has(e.target?.id || e.target))
      .map(e => ({ ...e, source: e.source?.id || e.source, target: e.target?.id || e.target }));

    nRef.current = nn;
    eRef.current = ne;
    if (simRef.current) simRef.current.stop();

    const hasAnyClusters = nn.some(n => n.is_cluster);
    const nodeCount = nn.length;
    const chargeDistMax = hasAnyClusters ? 450
      : nodeCount > 200 ? 180
      : nodeCount > 50  ? 300
      : 400;
    const sim = d3.forceSimulation(nn)
      .force('charge', d3.forceManyBody()
        .strength(d => d.is_cluster ? -350 - (d.member_count || 0) * 18 : -180)
        .distanceMax(chargeDistMax))
      .force('link', d3.forceLink(ne).id(d => d.id)
        .distance(d => {
          const s = typeof d.source === 'object' ? d.source : null;
          const t = typeof d.target === 'object' ? d.target : null;
          if (s?.is_cluster || t?.is_cluster) return 200;
          return 130;
        })
        .strength(0.5))
      .force('center', d3.forceCenter(width / 2, height / 2).strength(0.05))
      .force('collision', d3.forceCollide().radius(d =>
        d.is_cluster ? gRRef.current(d) * 1.8 + 15 : gRRef.current(d) + 8))
      .force('x', d3.forceX(width / 2).strength(0.02))
      .force('y', d3.forceY(height / 2).strength(0.02))
      .alphaDecay(0.025)
      .on('tick', render)
      .on('end', () => {
        if (simRef.current) {
          simRef.current.force('charge').strength(
            d => d.is_cluster ? -70 - (d.member_count || 0) * 4 : -45
          );
        }
      });

    simRef.current = sim;

    const gR = gRRef.current;

    // ── Render function (reads container size each frame — FIX #1) ──
    function render() {
      const c = cRef.current;
      if (!c) return;
      const { width, height } = getSize();
      const ctx = c.getContext('2d');
      const dpr = window.devicePixelRatio || 1;

      c.width = width * dpr;
      c.height = height * dpr;
      c.style.width = width + 'px';
      c.style.height = height + 'px';
      ctx.scale(dpr, dpr);

      const cs = getComputedStyle(document.body);
      const cv = k => cs.getPropertyValue(k).trim();
      const bgColor       = cv('--bg')           || '#08090d';
      const nodePrivate   = cv('--node-private')  || '#264060';
      const nodePrivateS  = cv('--node-private-s')|| '#5a9ad5';
      const nodeExternal  = cv('--node-external') || '#3d2855';
      const nodeExternalS = cv('--node-external-s')|| '#9060cc';
      const nodeSubnet    = cv('--node-subnet')   || '#253545';
      const nodeSubnetS   = cv('--node-subnet-s') || '#557080';
      const nodeGateway   = cv('--node-gateway')  || '#3d3018';
      const nodeGatewayS  = cv('--node-gateway-s')|| '#e0b020';
      const nodeLabel     = cv('--node-label')    || '#a0aab5';
      const acColor       = cv('--ac')            || '#58a6ff';
      const acGColor      = cv('--acG')           || '#3fb950';

      const t = tRef.current;
      const ss = selNRef.current;
      const hs = ss.size > 0;
      const se = selERef.current;
      const pc = pcRef.current;
      const inv = invNodesRef.current;
      const dfN = dfNodesRef.current;
      const dfE = dfEdgesRef.current;

      ctx.fillStyle = bgColor;
      ctx.fillRect(0, 0, width, height);
      const vig = ctx.createRadialGradient(width/2, height/2, 0, width/2, height/2, Math.max(width, height) * 0.7);
      vig.addColorStop(0, 'rgba(0,0,0,0)');
      vig.addColorStop(1, 'rgba(0,0,0,0.10)');
      ctx.fillStyle = vig;
      ctx.fillRect(0, 0, width, height);
      ctx.save();
      ctx.translate(t.x, t.y);
      ctx.scale(t.k, t.k);

      // Grid
      if (t.k > 0.3) {
        const gs = 60;
        const sx = -t.x / t.k, sy = -t.y / t.k;
        const ex = sx + width / t.k, ey = sy + height / t.k;
        ctx.strokeStyle = 'rgba(128,128,128,0.04)';
        ctx.lineWidth = 1 / t.k;
        for (let x = Math.floor(sx / gs) * gs; x < ex; x += gs) {
          ctx.beginPath(); ctx.moveTo(x, sy); ctx.lineTo(x, ey); ctx.stroke();
        }
        for (let y = Math.floor(sy / gs) * gs; y < ey; y += gs) {
          ctx.beginPath(); ctx.moveTo(sx, y); ctx.lineTo(ex, y); ctx.stroke();
        }
      }

      // Edges
      const eSizeMode = edgeSizeModeRef.current;
      const eColorMode = edgeColorModeRef.current;
      const eColorRules = edgeColorRulesRef.current;
      const edgeMetric = e => {
        if (eSizeMode === 'packets')  return e.packet_count  || 0;
        if (eSizeMode === 'sessions') return e.session_count || 0;
        return e.total_bytes || 0;
      };
      const meb = Math.max(...eRef.current.map(edgeMetric), 1);
      for (const edge of eRef.current) {
        const src = typeof edge.source === 'object' ? edge.source : nRef.current.find(n => n.id === edge.source);
        const tgt = typeof edge.target === 'object' ? edge.target : nRef.current.find(n => n.id === edge.target);
        if (!src || !tgt) continue;
        const isSel = se?.id === edge.id;
        const w = Math.max(0.6, (edgeMetric(edge) / meb) * 10);
        const sId = typeof src === 'object' ? src.id : src;
        const tId = typeof tgt === 'object' ? tgt.id : tgt;
        const con = hs && (ss.has(sId) || ss.has(tId));
        const inInv = !inv || (inv.has(sId) && inv.has(tId));
        const inDf  = !dfE || dfE.has(edge.id);

        const resolvedCol = edge.synthetic ? (edge.color || '#f0883e') : resolveEdgeColor(edge, eColorMode, eColorRules, pc);
        const edgeColor = resolvedCol;
        const edgeW = edge.synthetic ? 2 : w;

        const qh = qhRef.current;
        const eqh = qh?.edges && (qh.edges.has(`${sId}|${tId}`) || qh.edges.has(`${tId}|${sId}`));

        if (!inInv || !inDf) { ctx.globalAlpha = 0.04; }
        else if (edge.synthetic) ctx.globalAlpha = isSel ? 1 : hs ? (con ? 1 : 0.35) : 0.85;
        else ctx.globalAlpha = isSel ? 1 : hs ? (con ? 0.9 : 0.2) : 0.85;

        ctx.beginPath();
        ctx.moveTo(src.x, src.y);
        ctx.lineTo(tgt.x, tgt.y);
        ctx.strokeStyle = isSel ? '#fff' : eqh ? '#f0883e' : edgeColor;
        ctx.lineWidth = isSel ? edgeW + 2 : eqh ? edgeW + 1.5 : edgeW;
        if (edge.synthetic) { ctx.setLineDash([6, 4]); } else { ctx.setLineDash([]); }
        ctx.stroke();
        ctx.setLineDash([]);
        if (isSel) {
          ctx.strokeStyle = edgeColor + '55';
          ctx.lineWidth = edgeW + 6;
          ctx.stroke();
        }

        // Arrowhead at midpoint when direction mode is on
        if (showEdgeDirectionRef?.current) {
          const mx = (src.x + tgt.x) / 2;
          const my = (src.y + tgt.y) / 2;
          const dx = tgt.x - src.x;
          const dy = tgt.y - src.y;
          const len = Math.sqrt(dx * dx + dy * dy);
          if (len > 0) {
            const ux = dx / len;
            const uy = dy / len;
            // Fixed screen-space size: 8px tip, 5px half-width, independent of edge weight
            const tip = 8 / tk;
            const hw  = 5 / tk;
            ctx.beginPath();
            ctx.moveTo(mx + ux * tip,          my + uy * tip);
            ctx.lineTo(mx - ux * tip - uy * hw, my - uy * tip + ux * hw);
            ctx.lineTo(mx - ux * tip + uy * hw, my - uy * tip - ux * hw);
            ctx.closePath();
            ctx.fillStyle = isSel ? '#fff' : eqh ? '#f0883e' : edgeColor;
            ctx.fill();
          }
        }

        ctx.globalAlpha = 1;
      }

      // Nodes
      for (const node of nRef.current) {
        const r = gR(node);
        const isSel = ss.has(node.id);
        const isH = hRef.current === node.id;
        const inInv = !inv || inv.has(node.id);
        const inDf  = !dfN || dfN.has(node.id);
        const isC = hs && eRef.current.some(e => {
          const s = typeof e.source === 'object' ? e.source.id : e.source;
          const t2 = typeof e.target === 'object' ? e.target.id : e.target;
          return (ss.has(s) && t2 === node.id) || (ss.has(t2) && s === node.id);
        });

        if (!inInv || !inDf) { ctx.globalAlpha = 0.05; }
        else ctx.globalAlpha = hs ? (isSel || isC ? 1 : 0.3) : 1;

        // Glow
        if (isSel || isH) {
          const gl = ctx.createRadialGradient(node.x, node.y, r, node.x, node.y, r * 3);
          gl.addColorStop(0, (isSel ? '#58a6ff' : '#3fb950') + '44');
          gl.addColorStop(1, 'transparent');
          ctx.fillStyle = gl;
          ctx.fillRect(node.x - r * 3, node.y - r * 3, r * 6, r * 6);
        }

        // Shape
        const isGateway = node.plugin_data?.network_role?.role === 'gateway';
        if (node.is_cluster) {
          const cc = CLUSTER_COLORS[(node.cluster_id || 0) % CLUSTER_COLORS.length];
          const hr = r * 1.8;
          ctx.beginPath();
          for (let i = 0; i < 6; i++) {
            const angle = (Math.PI / 3) * i - Math.PI / 6;
            const hx = node.x + hr * Math.cos(angle);
            const hy = node.y + hr * Math.sin(angle);
            if (i === 0) ctx.moveTo(hx, hy); else ctx.lineTo(hx, hy);
          }
          ctx.closePath();
          ctx.fillStyle = isSel ? cc + '44' : cc + '18';
          ctx.fill();
          ctx.strokeStyle = isSel ? '#fff' : isH ? acGColor : cc;
          ctx.lineWidth = isSel || isH ? 2.5 : 2;
          ctx.stroke();
          if (node.member_count && t.k > 0.3) {
            ctx.font = `bold ${Math.max(9, 11 / t.k)}px JetBrains Mono, monospace`;
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillStyle = cc;
            ctx.fillText(String(node.member_count), node.x, node.y);
          }
        } else if (node.is_subnet) {
          const s = r * 2.0;
          const rad = 4;
          ctx.beginPath();
          if (ctx.roundRect) {
            ctx.roundRect(node.x - s / 2, node.y - s / 2, s, s, rad);
          } else {
            ctx.rect(node.x - s / 2, node.y - s / 2, s, s);
          }
          ctx.fillStyle = isSel ? acColor + '33' : nodeSubnet;
          ctx.fill();
          ctx.strokeStyle = isSel ? acColor : isH ? acGColor : nodeSubnetS;
          ctx.lineWidth = isSel ? 2.5 : 1.5;
          ctx.setLineDash([4, 2]);
          ctx.stroke();
          ctx.setLineDash([]);
          const memberCount = node.ips?.length || node.member_count;
          if (memberCount && t.k > 0.3) {
            ctx.font = `bold ${Math.max(8, 10 / t.k)}px JetBrains Mono, monospace`;
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillStyle = nodeSubnetS;
            ctx.fillText(String(memberCount), node.x, node.y);
          }
        } else if (isGateway) {
          const s = r * 1.6;
          ctx.save();
          ctx.translate(node.x, node.y);
          ctx.rotate(Math.PI / 4);
          ctx.beginPath();
          ctx.rect(-s / 2, -s / 2, s, s);
          ctx.fillStyle = isSel ? acColor + '33' : nodeGateway;
          ctx.fill();
          ctx.strokeStyle = isSel ? acColor : isH ? acGColor : nodeGatewayS;
          ctx.lineWidth = isSel || isH ? 2.5 : 1.8;
          ctx.stroke();
          ctx.restore();
        } else {
          ctx.beginPath();
          ctx.arc(node.x, node.y, r, 0, Math.PI * 2);
          if (node.synthetic) {
            const nc = node.color || '#f0883e';
            ctx.fillStyle = isSel ? nc + '55' : nc + '22';
            ctx.fill();
            ctx.strokeStyle = isSel ? '#fff' : isH ? '#fff' : nc;
            ctx.lineWidth = isSel || isH ? 2.5 : 2;
            ctx.setLineDash([4, 3]);
            ctx.stroke();
            ctx.setLineDash([]);
          } else {
            const [nFill, nStroke] = resolveNodeColor(
              node, nodeColorModeRef.current, nodeColorRulesRef.current, pc,
              nodePrivate, nodePrivateS, nodeExternal, nodeExternalS,
            );
            ctx.fillStyle = isSel ? acColor + '33' : nFill;
            ctx.fill();
            ctx.strokeStyle = isSel ? acColor : isH ? acGColor : nStroke;
            ctx.lineWidth = isSel || isH ? 2.5 : 1.5;
            ctx.stroke();
          }
        }

        // Query highlight ring
        const qh = qhRef.current;
        if (qh && qh.nodes && qh.nodes.has(node.id)) {
          ctx.save();
          ctx.globalAlpha = 0.9;
          ctx.beginPath();
          ctx.arc(node.x, node.y, r + 4, 0, Math.PI * 2);
          ctx.strokeStyle = '#f0883e';
          ctx.lineWidth = 2.5;
          ctx.stroke();
          const qgl = ctx.createRadialGradient(node.x, node.y, r, node.x, node.y, r * 2.5);
          qgl.addColorStop(0, 'rgba(240,136,62,0.25)');
          qgl.addColorStop(1, 'transparent');
          ctx.fillStyle = qgl;
          ctx.fillRect(node.x - r * 2.5, node.y - r * 2.5, r * 5, r * 5);
          ctx.restore();
        }

        // Synthetic marker
        if (node.synthetic && t.k > 0.25) {
          const nc = node.color || '#f0883e';
          ctx.font = `bold ${Math.max(7, 8 / t.k)}px sans-serif`;
          ctx.textAlign = 'center';
          ctx.textBaseline = 'top';
          ctx.fillStyle = nc + 'dd';
          ctx.fillText('\u2726', node.x, node.y + r + 15);
        }

        // Label
        const thresh = labelThreshRef.current || 0;
        if (t.k > 0.45 && (thresh === 0 || (node.total_bytes || 0) >= thresh || isSel || isH)) {
          const fs = Math.max(8, 10 / t.k);
          ctx.font = `500 ${fs}px JetBrains Mono, monospace`;
          ctx.textAlign = 'center';
          ctx.textBaseline = 'top';
          const displayName = node.metadata?.name
            || (node.hostnames?.length ? node.hostnames[0] : null)
            || ((node.synthetic || node.is_cluster) && node.label ? node.label : null);
          const rawId = (node.synthetic || node.is_cluster) && node.label ? node.label : node.id;
          const lb = displayName
            ? (displayName.length > 22 ? displayName.slice(0, 20) + '\u2026' : displayName)
            : (rawId.length > 22 ? rawId.slice(0, 20) + '\u2026' : rawId);
          ctx.fillStyle = 'rgba(0,0,0,0.7)';
          ctx.fillText(lb, node.x + 0.5, node.y + r + 5.5);
          ctx.fillStyle = displayName ? '#22d3ee' : isSel ? acColor : isH ? '#e6edf3' : nodeLabel;
          ctx.fillText(lb, node.x, node.y + r + 5);
        }
        ctx.globalAlpha = 1;
      }
      ctx.restore();
    }

    renRef.current = render;
    return () => sim.stop();
  }, [nodes, edges]);

  return { simRef, nRef, eRef, gRRef, doRelayout, doExportHTML, getSize };
}
