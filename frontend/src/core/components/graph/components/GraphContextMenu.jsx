import React, { useRef, useLayoutEffect, useState } from 'react';

// ── Primitives ────────────────────────────────────────────────────────────────

function MenuItem({ icon, onClick, children, danger = false }) {
  return (
    <div onClick={onClick} style={{
      padding: '7px 12px', fontSize: 12, cursor: 'pointer',
      display: 'flex', alignItems: 'center', gap: 8,
      color: danger ? 'var(--acR)' : 'var(--tx)',
    }}
      onMouseEnter={e => e.currentTarget.style.background = 'rgba(88,166,255,.1)'}
      onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
    >
      {icon}<span>{children}</span>
    </div>
  );
}

function MenuDivider() {
  return <div style={{ height: 1, background: 'var(--bd)', margin: '3px 0' }} />;
}

const MENU_STYLE = {
  background: 'var(--bgC)',
  border: '1px solid var(--bdL)',
  borderRadius: 7,
  padding: '4px 0',
  minWidth: 170,
  boxShadow: '0 4px 16px rgba(0,0,0,.4)',
  fontFamily: 'var(--fn)',
};

function SubMenu({ icon, label, children }) {
  const [open, setOpen] = useState(false);
  const flyRef = useRef(null);
  const rowRef = useRef(null);
  const [flyLeft, setFlyLeft] = useState(false);

  useLayoutEffect(() => {
    if (!open || !flyRef.current || !rowRef.current) return;
    const flyRect = flyRef.current.getBoundingClientRect();
    setFlyLeft(flyRect.right > window.innerWidth - 8);
  }, [open]);

  return (
    <div
      ref={rowRef}
      style={{ position: 'relative' }}
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
    >
      <div style={{
        padding: '7px 12px', fontSize: 12, color: 'var(--tx)', cursor: 'default',
        display: 'flex', alignItems: 'center', gap: 8,
      }}
        onMouseEnter={e => e.currentTarget.style.background = 'rgba(88,166,255,.1)'}
        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
      >
        {icon}
        <span style={{ flex: 1 }}>{label}</span>
        <svg width="8" height="8" viewBox="0 0 8 8" fill="none" style={{ opacity: 0.5, flexShrink: 0 }}>
          <path d="M2 1l4 3-4 3" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </div>
      {open && (
        <div ref={flyRef} style={{
          ...MENU_STYLE,
          position: 'absolute',
          top: -4,
          ...(flyLeft ? { right: '100%' } : { left: '100%' }),
          zIndex: 200,
        }}>
          {children}
        </div>
      )}
    </div>
  );
}

// ── Main component ─────────────────────────────────────────────────────────────

export default function GraphContextMenu({
  ctxMenu, setCtxMenu, cRef, eRef, selNRef,
  onSelRef, onInvRef, onInvNbRef,
  onAnimate, onFlagNode, onFlagEdge, onHideNode,
  onDeleteSynthetic, onStartPathfind,
  onExpandCluster, onUnclusterSubnet, onCreateManualCluster,
  onAddNodeAnnotation, onAddEdgeAnnotation, onAddAnnotation,
  setShowSyntheticNodeForm, setShowSyntheticEdgeForm, setSynEdgeSrc,
  onSetRadialFocus,
  onSetHierarchyRoot,
}) {
  const menuRef = useRef(null);

  useLayoutEffect(() => {
    const el = menuRef.current;
    const container = cRef.current?.parentElement;
    if (!el || !container || !ctxMenu) return;
    const cW = container.clientWidth;
    const cH = container.clientHeight;
    const mW = el.offsetWidth;
    const mH = el.offsetHeight;
    let x = ctxMenu.x + 2;
    let y = ctxMenu.y + 2;
    if (x + mW > cW) x = Math.max(0, ctxMenu.x - mW - 2);
    if (y + mH > cH) y = Math.max(0, ctxMenu.y - mH - 2);
    el.style.left = x + 'px';
    el.style.top = y + 'px';
  }, [ctxMenu]);

  const close = () => setCtxMenu(null);

  return (
    <>
      <div
        style={{ position: 'absolute', inset: 0, zIndex: 99 }}
        onClick={close}
        onContextMenu={e => { e.preventDefault(); close(); }}
      />
      <div ref={menuRef} style={{
        ...MENU_STYLE,
        position: 'absolute',
        left: ctxMenu.x + 2,
        top: ctxMenu.y + 2,
        zIndex: 100,
      }}>

        {/* ── NODE / CLUSTER ── */}
        {ctxMenu.nodeId ? (
          <>
            {/* Header */}
            <div style={{
              padding: '5px 12px 6px', borderBottom: '1px solid var(--bd)',
              fontSize: 10, color: 'var(--txD)',
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
              display: 'flex', alignItems: 'center', gap: 4,
            }}>
              {ctxMenu.isSynthetic && <span style={{ fontSize: 9, color: '#f0883e', border: '1px solid #f0883e', borderRadius: 3, padding: '0 3px' }}>synthetic</span>}
              {ctxMenu.isCluster && <span style={{ fontSize: 9, color: '#bc8cff', border: '1px solid #bc8cff', borderRadius: 3, padding: '0 3px' }}>cluster</span>}
              {ctxMenu.nodeLabel}
            </div>

            {/* Detail — top-level, most common action */}
            <MenuItem
              icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--txM)" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/></svg>}
              onClick={() => { onSelRef.current('node', ctxMenu.nodeId, false); close(); }}>
              {ctxMenu.isCluster ? 'Cluster detail' : 'Node detail'}
            </MenuItem>

            <MenuDivider />

            {/* Investigate submenu */}
            <SubMenu
              icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#58a6ff" strokeWidth="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>}
              label="Investigate"
            >
              <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#58a6ff" strokeWidth="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>}
                onClick={() => { onInvNbRef.current?.(ctxMenu.nodeId); close(); }}>Neighbours</MenuItem>
              {!ctxMenu.isCluster && (
                <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#2dd4bf" strokeWidth="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/><line x1="11" y1="8" x2="11" y2="14"/><line x1="8" y1="11" x2="14" y2="11"/></svg>}
                  onClick={() => { onInvRef.current?.(ctxMenu.nodeId); close(); }}>Isolate connected graph</MenuItem>
              )}
              {!ctxMenu.isCluster && !ctxMenu.isSubnet && (
                <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#e3b341" strokeWidth="2"><circle cx="5" cy="19" r="3"/><circle cx="19" cy="5" r="3"/><path d="M5 16V9a4 4 0 014-4h6"/><polyline points="15 1 19 5 15 9"/></svg>}
                  onClick={() => { onStartPathfind?.(ctxMenu.nodeId); close(); }}>Find paths to…</MenuItem>
              )}
              {onAnimate && !ctxMenu.isCluster && !ctxMenu.isSubnet && (
                <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#6ab4ff" strokeWidth="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>}
                  onClick={() => { onAnimate([ctxMenu.nodeId]); close(); }}>Animate timeline</MenuItem>
              )}
            </SubMenu>

            {/* Layout submenu — only if at least one layout option applies */}
            {!ctxMenu.isCluster && !ctxMenu.isSubnet && (onSetRadialFocus || onSetHierarchyRoot) && (
              <SubMenu
                icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--txM)" strokeWidth="2"><circle cx="12" cy="12" r="3"/><circle cx="12" cy="12" r="9"/></svg>}
                label="Layout"
              >
                {onSetRadialFocus && (
                  <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#a78bfa" strokeWidth="2"><circle cx="12" cy="12" r="3"/><circle cx="12" cy="12" r="8"/><line x1="12" y1="2" x2="12" y2="4"/><line x1="12" y1="20" x2="12" y2="22"/><line x1="2" y1="12" x2="4" y2="12"/><line x1="20" y1="12" x2="22" y2="12"/></svg>}
                    onClick={() => { onSetRadialFocus(ctxMenu.nodeId); close(); }}>Set as radial focus</MenuItem>
                )}
                {onSetHierarchyRoot && (
                  <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#f0883e" strokeWidth="2"><line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"/><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"/><line x1="2" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="22" y2="12"/><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"/><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"/></svg>}
                    onClick={() => { onSetHierarchyRoot(ctxMenu.nodeId); close(); }}>Set as hierarchy root</MenuItem>
                )}
              </SubMenu>
            )}

            <MenuDivider />

            {/* Annotate submenu */}
            <SubMenu
              icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#bc8cff" strokeWidth="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 013 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>}
              label="Annotate"
            >
              <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#58a6ff" strokeWidth="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 013 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>}
                onClick={() => { onAddNodeAnnotation?.(ctxMenu.nodeId, ctxMenu.nodeLabel); close(); }}>Add annotation</MenuItem>
              {!ctxMenu.isCluster && !ctxMenu.isSubnet && (
                <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#f85149" strokeWidth="2"><path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/></svg>}
                  onClick={() => { onFlagNode?.(ctxMenu.nodeId); close(); }}>Flag as Event</MenuItem>
              )}
            </SubMenu>

            {/* Edit submenu */}
            <SubMenu
              icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--txD)" strokeWidth="2"><path d="M17 3a2.828 2.828 0 114 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>}
              label="Edit"
            >
              <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--txD)" strokeWidth="2"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg>}
                onClick={() => { onHideNode?.(ctxMenu.nodeId); close(); }}>
                {ctxMenu.isCluster ? 'Hide cluster' : 'Hide node'}
              </MenuItem>
              {!ctxMenu.isCluster && (
                <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#3fb950" strokeWidth="2"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>}
                  onClick={() => { setSynEdgeSrc(ctxMenu.nodeId); close(); setShowSyntheticEdgeForm(true); }}>Draw edge from here</MenuItem>
              )}
              {ctxMenu.isCluster && (
                <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#d29922" strokeWidth="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>}
                  onClick={() => { onExpandCluster?.(ctxMenu.clusterId); close(); }}>Expand cluster</MenuItem>
              )}
              {ctxMenu.isSubnet && (
                <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#d29922" strokeWidth="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>}
                  onClick={() => { onUnclusterSubnet?.(ctxMenu.nodeId); close(); }}>Uncluster subnet</MenuItem>
              )}
              {ctxMenu.isSynthetic && (
                <MenuItem danger icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--acR)" strokeWidth="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/></svg>}
                  onClick={() => { onDeleteSynthetic?.(ctxMenu.nodeId); close(); }}>Delete synthetic</MenuItem>
              )}
            </SubMenu>
          </>

        /* ── EDGE ── */
        ) : ctxMenu.edgeId ? (
          <>
            <div style={{
              padding: '5px 12px 6px', borderBottom: '1px solid var(--bd)',
              fontSize: 10, color: 'var(--txD)',
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
              display: 'flex', alignItems: 'center', gap: 4,
            }}>
              {ctxMenu.isSyntheticEdge && <span style={{ fontSize: 9, color: '#f0883e', border: '1px solid #f0883e', borderRadius: 3, padding: '0 3px' }}>synthetic</span>}
              Edge
            </div>

            <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--txM)" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/></svg>}
              onClick={() => { const ed = eRef.current.find(e => e.id === ctxMenu.edgeId); if (ed) onSelRef.current('edge', ed, false); close(); }}>Edge detail</MenuItem>

            <MenuDivider />

            <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#bc8cff" strokeWidth="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 013 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>}
              onClick={() => { onAddEdgeAnnotation?.(ctxMenu.edgeId); close(); }}>Add annotation</MenuItem>

            {!ctxMenu.isSyntheticEdge && (
              <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#f85149" strokeWidth="2"><path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/></svg>}
                onClick={() => { onFlagEdge?.(ctxMenu.edgeId); close(); }}>Flag as Event</MenuItem>
            )}

            {ctxMenu.isSyntheticEdge && (
              <>
                <MenuDivider />
                <MenuItem danger icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--acR)" strokeWidth="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/></svg>}
                  onClick={() => { onDeleteSynthetic?.(ctxMenu.edgeId); close(); }}>Delete synthetic</MenuItem>
              </>
            )}
          </>

        /* ── CANVAS ── */
        ) : (
          <>
            {selNRef.current.size >= 2 && (
              <>
                <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#bc8cff" strokeWidth="2"><circle cx="5" cy="12" r="2"/><circle cx="12" cy="5" r="2"/><circle cx="19" cy="12" r="2"/><circle cx="12" cy="19" r="2"/><line x1="7" y1="12" x2="10" y2="12"/><line x1="12" y1="7" x2="12" y2="10"/><line x1="14" y1="12" x2="17" y2="12"/><line x1="12" y1="14" x2="12" y2="17"/></svg>}
                  onClick={() => { onCreateManualCluster?.(Array.from(selNRef.current)); close(); }}>
                  Group selected ({selNRef.current.size} nodes)
                </MenuItem>
                <MenuDivider />
              </>
            )}
            <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#f0883e" strokeWidth="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 013 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>}
              onClick={() => { onAddAnnotation?.(ctxMenu.canvasX, ctxMenu.canvasY); close(); }}>Add annotation</MenuItem>
            <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#3fb950" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/></svg>}
              onClick={() => { close(); setShowSyntheticNodeForm(true); }}>Add synthetic node</MenuItem>
            <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#3fb950" strokeWidth="2"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>}
              onClick={() => { close(); setShowSyntheticEdgeForm(true); setSynEdgeSrc(''); }}>Add synthetic edge</MenuItem>
          </>
        )}
      </div>
    </>
  );
}
