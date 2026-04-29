import React, { useState, useRef, useEffect } from 'react';
import Tag from './Tag';
import { fN } from '../utils';
import logoIconData from '../../logoIconData.js';
import logoWordmarkData from '../../logoWordmarkData.js';
import { VERSION } from '../../version.js';
import { selectWorkspace } from '../api';
import { useWorkspace } from '@/WorkspaceProvider';

export default function TopBar({
  fileName, sourceFiles = [], stats, search, setSearch,
  searchResult, onSelectNode, onSelectEdge,
  onNewFile, onMetadataFile, onSettings, onLogoClick,
  // Workspace switcher
  workspaceName, availableWorkspaces = [],
  // If provided, replaces the default "pkts" stat tag.
  // Array of { value, label } objects.
  topBarStats,
}) {
  const workspace = useWorkspace();
  const searchPlaceholder = workspace.searchPlaceholder || 'Search…';

  const isMulti = sourceFiles.length > 1;
  const fileTitle = isMulti ? sourceFiles.join('\n') : fileName;
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const dropRef = useRef(null);
  const [wsDropOpen, setWsDropOpen] = useState(false);
  const wsDropRef = useRef(null);
  const [wsSwitching, setWsSwitching] = useState(false);

  const searchInputRef = useRef(null);

  // Open search dropdown when search has results AND the input is focused
  useEffect(() => {
    const isFocused = document.activeElement === searchInputRef.current;
    if (isFocused && search && searchResult && (searchResult.totalNodes > 0 || searchResult.totalEdges > 0)) {
      setDropdownOpen(true);
    } else if (!search) {
      setDropdownOpen(false);
    }
  }, [search, searchResult]);

  // Close search dropdown on click outside
  useEffect(() => {
    if (!dropdownOpen) return;
    const handler = e => { if (dropRef.current && !dropRef.current.contains(e.target)) setDropdownOpen(false); };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [dropdownOpen]);

  // Close workspace dropdown on click outside
  useEffect(() => {
    if (!wsDropOpen) return;
    const handler = e => { if (wsDropRef.current && !wsDropRef.current.contains(e.target)) setWsDropOpen(false); };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [wsDropOpen]);

  async function handleSwitchWorkspace(name) {
    if (name === workspaceName || wsSwitching) return;
    setWsSwitching(true);
    try {
      await selectWorkspace(name);
      window.location.reload();
    } catch {
      setWsSwitching(false);
    }
  }

  const sr = searchResult || {};
  const mNodes = sr.matchedNodes || [];
  const mEdges = sr.matchedEdges || [];

  return (
    <div style={{
      height: 54, background: 'var(--bgP)', borderBottom: '1px solid var(--bd)',
      display: 'flex', alignItems: 'center', padding: '0 14px', gap: 10, flexShrink: 0,
    }}>
      <div
        onClick={onLogoClick}
        style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: onLogoClick ? 'pointer' : 'default' }}
        title={onLogoClick ? 'Back to overview' : undefined}
      >
        <img src={logoIconData} alt="SwiftEye icon" style={{ height: 46, objectFit: 'contain' }} />
        <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
          <img src={logoWordmarkData} alt="SwiftEye" style={{ height: 24, objectFit: 'contain', objectPosition: 'left' }} />
          <span style={{ fontSize: 9, color: 'var(--txD)', letterSpacing: '.06em', fontFamily: 'var(--fn)' }}>v{VERSION}</span>
        </div>
      </div>
      <div style={{ width: 1, height: 20, background: 'var(--bd)' }} />
      <span title={fileTitle} style={{
        fontSize: 11, color: 'var(--txM)', maxWidth: 200,
        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        cursor: isMulti ? 'help' : 'default',
      }}>
        {isMulti
          ? <><span style={{ color: 'var(--ac)', fontWeight: 600 }}>{sourceFiles.length} files</span></>
          : fileName}
      </span>

      {/* Stats — workspace-specific or default packet count */}
      {topBarStats ? (
        topBarStats.map(({ value, label }) => (
          <Tag key={label} color="var(--ac)">{value} {label}</Tag>
        ))
      ) : (
        <Tag color="var(--ac)">{fN(stats?.total_packets)} pkts</Tag>
      )}

      {/* Workspace switcher */}
      {availableWorkspaces.length > 1 && (
        <div style={{ position: 'relative' }} ref={wsDropRef}>
          <button
            className="btn"
            onClick={() => setWsDropOpen(o => !o)}
            disabled={wsSwitching}
            title="Switch workspace"
            style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 10 }}
          >
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M8 3H5a2 2 0 00-2 2v3M21 8V5a2 2 0 00-2-2h-3M3 16v3a2 2 0 002 2h3M16 21h3a2 2 0 002-2v-3" />
            </svg>
            {wsSwitching ? '…' : 'Switch'}
          </button>
          {wsDropOpen && (
            <div style={{
              position: 'absolute', top: '100%', left: 0, marginTop: 4, zIndex: 200,
              background: 'var(--bgP)', border: '1px solid var(--bd)', borderRadius: 6,
              boxShadow: '0 8px 24px rgba(0,0,0,.4)', minWidth: 130, overflow: 'hidden',
            }}>
              {availableWorkspaces.map(ws => {
                const isActive = ws.name === workspaceName;
                return (
                  <div
                    key={ws.name}
                    onClick={() => { setWsDropOpen(false); handleSwitchWorkspace(ws.name); }}
                    style={{
                      padding: '8px 12px', cursor: isActive ? 'default' : 'pointer',
                      fontSize: 12, color: isActive ? 'var(--txD)' : 'var(--txM)',
                      display: 'flex', alignItems: 'center', gap: 6,
                      transition: 'background .1s',
                    }}
                    onMouseEnter={e => { if (!isActive) e.currentTarget.style.background = 'rgba(88,166,255,.06)'; }}
                    onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; }}
                  >
                    {isActive && (
                      <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--ac)', flexShrink: 0 }} />
                    )}
                    {!isActive && <span style={{ width: 6 }} />}
                    {ws.label || ws.name}
                    {isActive && <span style={{ fontSize: 9, color: 'var(--txD)', marginLeft: 'auto' }}>active</span>}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      <div style={{ flex: 1 }} />

      {/* Search with dropdown */}
      <div style={{ position: 'relative' }} ref={dropRef}>
        <svg style={{ position: 'absolute', left: 8, top: '50%', transform: 'translateY(-50%)', zIndex: 1 }}
          width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--txD)" strokeWidth="2">
          <circle cx="11" cy="11" r="8" /><path d="M21 21l-4.35-4.35" />
        </svg>
        <input ref={searchInputRef} className="inp" placeholder={searchPlaceholder}
          value={search}
          onChange={e => setSearch(e.target.value)}
          onFocus={() => { if (search && searchResult) setDropdownOpen(true); }}
          style={{ width: 340, paddingLeft: 28, paddingRight: search ? 26 : 8 }} />
        {search && (
          <button onClick={() => { setSearch(''); setDropdownOpen(false); }}
            style={{
              position: 'absolute', right: 4, top: '50%', transform: 'translateY(-50%)', zIndex: 1,
              background: 'none', border: 'none', cursor: 'pointer', padding: '2px 4px',
              color: 'var(--txD)', fontSize: 14, lineHeight: 1, fontFamily: 'var(--fn)',
            }}
            title="Clear search">×</button>
        )}

        {/* Dropdown */}
        {dropdownOpen && (mNodes.length > 0 || mEdges.length > 0) && (
          <div style={{
            position: 'absolute', top: '100%', left: 0, right: 0, marginTop: 4, zIndex: 200,
            background: 'var(--bgP)', border: '1px solid var(--bd)', borderRadius: 6,
            boxShadow: '0 8px 24px rgba(0,0,0,.4)', maxHeight: 320, overflowY: 'auto',
          }}>
            {/* Nodes */}
            {mNodes.length > 0 && (
              <>
                <div style={{ padding: '4px 10px', fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: '.08em', background: 'var(--bgC)' }}>
                  Nodes ({sr.totalNodes})
                </div>
                {mNodes.map(({ node: n, reason }) => (
                  <div key={n.id}
                    onClick={() => { onSelectNode?.(n.id); setDropdownOpen(false); }}
                    style={{
                      padding: '6px 10px', cursor: 'pointer', borderBottom: '1px solid var(--bd)',
                      display: 'flex', alignItems: 'center', gap: 8,
                      transition: 'background .1s',
                    }}
                    onMouseEnter={e => e.currentTarget.style.background = 'rgba(88,166,255,.06)'}
                    onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                  >
                    <span style={{ width: 7, height: 7, borderRadius: '50%', background: n.is_private ? 'var(--node-private)' : 'var(--node-external)', flexShrink: 0 }} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 11, color: 'var(--txM)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {n.hostnames?.[0] || n.label || n.id}
                      </div>
                      {n.hostnames?.[0] && n.id !== n.hostnames[0] && (
                        <div style={{ fontSize: 9, color: 'var(--txD)', fontFamily: 'var(--fn)' }}>{n.id}</div>
                      )}
                    </div>
                    <span style={{ fontSize: 9, color: 'var(--acG)', flexShrink: 0 }}>{reason}</span>
                  </div>
                ))}
                {sr.totalNodes > 20 && (
                  <div style={{ padding: '4px 10px', fontSize: 9, color: 'var(--txD)', textAlign: 'center' }}>
                    +{sr.totalNodes - 20} more nodes
                  </div>
                )}
              </>
            )}
            {/* Edges */}
            {mEdges.length > 0 && (
              <>
                <div style={{ padding: '4px 10px', fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: '.08em', background: 'var(--bgC)' }}>
                  Edges ({sr.totalEdges})
                </div>
                {mEdges.map(({ edge: e, reason }) => {
                  const src = e.source?.id || e.source;
                  const tgt = e.target?.id || e.target;
                  return (
                    <div key={e.id}
                      onClick={() => { onSelectEdge?.(e); setDropdownOpen(false); }}
                      style={{
                        padding: '6px 10px', cursor: 'pointer', borderBottom: '1px solid var(--bd)',
                        display: 'flex', alignItems: 'center', gap: 8,
                        transition: 'background .1s',
                      }}
                      onMouseEnter={ev => ev.currentTarget.style.background = 'rgba(88,166,255,.06)'}
                      onMouseLeave={ev => ev.currentTarget.style.background = 'transparent'}
                    >
                      <span style={{ width: 14, height: 2, background: 'var(--ac)', flexShrink: 0 }} />
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: 11, color: 'var(--txM)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {src} → {tgt}
                        </div>
                        <div style={{ fontSize: 9, color: 'var(--txD)' }}>{e.protocol}</div>
                      </div>
                      <span style={{ fontSize: 9, color: 'var(--acG)', flexShrink: 0 }}>{reason}</span>
                    </div>
                  );
                })}
                {sr.totalEdges > 20 && (
                  <div style={{ padding: '4px 10px', fontSize: 9, color: 'var(--txD)', textAlign: 'center' }}>
                    +{sr.totalEdges - 20} more edges
                  </div>
                )}
              </>
            )}
          </div>
        )}
      </div>

      <button className="btn" onClick={onSettings} title="Settings"
        style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="12" cy="12" r="3" />
          <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z" />
        </svg>
      </button>
      <button className="btn" onClick={onMetadataFile} title="Load researcher metadata JSON"
        style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" /><path d="M14 2v6h6" /><path d="M12 18v-6M9 15l3 3 3-3" />
        </svg>
        META
      </button>
      <button className="btn" onClick={onNewFile}
        style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M17 8l-5-5-5 5M12 3v12" />
        </svg>
        NEW
      </button>
    </div>
  );
}
