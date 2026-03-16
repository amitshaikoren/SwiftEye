import React from 'react';
import Tag from './Tag';
import { fN } from '../utils';
import logoIconData from '../logoIconData.js';
import logoWordmarkData from '../logoWordmarkData.js';
import { VERSION } from '../version.js';

export default function TopBar({
  fileName, sourceFiles = [], stats, search, setSearch,
  onNewFile, onMetadataFile, onSettings,
}) {
  const isMulti = sourceFiles.length > 1;
  const fileTitle = isMulti ? sourceFiles.join('\n') : fileName;

  return (
    <div style={{
      height: 54, background: 'var(--bgP)', borderBottom: '1px solid var(--bd)',
      display: 'flex', alignItems: 'center', padding: '0 14px', gap: 10, flexShrink: 0,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <img src={logoIconData} alt="SwiftEye icon" style={{ height: 46, objectFit: 'contain' }} />
        <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
          <img src={logoWordmarkData} alt="SwiftEye" style={{ height: 24, objectFit: 'contain', objectPosition: 'left' }} />
          <span style={{ fontSize: 8, color: 'var(--txD)', letterSpacing: '.06em', fontFamily: 'var(--fn)' }}>v{VERSION}</span>
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
      <Tag color="var(--ac)">{fN(stats?.total_packets)} pkts</Tag>
      <div style={{ flex: 1 }} />

      {/* Search */}
      <div style={{ position: 'relative' }}>
        <svg style={{ position: 'absolute', left: 8, top: '50%', transform: 'translateY(-50%)' }}
          width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--txD)" strokeWidth="2">
          <circle cx="11" cy="11" r="8" /><path d="M21 21l-4.35-4.35" />
        </svg>
        <input className="inp" placeholder="Search — IPs, MACs, hostnames, protocols, ports, flags…"
          value={search} onChange={e => setSearch(e.target.value)} style={{ width: 340, paddingLeft: 28 }} />
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
