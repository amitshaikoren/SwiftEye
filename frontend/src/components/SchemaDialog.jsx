import React, { useState, useMemo } from 'react';

/**
 * SchemaDialog — shown when the backend returns schema_negotiation_required=true.
 *
 * Props:
 *   report         — the schema_report object from the upload response
 *   stagingToken   — token to resume ingestion (passed to confirmSchemaMapping)
 *   fileName       — display name of the file being ingested
 *   onConfirm(mapping) — called with the final {actual_col: expected_field} mapping
 *   onCancel()     — called when the user dismisses without confirming
 *   loading        — true while the confirm request is in-flight
 */
export default function SchemaDialog({ report, stagingToken, fileName, onConfirm, onCancel, loading }) {
  const { detected_columns = [], declared_fields = [], missing_required = [],
          missing_optional = [], unknown_columns = [], suggested_mappings = {} } = report;

  // mapping state: {actual_col: expected_field | ""}
  // Pre-populate from suggested_mappings.
  const [mapping, setMapping] = useState(() => {
    const init = {};
    for (const col of detected_columns) {
      init[col] = suggested_mappings[col] || '';
    }
    return init;
  });

  const expectedOptions = useMemo(() => {
    return ['', ...declared_fields.map(f => f.name)];
  }, [declared_fields]);

  // Which required fields are still unmapped?
  const unmappedRequired = useMemo(() => {
    const mappedTargets = new Set(Object.values(mapping).filter(Boolean));
    return missing_required.filter(r => !mappedTargets.has(r));
  }, [mapping, missing_required]);

  const canConfirm = unmappedRequired.length === 0;

  function handleSet(actualCol, expectedField) {
    setMapping(prev => ({ ...prev, [actualCol]: expectedField }));
  }

  function handleConfirm() {
    // Strip empty mappings — pass only the user-confirmed renames.
    const finalMapping = {};
    for (const [k, v] of Object.entries(mapping)) {
      if (v) finalMapping[k] = v;
    }
    onConfirm(finalMapping);
  }

  const fieldMap = useMemo(() => {
    const m = {};
    for (const f of declared_fields) m[f.name] = f;
    return m;
  }, [declared_fields]);

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 2000,
      background: 'rgba(0,0,0,0.65)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}>
      <div style={{
        width: 680, maxHeight: '90vh', background: 'var(--bgP)',
        border: '1px solid var(--bd)', borderRadius: 12,
        display: 'flex', flexDirection: 'column',
        boxShadow: '0 24px 60px rgba(0,0,0,0.6)',
      }}>
        {/* Header */}
        <div style={{ padding: '18px 22px 14px', borderBottom: '1px solid var(--bd)', flexShrink: 0 }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
            <div>
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--tx)', marginBottom: 4 }}>
                Column Mapping Required
              </div>
              <div style={{ fontSize: 11, color: 'var(--txM)', lineHeight: 1.5 }}>
                <span style={{ color: 'var(--txD)' }}>{fileName}</span> uses column names that
                differ from what SwiftEye expects for this format.
                Map each detected column to the field it represents, then confirm to ingest.
              </div>
            </div>
            <button className="btn" onClick={onCancel} style={{ flexShrink: 0, marginTop: 2 }}>✕</button>
          </div>

          {/* Missing required banner */}
          {missing_required.length > 0 && (
            <div style={{
              marginTop: 12, padding: '8px 12px', borderRadius: 6,
              background: 'rgba(248,81,73,.08)', border: '1px solid rgba(248,81,73,.3)',
              fontSize: 11, color: 'var(--acR)', lineHeight: 1.5,
            }}>
              <strong>Required columns not found:</strong>{' '}
              {missing_required.join(', ')}.
              {' '}Map them below before confirming.
            </div>
          )}
        </div>

        {/* Scrollable body */}
        <div style={{ overflowY: 'auto', flex: 1, padding: '12px 22px' }}>

          {/* Detected columns table */}
          <div style={{ marginBottom: 8 }}>
            <div style={{
              fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase',
              letterSpacing: '.08em', marginBottom: 8,
            }}>
              Detected columns ({detected_columns.length})
            </div>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr>
                  {['Detected column', 'Map to SwiftEye field', 'Status'].map(h => (
                    <th key={h} style={{
                      textAlign: 'left', fontSize: 10, fontWeight: 600,
                      color: 'var(--txD)', padding: '4px 8px',
                      borderBottom: '1px solid var(--bd)',
                    }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {detected_columns.map(col => {
                  const mapped = mapping[col] || '';
                  const isKnown = !!fieldMap[col];
                  const isSuggested = !!suggested_mappings[col] && mapped === suggested_mappings[col];
                  const targetField = fieldMap[mapped];
                  const isRequired = targetField?.required;

                  let statusColor = 'var(--txD)';
                  let statusText = 'unmapped';
                  if (isKnown && !mapped) {
                    statusColor = 'var(--ac)';
                    statusText = 'matched';
                  } else if (mapped) {
                    statusColor = isSuggested ? 'var(--acP)' : 'var(--acG)';
                    statusText = isSuggested ? 'suggested' : 'mapped';
                  }

                  return (
                    <tr key={col} style={{ borderBottom: '1px solid rgba(255,255,255,.04)' }}>
                      <td style={{ padding: '6px 8px', fontSize: 11, fontFamily: 'monospace', color: 'var(--tx)' }}>
                        {col}
                        {unknown_columns.includes(col) && (
                          <span style={{
                            marginLeft: 6, fontSize: 9, padding: '1px 5px', borderRadius: 4,
                            background: 'rgba(255,166,0,.1)', color: '#ffa600', border: '1px solid rgba(255,166,0,.25)',
                          }}>unknown</span>
                        )}
                      </td>
                      <td style={{ padding: '6px 8px' }}>
                        {isKnown && !mapped ? (
                          <span style={{ fontSize: 11, color: 'var(--txD)', fontStyle: 'italic' }}>
                            (same name — no remapping needed)
                          </span>
                        ) : (
                          <select
                            value={mapped}
                            onChange={e => handleSet(col, e.target.value)}
                            style={{
                              background: 'var(--bgH)', border: '1px solid var(--bd)',
                              borderRadius: 4, padding: '3px 6px', fontSize: 11,
                              color: 'var(--tx)', outline: 'none', cursor: 'pointer',
                              width: '100%',
                            }}
                          >
                            {expectedOptions.map(opt => (
                              <option key={opt} value={opt}>
                                {opt || '— no mapping —'}
                                {opt && fieldMap[opt]?.required ? ' *' : ''}
                              </option>
                            ))}
                          </select>
                        )}
                      </td>
                      <td style={{ padding: '6px 8px', fontSize: 10, color: statusColor }}>{statusText}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Still-missing required fields hint */}
          {unmappedRequired.length > 0 && (
            <div style={{
              marginTop: 12, padding: '8px 12px', borderRadius: 6,
              background: 'rgba(248,81,73,.06)', border: '1px solid rgba(248,81,73,.2)',
              fontSize: 11, color: 'var(--txM)', lineHeight: 1.6,
            }}>
              Still need to map:{' '}
              <span style={{ color: 'var(--acR)' }}>{unmappedRequired.join(', ')}</span>
            </div>
          )}

          {/* Legend */}
          <div style={{ marginTop: 16, fontSize: 10, color: 'var(--txD)', lineHeight: 1.6 }}>
            <span style={{ color: 'var(--acP)' }}>*</span> = required field ·
            {' '}<span style={{ color: '#ffa600' }}>unknown</span> = column not declared by this adapter (will go into <code>extra</code> or be ignored)
          </div>
        </div>

        {/* Footer */}
        <div style={{
          padding: '14px 22px', borderTop: '1px solid var(--bd)',
          display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 10,
          flexShrink: 0,
        }}>
          <span style={{ fontSize: 10, color: 'var(--txD)', flex: 1 }}>
            {canConfirm
              ? 'All required fields are mapped — ready to ingest.'
              : `${unmappedRequired.length} required field${unmappedRequired.length !== 1 ? 's' : ''} still need mapping.`}
          </span>
          <button className="btn" onClick={onCancel} disabled={loading}>
            Cancel
          </button>
          <button
            onClick={handleConfirm}
            disabled={!canConfirm || loading}
            style={{
              padding: '6px 18px', borderRadius: 6, fontSize: 12, fontWeight: 500,
              background: canConfirm ? 'var(--ac)' : 'rgba(88,166,255,.15)',
              color: canConfirm ? '#000' : 'var(--txD)',
              border: 'none', cursor: canConfirm && !loading ? 'pointer' : 'not-allowed',
              opacity: loading ? 0.6 : 1,
            }}
          >
            {loading ? 'Ingesting…' : 'Confirm & Ingest'}
          </button>
        </div>
      </div>
    </div>
  );
}
