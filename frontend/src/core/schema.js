/**
 * Generic schema-driven predicate evaluator.
 *
 * `applyDisplayFilter` walks a WorkspaceSchema (node_types, edge_types)
 * and dispatches predicates on `field.type` — not `field.name`. That keeps
 * `core/` agnostic to which workspace is mounted: a forensic `process_name`
 * of type `string` reuses the same matching code as a network `hostname`.
 *
 * Wire-name knowledge (e.g. that network's flow `port` filter unions
 * `src_ports` and `dst_ports`) is declared schema-side via `field.sources`
 * and resolved here generically.
 */

// ── IP helpers ────────────────────────────────────────────────────────────────

function ipToInt(ip) {
  const parts = String(ip).split('.').map(Number);
  if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function cidrMatch(ip, cidr) {
  const [net, bits] = cidr.split('/');
  const prefixLen = parseInt(bits, 10);
  if (isNaN(prefixLen) || prefixLen < 0 || prefixLen > 32) return false;
  const ipInt = ipToInt(ip);
  const netInt = ipToInt(net);
  if (ipInt === null || netInt === null) return false;
  const mask = prefixLen === 0 ? 0 : (0xFFFFFFFF << (32 - prefixLen)) >>> 0;
  return (ipInt & mask) === (netInt & mask);
}

// ── Core value-lookup ─────────────────────────────────────────────────────────

function getNested(obj, path) {
  if (obj == null) return undefined;
  return path.split('.').reduce((o, seg) => (o == null ? undefined : o[seg]), obj);
}

/**
 * Return the flat list of values a field reads from `obj`, unioning across
 * `field.sources` (or `[field.name]` if unset) and flattening array values.
 */
export function getFieldValues(obj, field) {
  const keys = (field.sources && field.sources.length > 0) ? field.sources : [field.name];
  const out = [];
  for (const k of keys) {
    const v = getNested(obj, k);
    if (v === undefined || v === null) continue;
    if (Array.isArray(v)) {
      for (const x of v) if (x !== undefined && x !== null) out.push(x);
    } else {
      out.push(v);
    }
  }
  return out;
}

// ── Per-type predicate ────────────────────────────────────────────────────────

function numericCompare(op, actual, expected) {
  const a = typeof actual === 'number' ? actual : parseFloat(actual);
  const e = typeof expected === 'number' ? expected : parseFloat(expected);
  if (isNaN(a) || isNaN(e)) return false;
  switch (op) {
    case '==': return a === e;
    case '!=': return a !== e;
    case '>':  return a >  e;
    case '<':  return a <  e;
    case '>=': return a >= e;
    case '<=': return a <= e;
    default:   return false;
  }
}

function stringCompare(op, actual, expected) {
  const a = String(actual ?? '').toLowerCase();
  const e = String(expected ?? '').toLowerCase();
  switch (op) {
    case '==':       return a === e;
    case '!=':       return a !== e;
    case 'contains': return a.includes(e);
    case 'matches':  try { return new RegExp(expected, 'i').test(String(actual ?? '')); } catch { return false; }
    case '>': case '<': case '>=': case '<=':
      return numericCompare(op, actual, expected);
    default: return false;
  }
}

/**
 * Apply an operator to one actual value, dispatched on field.type.
 * Returns bool. `value` is always a string (as produced by the parser).
 */
export function applySchemaPredicate(actualValue, fieldType, op, expected) {
  switch (fieldType) {
    case 'ip': {
      if ((op === '==' || op === '!=') && String(expected).includes('/')) {
        const m = cidrMatch(actualValue, expected);
        return op === '==' ? m : !m;
      }
      return stringCompare(op, actualValue, expected);
    }
    case 'port':
    case 'int':
    case 'timestamp':
      return numericCompare(op, actualValue, expected);
    case 'bool': {
      if (op === '==' || op === '!=') {
        const target = String(expected).toLowerCase() === 'true' || expected === true;
        const actual = !!actualValue;
        return op === '==' ? actual === target : actual !== target;
      }
      return !!actualValue;
    }
    case 'mac':
    case 'protocol':
    case 'enum':
    case 'string':
    case 'string-array':
    default:
      return stringCompare(op, actualValue, expected);
  }
}

// ── Field-list dispatch ───────────────────────────────────────────────────────

function allFields(schema, kind) {
  const defs = kind === 'node' ? (schema.node_types || []) : (schema.edge_types || []);
  const out = [];
  for (const t of defs) for (const f of (t.fields || [])) out.push(f);
  return out;
}

/**
 * Evaluate FIELD OP VALUE against `obj`. Walks every schema field whose
 * `filter_path` matches; short-circuits on first true. Returns false if
 * no matching field or no source produced a value.
 */
export function evalSchemaPred(obj, schema, kind, filterPath, op, value) {
  const fields = allFields(schema, kind).filter(f => f.filter_path === filterPath);
  if (fields.length === 0) return false;
  for (const field of fields) {
    const values = getFieldValues(obj, field);
    if (values.length === 0) continue;
    if (values.some(v => applySchemaPredicate(v, field.type, op, value))) return true;
  }
  return false;
}

/**
 * Evaluate a bare keyword against `obj`.
 *   1) If any field declares `bare_flag === keyword`, that field's value
 *      (bool: truthy / other: equals-keyword) decides.
 *   2) Otherwise, treat the keyword as a protocol shorthand: match
 *      case-insensitively against any field of type=protocol.
 */
export function evalSchemaBare(obj, schema, kind, keyword) {
  const kw = String(keyword).toLowerCase();
  const fields = allFields(schema, kind);

  for (const field of fields) {
    if (!field.bare_flag || String(field.bare_flag).toLowerCase() !== kw) continue;
    const values = getFieldValues(obj, field);
    if (field.type === 'bool') {
      if (values.some(v => !!v)) return true;
    } else {
      if (values.some(v => String(v).toLowerCase() === kw)) return true;
    }
  }

  for (const field of fields) {
    if (field.type !== 'protocol') continue;
    const values = getFieldValues(obj, field);
    if (values.some(v => String(v).toLowerCase() === kw)) return true;
  }

  return false;
}

// ── Introspection helpers (FilterBar autocomplete + help) ────────────────────

/**
 * Unique filter_paths across a schema (for autocomplete suggestions).
 * Also includes declared `bare_flag` values.
 */
export function schemaFilterTokens(schema) {
  const set = new Set();
  for (const kind of ['node', 'edge']) {
    for (const f of allFields(schema, kind)) {
      if (f.filter_path) set.add(f.filter_path);
      if (f.bare_flag) set.add(f.bare_flag);
    }
  }
  return [...set];
}

/**
 * Return `[{filter_path, description, bare_flag}]` rows for the help
 * table, de-duped by filter_path. Synthetic `_-prefixed` fields keep
 * their descriptions but their wire `name` is never surfaced.
 */
export function schemaHelpRows(schema) {
  const byPath = new Map();
  for (const kind of ['node', 'edge']) {
    for (const f of allFields(schema, kind)) {
      if (!f.filter_path) continue;
      const prev = byPath.get(f.filter_path);
      if (!prev || (prev.description.length < (f.description || '').length)) {
        byPath.set(f.filter_path, { filter_path: f.filter_path, description: f.description || '', bare_flag: f.bare_flag || null });
      }
    }
  }
  for (const kind of ['node', 'edge']) {
    for (const f of allFields(schema, kind)) {
      if (f.bare_flag && !byPath.has(f.bare_flag)) {
        byPath.set(f.bare_flag, {
          filter_path: f.bare_flag,
          description: `Bare flag (matches ${f.filter_path}${f.type === 'bool' ? ' when true' : ` = "${f.bare_flag}"`}).`,
          bare_flag: f.bare_flag,
        });
      }
    }
  }
  return [...byPath.values()];
}
