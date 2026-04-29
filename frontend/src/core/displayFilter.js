/**
 * SwiftEye Display Filter Engine — schema-driven.
 *
 * Parses and evaluates Wireshark-style display filter expressions against
 * graph nodes and edges (client-side, no backend call needed).
 *
 * Field-name knowledge is NOT hardcoded here — the active workspace's
 * `schema` declares filter paths, types, bare flags, and (via
 * `workspace.enrichEdge`) any synthetic edge fields needed to express
 * concepts like "flow endpoint IP" without core knowing about hosts.
 *
 * Supported syntax (unchanged from pre-schema version):
 *   ip == 10.0.0.1          ip != 10.0.0.1
 *   ip == 10.0.0.0/24       (CIDR for any ip-typed field)
 *   ip.src == 10.0.0.1
 *   hostname contains "google"
 *   protocol == "HTTP"       (or just: http / tcp / dns — protocol shorthand)
 *   port == 443
 *   bytes > 10000
 *   private                  !private
 *   tls.sni contains "example.com"
 *   (expr1 && expr2)         expr1 || expr2    !expr
 *
 * Returns:
 *   { nodes: Set<id>, edges: Set<id> }  — IDs to SHOW (hide everything else)
 *   null                                — empty filter, show everything
 *   { error: string }                   — parse/eval error
 */

import { evalSchemaPred, evalSchemaBare } from './schema';

// ── Tokeniser ─────────────────────────────────────────────────────────────────

const TT = {
  FIELD: 'FIELD', OP: 'OP', VALUE: 'VALUE',
  AND: 'AND', OR: 'OR', NOT: 'NOT',
  LPAREN: 'LPAREN', RPAREN: 'RPAREN',
  BARE: 'BARE',
  EOF: 'EOF',
};

function collectFilterPaths(schema) {
  const set = new Set();
  for (const kind of ['node_types', 'edge_types']) {
    for (const t of (schema[kind] || [])) {
      for (const f of (t.fields || [])) {
        if (f.filter_path) set.add(f.filter_path.toLowerCase());
      }
    }
  }
  return set;
}

function collectBareFlags(schema) {
  const set = new Set();
  for (const kind of ['node_types', 'edge_types']) {
    for (const t of (schema[kind] || [])) {
      for (const f of (t.fields || [])) {
        if (f.bare_flag) set.add(String(f.bare_flag).toLowerCase());
      }
    }
  }
  return set;
}

function tokenise(src, schema) {
  const FIELDS = collectFilterPaths(schema);
  const BARE_FLAGS = collectBareFlags(schema);

  const tokens = [];
  let i = 0;
  const s = src.trim();

  while (i < s.length) {
    if (/\s/.test(s[i])) { i++; continue; }

    if (s[i] === '(') { tokens.push({ type: TT.LPAREN }); i++; continue; }
    if (s[i] === ')') { tokens.push({ type: TT.RPAREN }); i++; continue; }

    if (s.slice(i, i+2) === '&&') { tokens.push({ type: TT.AND }); i += 2; continue; }
    if (s.slice(i, i+2) === '||') { tokens.push({ type: TT.OR });  i += 2; continue; }
    if (s[i] === '!' && s[i+1] !== '=') { tokens.push({ type: TT.NOT }); i++; continue; }

    if (s[i] === '"' || s[i] === "'") {
      const q = s[i++];
      let val = '';
      while (i < s.length && s[i] !== q) {
        if (s[i] === '\\') i++;
        val += s[i++];
      }
      i++;
      tokens.push({ type: TT.VALUE, value: val });
      continue;
    }

    if (s.slice(i,i+2) === '>=' || s.slice(i,i+2) === '<=' ||
        s.slice(i,i+2) === '!=' || s.slice(i,i+2) === '==') {
      tokens.push({ type: TT.OP, op: s.slice(i,i+2) }); i += 2; continue;
    }
    if (s[i] === '>' || s[i] === '<') {
      tokens.push({ type: TT.OP, op: s[i] }); i++; continue;
    }

    if (/[a-zA-Z0-9_.\/\-:@]/.test(s[i])) {
      let word = '';
      while (i < s.length && /[a-zA-Z0-9_.\/\-:@]/.test(s[i])) word += s[i++];

      const lo = word.toLowerCase();

      if (lo === 'and') { tokens.push({ type: TT.AND }); continue; }
      if (lo === 'or')  { tokens.push({ type: TT.OR  }); continue; }
      if (lo === 'not') { tokens.push({ type: TT.NOT }); continue; }

      if (lo === 'contains' || lo === 'matches') {
        tokens.push({ type: TT.OP, op: lo }); continue;
      }

      if (FIELDS.has(lo)) {
        tokens.push({ type: TT.FIELD, field: lo }); continue;
      }
      if (BARE_FLAGS.has(lo)) {
        tokens.push({ type: TT.BARE, keyword: lo }); continue;
      }

      // Unknown word → bare keyword (protocol-shorthand fallback in evaluator)
      tokens.push({ type: TT.BARE, keyword: word });
      continue;
    }

    i++;
  }

  tokens.push({ type: TT.EOF });
  return tokens;
}

// ── Recursive-descent parser (unchanged) ──────────────────────────────────────

function parse(tokens) {
  let pos = 0;

  function peek() { return tokens[pos]; }
  function consume() { return tokens[pos++]; }
  function expect(type) {
    const t = tokens[pos++];
    if (t.type !== type) throw new Error(`Expected ${type}, got ${t.type} at position ${pos}`);
    return t;
  }

  function parseExpr() { return parseOr(); }

  function parseOr() {
    let left = parseAnd();
    while (peek().type === TT.OR) {
      consume();
      const right = parseAnd();
      left = { type: 'or', left, right };
    }
    return left;
  }

  function parseAnd() {
    let left = parseUnary();
    while (peek().type === TT.AND) {
      consume();
      const right = parseUnary();
      left = { type: 'and', left, right };
    }
    return left;
  }

  function parseUnary() {
    if (peek().type === TT.NOT) {
      consume();
      const operand = parseUnary();
      return { type: 'not', operand };
    }
    return parseAtom();
  }

  function parseAtom() {
    const t = peek();

    if (t.type === TT.LPAREN) {
      consume();
      const inner = parseExpr();
      expect(TT.RPAREN);
      return inner;
    }

    if (t.type === TT.BARE) {
      consume();
      return { type: 'bare', keyword: t.keyword };
    }

    if (t.type === TT.FIELD) {
      consume();
      const opTok = consume();
      if (opTok.type !== TT.OP) throw new Error(`Expected operator after field "${t.field}", got ${opTok.type}`);
      const valTok = consume();
      const rawVal = valTok.type === TT.VALUE ? valTok.value
                   : valTok.type === TT.BARE  ? valTok.keyword
                   : String(valTok.value || valTok.keyword || '');
      return { type: 'pred', field: t.field, op: opTok.op, value: rawVal };
    }

    throw new Error(`Unexpected token: ${t.type} "${t.keyword || t.field || t.value || ''}"`);
  }

  const tree = parseExpr();
  if (peek().type !== TT.EOF) {
    throw new Error(`Unexpected token after expression: ${peek().type}`);
  }
  return tree;
}

// ── Evaluator ─────────────────────────────────────────────────────────────────

function evalAst(ast, evalPred, evalBare) {
  switch (ast.type) {
    case 'and': return evalAst(ast.left, evalPred, evalBare) && evalAst(ast.right, evalPred, evalBare);
    case 'or':  return evalAst(ast.left, evalPred, evalBare) || evalAst(ast.right, evalPred, evalBare);
    case 'not': return !evalAst(ast.operand, evalPred, evalBare);
    case 'pred': return evalPred(ast.field, ast.op, ast.value);
    case 'bare': return evalBare(ast.keyword);
    default: return false;
  }
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Apply a display filter expression to graph nodes and edges.
 *
 * @param {string} expr      filter expression string
 * @param {Array}  nodes     graph.nodes array
 * @param {Array}  edges     graph.edges array
 * @param {Object} workspace active workspace descriptor ({schema, enrichEdge?})
 * @returns {null | {error} | {nodes: Set, edges: Set, matchCount: number}}
 */
export function applyDisplayFilter(expr, nodes, edges, workspace) {
  if (!expr || !expr.trim()) return null;
  if (!workspace || !workspace.schema) {
    return { error: 'Workspace schema not loaded' };
  }
  const schema = workspace.schema;

  let ast;
  try {
    const tokens = tokenise(expr.trim(), schema);
    ast = parse(tokens);
  } catch (e) {
    return { error: e.message };
  }

  const nodeById = new Map(nodes.map(n => [n.id, n]));
  const enrichFn = typeof workspace.enrichEdge === 'function' ? workspace.enrichEdge : null;

  const enrichedEdges = edges.map(e => {
    const srcId = typeof e.source === 'object' ? e.source.id : e.source;
    const dstId = typeof e.target === 'object' ? e.target.id : e.target;
    const srcNode = nodeById.get(srcId);
    const dstNode = nodeById.get(dstId);
    const extra = enrichFn ? (enrichFn(e, srcNode, dstNode) || {}) : {};
    return { ...e, _srcId: srcId, _dstId: dstId, ...extra };
  });

  const matchedNodes = new Set();
  const matchedEdges = new Set();

  for (const node of nodes) {
    const match = evalAst(
      ast,
      (field, op, value) => evalSchemaPred(node, schema, 'node', field, op, value),
      (kw) => evalSchemaBare(node, schema, 'node', kw),
    );
    if (match) matchedNodes.add(node.id);
  }

  for (const edge of enrichedEdges) {
    const directMatch = evalAst(
      ast,
      (field, op, value) => evalSchemaPred(edge, schema, 'edge', field, op, value),
      (kw) => evalSchemaBare(edge, schema, 'edge', kw),
    );
    const endpointMatch = matchedNodes.has(edge._srcId) && matchedNodes.has(edge._dstId);
    if (directMatch || endpointMatch) matchedEdges.add(edge.id);
  }

  // Also include nodes touched by matched edges (so the graph stays connected)
  for (const edge of enrichedEdges) {
    if (matchedEdges.has(edge.id)) {
      matchedNodes.add(edge._srcId);
      matchedNodes.add(edge._dstId);
    }
  }

  return { nodes: matchedNodes, edges: matchedEdges, matchCount: matchedNodes.size };
}

/**
 * Validate a filter expression without applying it.
 * Returns null on success, error string on failure.
 */
export function validateFilter(expr, workspace) {
  if (!expr || !expr.trim()) return null;
  if (!workspace || !workspace.schema) return 'Workspace schema not loaded';
  try {
    const tokens = tokenise(expr.trim(), workspace.schema);
    parse(tokens);
    return null;
  } catch (e) {
    return e.message;
  }
}
