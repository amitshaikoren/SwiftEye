/**
 * SwiftEye Display Filter Engine
 *
 * Parses and evaluates Wireshark-style display filter expressions against
 * the graph's nodes and edges (client-side, no backend call needed).
 *
 * Supported syntax:
 *   ip == 10.0.0.1          ip != 10.0.0.1
 *   ip == 10.0.0.0/24       (CIDR match against any IP on the node)
 *   ip.src == 10.0.0.1      ip.dst == 10.0.0.1
 *   mac == aa:bb:cc:dd:ee:ff
 *   hostname contains "google"
 *   protocol == "HTTP"       (or just: http  /  tcp  / dns)
 *   protocol != "ARP"
 *   port == 443              port contains 80
 *   bytes > 10000            packets >= 5
 *   private                  !private
 *   subnet
 *   tls.sni contains "example.com"
 *   http.host == "example.com"
 *   dns contains "google"
 *   (expr1 && expr2)         expr1 || expr2    !expr
 *
 * Bare protocol keywords (http, dns, tcp, udp, ssh, tls, …) are shorthand
 * for `protocol == "HTTP"` etc. — case-insensitive.
 *
 * Returns:
 *   { nodes: Set<id>, edges: Set<id> }  — IDs to SHOW (hide everything else)
 *   null                                — empty filter, show everything
 *   { error: string }                   — parse/eval error
 */

// ── CIDR helpers ──────────────────────────────────────────────────────────────

function ipToInt(ip) {
  const parts = ip.split('.').map(Number);
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

function ipMatchesValue(ip, value) {
  if (value.includes('/')) return cidrMatch(ip, value);
  return ip === value;
}

// ── Tokeniser ─────────────────────────────────────────────────────────────────

const TT = {
  FIELD: 'FIELD', OP: 'OP', VALUE: 'VALUE',
  AND: 'AND', OR: 'OR', NOT: 'NOT',
  LPAREN: 'LPAREN', RPAREN: 'RPAREN',
  BARE: 'BARE',  // bare keyword like "http" or "private"
  EOF: 'EOF',
};

function tokenise(src) {
  const tokens = [];
  let i = 0;
  const s = src.trim();

  while (i < s.length) {
    // skip whitespace
    if (/\s/.test(s[i])) { i++; continue; }

    // grouped parens
    if (s[i] === '(') { tokens.push({ type: TT.LPAREN }); i++; continue; }
    if (s[i] === ')') { tokens.push({ type: TT.RPAREN }); i++; continue; }

    // logical operators
    if (s.slice(i, i+2) === '&&') { tokens.push({ type: TT.AND }); i += 2; continue; }
    if (s.slice(i, i+2) === '||') { tokens.push({ type: TT.OR });  i += 2; continue; }
    if (s[i] === '!' && s[i+1] !== '=') { tokens.push({ type: TT.NOT }); i++; continue; }

    // quoted string value
    if (s[i] === '"' || s[i] === "'") {
      const q = s[i++];
      let val = '';
      while (i < s.length && s[i] !== q) {
        if (s[i] === '\\') i++;
        val += s[i++];
      }
      i++; // closing quote
      tokens.push({ type: TT.VALUE, value: val });
      continue;
    }

    // operators: >=, <=, !=, ==, >, <
    if (s.slice(i,i+2) === '>=' || s.slice(i,i+2) === '<=' ||
        s.slice(i,i+2) === '!=' || s.slice(i,i+2) === '==') {
      tokens.push({ type: TT.OP, op: s.slice(i,i+2) }); i += 2; continue;
    }
    if (s[i] === '>' || s[i] === '<') {
      tokens.push({ type: TT.OP, op: s[i] }); i++; continue;
    }

    // word: field path, keyword, bare value, or number
    if (/[a-zA-Z0-9_.\/\-:@]/.test(s[i])) {
      let word = '';
      while (i < s.length && /[a-zA-Z0-9_.\/\-:@]/.test(s[i])) word += s[i++];

      const lo = word.toLowerCase();

      // logical word operators
      if (lo === 'and') { tokens.push({ type: TT.AND }); continue; }
      if (lo === 'or')  { tokens.push({ type: TT.OR  }); continue; }
      if (lo === 'not') { tokens.push({ type: TT.NOT }); continue; }

      // word operators: contains, matches
      if (lo === 'contains' || lo === 'matches') {
        tokens.push({ type: TT.OP, op: lo }); continue;
      }

      // known field paths
      const FIELDS = new Set([
        'ip', 'ip.src', 'ip.dst', 'mac', 'hostname', 'protocol',
        'port', 'bytes', 'packets', 'tls.sni', 'http.host', 'dns', 'os', 'role',
      ]);
      // bare boolean flags
      const BARE_FLAGS = new Set(['private', 'subnet', 'gateway']);

      if (FIELDS.has(lo)) {
        tokens.push({ type: TT.FIELD, field: lo }); continue;
      }
      if (BARE_FLAGS.has(lo)) {
        tokens.push({ type: TT.BARE, keyword: lo }); continue;
      }

      // bare protocol shorthand: http, dns, tcp, udp, ssh, tls, arp, icmp, ftp, smtp …
      // treat as a bare keyword to be evaluated as protocol match
      tokens.push({ type: TT.BARE, keyword: word });
      continue;
    }

    // unknown character — skip
    i++;
  }

  tokens.push({ type: TT.EOF });
  return tokens;
}

// ── Recursive-descent parser ──────────────────────────────────────────────────
// Grammar:
//   expr   := or_expr
//   or_expr := and_expr (OR and_expr)*
//   and_expr := unary (AND unary)*
//   unary  := NOT unary | atom
//   atom   := LPAREN expr RPAREN | BARE | predicate
//   predicate := FIELD OP value

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

function applyOp(op, actual, expected) {
  const num = parseFloat(actual);
  const expNum = parseFloat(expected);
  const str = String(actual).toLowerCase();
  const exp = String(expected).toLowerCase();

  switch (op) {
    case '==':       return str === exp || actual === expected;
    case '!=':       return str !== exp && actual !== expected;
    case 'contains': return str.includes(exp);
    case 'matches':  try { return new RegExp(expected, 'i').test(String(actual)); } catch { return false; }
    case '>':        return !isNaN(num) && !isNaN(expNum) && num > expNum;
    case '<':        return !isNaN(num) && !isNaN(expNum) && num < expNum;
    case '>=':       return !isNaN(num) && !isNaN(expNum) && num >= expNum;
    case '<=':       return !isNaN(num) && !isNaN(expNum) && num <= expNum;
    default:         return false;
  }
}

// Evaluate a predicate node against a graph node dict
function evalNodePred(node, field, op, value) {
  const val = value.toLowerCase();
  switch (field) {
    case 'ip':
      return (node.ips || []).some(ip =>
        op === 'contains' ? ip.includes(val) :
        op === 'matches'  ? new RegExp(value,'i').test(ip) :
        op === '==' || op === '!='
          ? (ipMatchesValue(ip, value) ? op === '==' : op === '!=')
          : applyOp(op, ip, value)
      );
    case 'mac':
      return (node.macs || []).some(m => applyOp(op, m.toLowerCase(), val));
    case 'os':
      return node.os_guess ? applyOp(op, node.os_guess.toLowerCase(), val) : false;
    case 'role': {
      const nr = node.plugin_data?.network_role?.role || '';
      return applyOp(op, nr.toLowerCase(), val);
    }
    case 'hostname':
      return (node.hostnames || []).some(h => applyOp(op, h.toLowerCase(), val));
    case 'protocol':
      return (node.protocols || []).some(p => applyOp(op, p.toLowerCase(), val));
    case 'bytes':
      return applyOp(op, node.total_bytes || 0, value);
    case 'packets':
      return applyOp(op, node.packet_count || 0, value);
    // These fields live on edges, not nodes — always false on a node
    case 'ip.src': case 'ip.dst': case 'port':
    case 'tls.sni': case 'http.host': case 'dns':
      return false;
    default:
      return false;
  }
}

// Evaluate a predicate node against a graph edge dict
function evalEdgePred(edge, field, op, value) {
  const val = value.toLowerCase();
  switch (field) {
    case 'protocol':
      return applyOp(op, (edge.protocol || '').toLowerCase(), val);
    case 'ip':
      // Match either endpoint
      return [edge._srcIp, edge._dstIp].filter(Boolean)
        .some(ip => (op === '==' || op === '!=')
          ? (ipMatchesValue(ip, value) ? op === '==' : op === '!=')
          : applyOp(op, ip, value));
    case 'ip.src':
      return edge._srcIp ? (
        (op === '==' || op === '!=')
          ? (ipMatchesValue(edge._srcIp, value) ? op === '==' : op === '!=')
          : applyOp(op, edge._srcIp, value)
      ) : false;
    case 'ip.dst':
      return edge._dstIp ? (
        (op === '==' || op === '!=')
          ? (ipMatchesValue(edge._dstIp, value) ? op === '==' : op === '!=')
          : applyOp(op, edge._dstIp, value)
      ) : false;
    case 'port':
      return (edge.ports || []).some(p => applyOp(op, p, value));
    case 'bytes':
      return applyOp(op, edge.total_bytes || 0, value);
    case 'packets':
      return applyOp(op, edge.packet_count || 0, value);
    case 'tls.sni':
      return (edge.tls_snis || []).some(s => applyOp(op, s.toLowerCase(), val));
    case 'http.host':
      return (edge.http_hosts || []).some(h => applyOp(op, h.toLowerCase(), val));
    case 'dns':
      return (edge.dns_queries || []).some(q => applyOp(op, q.toLowerCase(), val));
    // Node-only fields — false on edges
    case 'mac': case 'hostname':
      return false;
    default:
      return false;
  }
}

// Evaluate a BARE keyword against a node
function evalNodeBare(node, keyword) {
  const lo = keyword.toLowerCase();
  if (lo === 'private') return !!node.is_private;
  if (lo === 'subnet')  return !!node.is_subnet;
  if (lo === 'gateway') return node.plugin_data?.network_role?.role === 'gateway';
  // Treat as protocol shorthand
  return (node.protocols || []).some(p => p.toLowerCase() === lo);
}

// Evaluate a BARE keyword against an edge
function evalEdgeBare(edge, keyword) {
  const lo = keyword.toLowerCase();
  if (lo === 'private' || lo === 'subnet') return false;
  return (edge.protocol || '').toLowerCase() === lo;
}

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
 * @param {string} expr  — filter expression string
 * @param {Array}  nodes — graph.nodes array
 * @param {Array}  edges — graph.edges array
 * @returns {null | {error} | {nodes: Set, edges: Set, matchCount: number}}
 */
export function applyDisplayFilter(expr, nodes, edges) {
  if (!expr || !expr.trim()) return null;

  let ast;
  try {
    const tokens = tokenise(expr.trim());
    ast = parse(tokens);
  } catch (e) {
    return { error: e.message };
  }

  // Pre-compute src/dst IP for each edge (look up from nodes)
  const nodeById = new Map(nodes.map(n => [n.id, n]));
  const enrichedEdges = edges.map(e => {
    const srcId = typeof e.source === 'object' ? e.source.id : e.source;
    const dstId = typeof e.target === 'object' ? e.target.id : e.target;
    const srcNode = nodeById.get(srcId);
    const dstNode = nodeById.get(dstId);
    return {
      ...e,
      _srcId: srcId,
      _dstId: dstId,
      _srcIp: srcNode?.ips?.[0],
      _dstIp: dstNode?.ips?.[0],
    };
  });

  const matchedNodes = new Set();
  const matchedEdges = new Set();

  // Evaluate each node
  for (const node of nodes) {
    const match = evalAst(
      ast,
      (field, op, value) => evalNodePred(node, field, op, value),
      (kw) => evalNodeBare(node, kw),
    );
    if (match) matchedNodes.add(node.id);
  }

  // Evaluate each edge — also include edges where both endpoints matched
  for (const edge of enrichedEdges) {
    const directMatch = evalAst(
      ast,
      (field, op, value) => evalEdgePred(edge, field, op, value),
      (kw) => evalEdgeBare(edge, kw),
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
export function validateFilter(expr) {
  if (!expr || !expr.trim()) return null;
  try {
    const tokens = tokenise(expr.trim());
    parse(tokens);
    return null;
  } catch (e) {
    return e.message;
  }
}
