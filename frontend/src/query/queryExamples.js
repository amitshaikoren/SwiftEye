/**
 * Canned example queries per syntax.
 * Shown in the Examples dropdown — filtered by the user's selected dialect.
 *
 * Each example has cypher, sql, and pyspark keys.
 * SQL note: CONTAINS is not standard SQL. Use ARRAY_CONTAINS(field, value)
 * for set membership checks — sqlglot recognises it.
 */

export const EXAMPLES = [
  {
    title: 'Nodes with multiple MACs',
    cypher: 'MATCH (n) WHERE count(n.macs) > 1 RETURN n',
    sql:    'SELECT * FROM nodes WHERE COUNT(macs) > 1',
    pyspark: 'nodes.filter(count(col("macs")) > 1)',
  },
  {
    title: 'High-traffic nodes (>10000 packets)',
    cypher: 'MATCH (n) WHERE n.packets > 10000 RETURN n',
    sql:    'SELECT * FROM nodes WHERE packets > 10000',
    pyspark: 'nodes.filter(col("packets") > 10000)',
  },
  {
    title: 'Nodes using DNS',
    cypher: 'MATCH (n) WHERE n.protocols CONTAINS "DNS" RETURN n',
    sql:    "SELECT * FROM nodes WHERE ARRAY_CONTAINS(protocols, 'DNS')",
    pyspark: 'nodes.filter(col("protocols").contains("DNS"))',
  },
  {
    title: 'Edges with ARP',
    cypher: 'MATCH (n)-[r]->(m) WHERE r.protocols CONTAINS "ARP" RETURN r',
    sql:    "SELECT * FROM edges WHERE ARRAY_CONTAINS(protocols, 'ARP')",
    pyspark: 'edges.filter(col("protocols").contains("ARP"))',
  },
  {
    title: 'Edges with TCP resets',
    cypher: 'MATCH (n)-[r]->(m) WHERE r.has_reset IS TRUE RETURN r',
    sql:    'SELECT * FROM edges WHERE has_reset IS TRUE',
    pyspark: 'edges.filter(col("has_reset") == True)',
  },
  {
    title: 'Private nodes with high degree',
    cypher: 'MATCH (n) WHERE n.is_private IS TRUE AND n.degree > 10 RETURN n',
    sql:    'SELECT * FROM nodes WHERE is_private IS TRUE AND degree > 10',
    pyspark: 'nodes.filter((col("is_private") == True) & (col("degree") > 10))',
  },
  {
    title: 'Edges containing HTTP',
    cypher: 'MATCH (n)-[r]->(m) WHERE r.protocols CONTAINS "HTTP" RETURN r',
    sql:    "SELECT * FROM edges WHERE ARRAY_CONTAINS(protocols, 'HTTP')",
    pyspark: 'edges.filter(col("protocols").contains("HTTP"))',
  },
  {
    title: 'Windows nodes with high traffic',
    cypher: 'MATCH (n) WHERE n.os_guess STARTS WITH "Win" AND n.bytes > 50000 RETURN n',
    sql:    "SELECT * FROM nodes WHERE os_guess LIKE 'Win%' AND bytes > 50000",
    pyspark: 'nodes.filter((col("os_guess").startswith("Win")) & (col("bytes") > 50000))',
  },
  {
    title: 'TLS sessions',
    pyspark: 'sessions.filter(col("protocol") == "TLS")',
    pysparkOnly: true,
  },
  {
    title: 'Large flows (>1 MB)',
    pyspark: 'sessions.filter(col("total_bytes") > 1000000)',
    pysparkOnly: true,
  },
  {
    title: 'Long-lived sessions (>5 min)',
    pyspark: 'sessions.filter(col("duration") > 300)',
    pysparkOnly: true,
  },
  {
    title: 'HTTPS sessions (port 443)',
    pyspark: 'sessions.filter(col("dst_port") == 443)',
    pysparkOnly: true,
  },
  {
    title: 'DNS sessions',
    pyspark: 'sessions.filter(col("protocol") == "DNS")',
    pysparkOnly: true,
  },
];

/** Get a random example in the given syntax. */
export function randomExample(syntax = 'cypher') {
  const ex = EXAMPLES[Math.floor(Math.random() * EXAMPLES.length)];
  return ex[syntax] || ex.cypher;
}
