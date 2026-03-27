const axios = require('axios');

// Error Disclosure Scanner
// Triggers errors via malformed requests and checks for stack traces, versions, debug info
// FP prevention: Matches 30+ specific framework error fingerprints, not generic strings
// FN prevention: Triggers errors via multiple methods (bad content-type, invalid JSON, etc.)

// Very specific error fingerprints — each pattern should ONLY appear in actual error output,
// not in normal page content, documentation, or blog posts.
// Removed generic/ambiguous patterns that caused false positives.
const ERROR_FINGERPRINTS = {
  python: [
    { pattern: 'Traceback (most recent call last)', name: 'Python Traceback', severity: 'critical' },
    { pattern: 'File "/usr/', name: 'Python file path leak', severity: 'critical' },
    { pattern: 'File "/app/', name: 'Python app path leak', severity: 'high' },
    { pattern: 'django.core.exceptions', name: 'Django debug error', severity: 'critical' },
    { pattern: 'DJANGO_SETTINGS_MODULE', name: 'Django settings exposed', severity: 'critical' },
    { pattern: 'flask.debughelpers', name: 'Flask debug mode', severity: 'critical' },
    { pattern: 'Werkzeug Debugger', name: 'Werkzeug interactive debugger', severity: 'critical' },
    { pattern: 'The debugger caught an exception', name: 'Python debugger active', severity: 'critical' },
  ],
  php: [
    // Require the HTML <b> tags that PHP error handler specifically outputs (not in normal pages)
    { pattern: '<b>Fatal error</b>', name: 'PHP Fatal Error', severity: 'high' },
    { pattern: '<b>Parse error</b>', name: 'PHP Parse Error', severity: 'high' },
    { pattern: '<b>Warning</b>:', name: 'PHP Warning', severity: 'medium' },
    { pattern: 'on line <b>', name: 'PHP line number disclosure', severity: 'high' },
    { pattern: 'Symfony\\Component\\', name: 'Symfony framework error', severity: 'high' },
    { pattern: 'Whoops\\Handler\\', name: 'Whoops error handler', severity: 'high' },
    { pattern: 'vendor/laravel/framework', name: 'Laravel path leak', severity: 'high' },
  ],
  java: [
    { pattern: 'java.lang.NullPointerException', name: 'Java NullPointerException', severity: 'high' },
    { pattern: 'java.lang.ClassNotFoundException', name: 'Java ClassNotFoundException', severity: 'high' },
    { pattern: 'at org.apache.catalina.', name: 'Tomcat stack trace', severity: 'high' },
    { pattern: 'at org.springframework.web.', name: 'Spring Web stack trace', severity: 'high' },
    { pattern: 'javax.servlet.ServletException', name: 'Servlet exception', severity: 'high' },
  ],
  dotnet: [
    { pattern: 'System.NullReferenceException', name: '.NET NullReference', severity: 'high' },
    { pattern: 'System.Web.HttpException', name: '.NET HTTP Exception', severity: 'high' },
    { pattern: '<b>Stack Trace:</b>', name: 'ASP.NET stack trace', severity: 'high' },
    { pattern: 'System.Data.SqlClient.SqlException', name: '.NET SQL error leak', severity: 'critical' },
    { pattern: 'Microsoft.AspNetCore.Diagnostics', name: 'ASP.NET Core diagnostics page', severity: 'high' },
  ],
  node: [
    { pattern: 'at Module._compile', name: 'Node.js module error', severity: 'high' },
    { pattern: 'at Object.<anonymous> (/', name: 'Node.js stack trace with path', severity: 'high' },
    { pattern: 'SyntaxError: Unexpected token', name: 'Node.js JSON parse error', severity: 'medium' },
  ],
  database: [
    { pattern: 'SQLSTATE[', name: 'SQL state error', severity: 'critical' },
    { pattern: 'syntax error at or near', name: 'PostgreSQL syntax error', severity: 'critical' },
    { pattern: 'You have an error in your SQL syntax', name: 'MySQL syntax error', severity: 'critical' },
    { pattern: 'ORA-0', name: 'Oracle database error', severity: 'critical' },
    { pattern: 'ORA-1', name: 'Oracle database error (1xxx)', severity: 'critical' },
    { pattern: 'Microsoft OLE DB Provider for SQL', name: 'MSSQL OLE error', severity: 'critical' },
    { pattern: 'pg_query():', name: 'PostgreSQL query error', severity: 'critical' },
    { pattern: 'SQLite3::query', name: 'SQLite error', severity: 'critical' },
  ],
};

// Methods to trigger errors
async function triggerErrors(targetUrl) {
  const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
  const responses = [];

  // 1. Invalid JSON POST
  try {
    const r = await axios.post(targetUrl, '{invalid json!!!', {
      timeout: 6000, validateStatus: () => true,
      headers: { 'Content-Type': 'application/json', 'User-Agent': ua }
    });
    responses.push({ method: 'Invalid JSON', body: typeof r.data === 'string' ? r.data : JSON.stringify(r.data || ''), status: r.status, headers: r.headers });
  } catch { /* skip */ }

  // 2. Wrong content-type
  try {
    const r = await axios.post(targetUrl, 'test', {
      timeout: 6000, validateStatus: () => true,
      headers: { 'Content-Type': 'application/xml', 'User-Agent': ua }
    });
    responses.push({ method: 'Wrong Content-Type', body: typeof r.data === 'string' ? r.data : JSON.stringify(r.data || ''), status: r.status, headers: r.headers });
  } catch { /* skip */ }

  // 3. Non-existent path with special characters
  try {
    const r = await axios.get(`${targetUrl.replace(/\/$/, '')}/'%22%3E%3Ctest%3E/..%00`, {
      timeout: 6000, validateStatus: () => true,
      headers: { 'User-Agent': ua }
    });
    responses.push({ method: 'Special chars path', body: typeof r.data === 'string' ? r.data : JSON.stringify(r.data || ''), status: r.status, headers: r.headers });
  } catch { /* skip */ }

  // 4. Oversized header
  try {
    const r = await axios.get(targetUrl, {
      timeout: 6000, validateStatus: () => true,
      headers: { 'User-Agent': ua, 'X-Custom-Test': 'A'.repeat(8000) }
    });
    responses.push({ method: 'Oversized header', body: typeof r.data === 'string' ? r.data : JSON.stringify(r.data || ''), status: r.status, headers: r.headers });
  } catch { /* skip */ }

  // 5. Method not allowed
  try {
    const r = await axios({ method: 'PATCH', url: targetUrl, timeout: 6000, validateStatus: () => true,
      headers: { 'User-Agent': ua }, data: '' });
    responses.push({ method: 'PATCH method', body: typeof r.data === 'string' ? r.data : JSON.stringify(r.data || ''), status: r.status, headers: r.headers });
  } catch { /* skip */ }

  // 6. SQL-like query param
  try {
    const testUrl = new URL(targetUrl);
    testUrl.searchParams.set('id', "1' OR '1'='1");
    const r = await axios.get(testUrl.toString(), {
      timeout: 6000, validateStatus: () => true,
      headers: { 'User-Agent': ua }
    });
    responses.push({ method: 'SQL-like param', body: typeof r.data === 'string' ? r.data : JSON.stringify(r.data || ''), status: r.status, headers: r.headers });
  } catch { /* skip */ }

  // 7. Deep non-existent path
  try {
    const r = await axios.get(`${targetUrl.replace(/\/$/, '')}/synthrex_test_8f3a2b/${Date.now()}/nonexistent`, {
      timeout: 6000, validateStatus: () => true,
      headers: { 'User-Agent': ua }
    });
    responses.push({ method: 'Deep 404 path', body: typeof r.data === 'string' ? r.data : JSON.stringify(r.data || ''), status: r.status, headers: r.headers });
  } catch { /* skip */ }

  return responses;
}

async function scan(targetUrl) {
  const results = { findings: [], tests: [] };

  try {
    const responses = await triggerErrors(targetUrl);

    if (responses.length === 0) {
      results.tests.push({ id: 'err-unreachable', name: 'Could not trigger error responses', status: 'info', severity: 'info' });
      return { scanner: 'Error Disclosure', icon: '🐛', results, testCount: results.tests.length };
    }

    const foundFingerprints = new Set();

    // Scan all responses for all fingerprints
    for (const resp of responses) {
      for (const [category, fingerprints] of Object.entries(ERROR_FINGERPRINTS)) {
        for (const fp of fingerprints) {
          if (foundFingerprints.has(fp.name)) continue; // Already found
          if (resp.body.includes(fp.pattern)) {
            foundFingerprints.add(fp.name);
            results.findings.push({ fingerprint: fp.name, category, method: resp.method, status: resp.status });
            results.tests.push({
              id: `err-${fp.name.replace(/\s/g, '-').replace(/[^a-zA-Z0-9-]/g, '')}`,
              name: `${fp.name} (triggered by: ${resp.method})`,
              status: 'fail', severity: fp.severity
            });
          }
        }
      }
    }

    if (foundFingerprints.size === 0) {
      results.tests.push({ id: 'err-none', name: 'No error information disclosure detected', status: 'pass', severity: 'info' });
    }

    // Additional test: Check Server header for version info
    const serverHeader = responses[0]?.headers?.['server'] || '';
    if (serverHeader) {
      // Check if version number is revealed (e.g., "Apache/2.4.41" or "nginx/1.18.0")
      const versionRegex = /\d+\.\d+/;
      if (versionRegex.test(serverHeader)) {
        results.tests.push({
          id: 'err-server-version',
          name: `Server version disclosed: ${serverHeader}`,
          status: 'warn', severity: 'low'
        });
      } else {
        results.tests.push({
          id: 'err-server-header',
          name: `Server header: ${serverHeader} (no version)`,
          status: 'pass', severity: 'info'
        });
      }
    }

    // Additional test: X-Powered-By header
    const poweredBy = responses[0]?.headers?.['x-powered-by'] || '';
    if (poweredBy) {
      results.tests.push({
        id: 'err-powered-by',
        name: `X-Powered-By: ${poweredBy}`,
        status: 'warn', severity: 'low'
      });
    }

    // Additional test: Debug mode indicators in headers
    const debugHeaders = ['x-debug-token', 'x-debug-token-link', 'x-debug-mode', 'x-debug-info'];
    for (const dh of debugHeaders) {
      const val = responses[0]?.headers?.[dh];
      if (val) {
        results.tests.push({
          id: `err-debug-${dh}`,
          name: `Debug header found: ${dh}: ${val.toString().substring(0, 50)}`,
          status: 'fail', severity: 'high'
        });
      }
    }

    // Custom error page quality check (does 404 page leak info?)
    const fourOhFours = responses.filter(r => r.status === 404);
    for (const resp of fourOhFours) {
      if (resp.body.length > 5000) {
        results.tests.push({
          id: 'err-verbose-404',
          name: `Verbose 404 page (${resp.body.length} chars — may contain info leaks)`,
          status: 'warn', severity: 'low'
        });
        break;
      }
    }

  } catch (err) {
    results.error = `Error disclosure scan failed: ${err.message}`;
  }
  return { scanner: 'Error Disclosure', icon: '🐛', results, testCount: results.tests.length };
}

module.exports = { scan };
