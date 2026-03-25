const axios = require('axios');

const TEST_ORIGINS = [
  'https://evil.com',
  'https://attacker.example.com',
  'null',
  'https://sub.evil.com',
  'http://localhost',
  'http://127.0.0.1',
  'https://evil.com%60.target.com',
  'https://target.com.evil.com',
];

async function scan(targetUrl) {
  const results = { findings: [], tests: [] };
  try {
    const url = new URL(targetUrl);

    // Test each origin
    for (const origin of TEST_ORIGINS) {
      try {
        const response = await axios.get(targetUrl, {
          timeout: 10000, validateStatus: () => true,
          headers: { 'Origin': origin, 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' }
        });
        const acao = response.headers['access-control-allow-origin'];
        const acac = response.headers['access-control-allow-credentials'];

        if (acao === '*') {
          results.tests.push({ id: `cors-wildcard-${origin}`, name: `CORS wildcard for origin: ${origin}`, status: 'warn', severity: 'medium' });
          results.findings.push({ issue: 'CORS allows wildcard origin (*)', origin, severity: 'medium' });
        } else if (acao === origin) {
          results.tests.push({ id: `cors-reflect-${origin}`, name: `CORS reflects origin: ${origin}`, status: 'fail', severity: 'critical' });
          results.findings.push({ issue: 'CORS reflects arbitrary origin', origin, reflected: acao, severity: 'critical' });
          if (acac === 'true') {
            results.tests.push({ id: `cors-creds-${origin}`, name: `CORS + credentials for: ${origin}`, status: 'fail', severity: 'critical' });
            results.findings.push({ issue: 'CORS reflects origin WITH credentials', origin, severity: 'critical' });
          }
        } else if (acao === 'null') {
          results.tests.push({ id: `cors-null-${origin}`, name: `CORS allows null origin`, status: 'fail', severity: 'high' });
        } else {
          results.tests.push({ id: `cors-blocked-${origin}`, name: `CORS blocks origin: ${origin}`, status: 'pass', severity: 'info' });
        }
      } catch (e) { /* timeout/error is fine */ }
    }

    // Test HTTP methods
    const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT'];
    for (const method of methods) {
      try {
        const response = await axios({ method: method === 'CONNECT' ? 'GET' : method, url: targetUrl, timeout: 5000, validateStatus: () => true, headers: { 'Origin': 'https://evil.com' } });
        const acam = response.headers['access-control-allow-methods'];
        if (acam) {
          results.tests.push({ id: `cors-method-${method}`, name: `CORS allows ${method} method`, status: acam.includes(method) ? 'warn' : 'pass', severity: acam.includes(method) ? 'medium' : 'info' });
        }
      } catch (e) { /* skip */ }
    }

    // Preflight check
    try {
      const preflight = await axios({ method: 'OPTIONS', url: targetUrl, timeout: 5000, validateStatus: () => true,
        headers: { 'Origin': 'https://evil.com', 'Access-Control-Request-Method': 'PUT', 'Access-Control-Request-Headers': 'X-Custom-Header,Authorization' }
      });
      const allowHeaders = preflight.headers['access-control-allow-headers'];
      const allowMethods = preflight.headers['access-control-allow-methods'];
      const maxAge = preflight.headers['access-control-max-age'];

      results.tests.push({ id: 'cors-preflight-status', name: `Preflight response: ${preflight.status}`, status: 'info', severity: 'info' });
      if (allowHeaders) {
        if (allowHeaders === '*') results.tests.push({ id: 'cors-wildcard-headers', name: 'CORS allows all headers (*)', status: 'fail', severity: 'high' });
        if (allowHeaders.toLowerCase().includes('authorization')) results.tests.push({ id: 'cors-auth-header', name: 'CORS allows Authorization header', status: 'warn', severity: 'medium' });
        if (allowHeaders.toLowerCase().includes('cookie')) results.tests.push({ id: 'cors-cookie-header', name: 'CORS allows Cookie header', status: 'fail', severity: 'high' });
      }
      if (allowMethods === '*') results.tests.push({ id: 'cors-wildcard-methods', name: 'CORS allows all methods (*)', status: 'fail', severity: 'high' });
      if (maxAge && parseInt(maxAge) > 86400) results.tests.push({ id: 'cors-maxage', name: 'CORS max-age > 24h', status: 'warn', severity: 'low' });
    } catch (e) { /* skip */ }

  } catch (err) {
    results.error = `CORS scan failed: ${err.message}`;
  }
  return { scanner: 'CORS Misconfiguration', icon: '🌐', results, testCount: results.tests.length };
}

module.exports = { scan };
