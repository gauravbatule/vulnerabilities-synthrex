const axios = require('axios');

const HTTP_METHODS = ['GET','POST','PUT','DELETE','PATCH','OPTIONS','HEAD','TRACE','CONNECT','PROPFIND','PROPPATCH','MKCOL','COPY','MOVE','LOCK','UNLOCK','SEARCH'];
const DANGEROUS_METHODS = ['TRACE','CONNECT','DELETE','PUT','PROPFIND','PROPPATCH','MKCOL','COPY','MOVE','LOCK','UNLOCK'];

async function scan(targetUrl) {
  const results = { allowed: [], blocked: [], tests: [] };
  try {
    for (const method of HTTP_METHODS) {
      try {
        const response = await axios({ method: method === 'CONNECT' ? 'OPTIONS' : method, url: targetUrl, timeout: 5000, validateStatus: () => true, headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' } });
        const isDangerous = DANGEROUS_METHODS.includes(method);
        const isAllowed = response.status < 400 && response.status !== 405;
        if (isAllowed) {
          results.allowed.push({ method, status: response.status });
          results.tests.push({ id: `http-${method}`, name: `${method} method allowed (${response.status})`, status: isDangerous ? 'fail' : 'info', severity: isDangerous ? 'high' : 'info' });
        } else {
          results.blocked.push({ method, status: response.status });
          results.tests.push({ id: `http-${method}`, name: `${method} method blocked (${response.status})`, status: 'pass', severity: 'info' });
        }
      } catch {
        results.tests.push({ id: `http-${method}`, name: `${method} method blocked/error`, status: 'pass', severity: 'info' });
      }
    }

    // OPTIONS response analysis
    try {
      const optResp = await axios({ method: 'OPTIONS', url: targetUrl, timeout: 5000, validateStatus: () => true });
      const allow = optResp.headers['allow'];
      if (allow) {
        results.tests.push({ id: 'http-allow-header', name: `Allow header: ${allow}`, status: 'info', severity: 'info' });
        for (const dm of DANGEROUS_METHODS) {
          if (allow.toUpperCase().includes(dm)) {
            results.tests.push({ id: `http-allow-${dm}`, name: `Dangerous method ${dm} in Allow header`, status: 'fail', severity: 'high' });
          }
        }
      }
    } catch { /* skip */ }

    // TRACE method XST test
    try {
      const traceResp = await axios({ method: 'TRACE', url: targetUrl, timeout: 5000, validateStatus: () => true });
      if (traceResp.status === 200) {
        results.tests.push({ id: 'http-xst', name: 'Cross-Site Tracing (XST) possible', status: 'fail', severity: 'high' });
      }
    } catch { /* skip */ }

  } catch (err) {
    results.error = `HTTP methods scan failed: ${err.message}`;
  }
  return { scanner: 'HTTP Methods', icon: '📡', results, testCount: results.tests.length };
}

module.exports = { scan };
