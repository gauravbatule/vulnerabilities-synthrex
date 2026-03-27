const axios = require('axios');

// CRLF Injection Scanner
// Tests for HTTP header injection via %0d%0a in URL parameters
// FP prevention: Only flags if injected header actually appears in response headers
// FN prevention: Multiple encoding variants tested per parameter

const CRLF_PAYLOADS = [
  { name: 'Basic CRLF', value: '%0d%0aInjected-Header:SynthrexCRLF' },
  { name: 'Double-encoded CRLF', value: '%250d%250aInjected-Header:SynthrexCRLF' },
  { name: 'Unicode CRLF', value: '%E5%98%8A%E5%98%8DInjected-Header:SynthrexCRLF' },
  { name: 'Mixed CRLF (\\r only)', value: '%0dInjected-Header:SynthrexCRLF' },
  { name: 'Mixed CRLF (\\n only)', value: '%0aInjected-Header:SynthrexCRLF' },
  { name: 'URL-path CRLF', value: '%0d%0aSet-Cookie:synthrex=crlftest' },
];

const PARAMS = ['url', 'redirect', 'next', 'page', 'lang', 'q', 'search'];
const SCANNER_TIMEOUT = 45000;

async function scan(targetUrl) {
  const results = { findings: [], tests: [] };
  const deadline = Date.now() + SCANNER_TIMEOUT;

  const safeGet = (url) =>
    axios.get(url, {
      timeout: 6000, maxRedirects: 0, validateStatus: () => true,
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' }
    }).catch(() => null);

  try {
    // Test 1: CRLF via query parameters
    let crlfFound = false;
    for (const payload of CRLF_PAYLOADS) {
      if (Date.now() > deadline) break;

      for (const param of PARAMS) {
        if (Date.now() > deadline) break;
        try {
          const testUrl = new URL(targetUrl);
          testUrl.searchParams.set(param, `test${payload.value}`);
          const r = await safeGet(testUrl.toString());
          if (!r) continue;

          // Check if injected header exists in response
          const hasInjectedHeader = r.headers['injected-header'] === 'SynthrexCRLF';
          const hasInjectedCookie = (r.headers['set-cookie'] || '').toString().includes('synthrex=crlftest');

          if (hasInjectedHeader || hasInjectedCookie) {
            crlfFound = true;
            results.findings.push({ param, payload: payload.name, evidence: hasInjectedHeader ? 'header' : 'cookie' });
            results.tests.push({
              id: `crlf-${param}-${payload.name.replace(/\s/g, '-')}`,
              name: `CRLF Injection via ?${param} (${payload.name})`,
              status: 'fail', severity: 'high'
            });
          }
        } catch { /* skip */ }
      }

      if (!crlfFound) {
        results.tests.push({
          id: `crlf-safe-${payload.name.replace(/\s/g, '-')}`,
          name: `CRLF safe: ${payload.name}`,
          status: 'pass', severity: 'info'
        });
      }
    }

    // Test 2: CRLF in path
    try {
      const pathUrl = `${targetUrl.replace(/\/$/, '')}/%0d%0aInjected-Header:SynthrexCRLF`;
      const r = await safeGet(pathUrl);
      if (r && r.headers['injected-header'] === 'SynthrexCRLF') {
        results.tests.push({ id: 'crlf-path', name: 'CRLF Injection in URL path', status: 'fail', severity: 'high' });
      } else {
        results.tests.push({ id: 'crlf-path', name: 'CRLF in URL path blocked', status: 'pass', severity: 'info' });
      }
    } catch {
      results.tests.push({ id: 'crlf-path', name: 'CRLF in URL path blocked', status: 'pass', severity: 'info' });
    }

    // Test 3: Check if server properly sanitizes Location header on redirects
    try {
      const u = new URL(targetUrl);
      const redirectPayload = `${targetUrl.replace(/\/$/, '')}/%0d%0aLocation:%20https://evil.com`;
      const r = await safeGet(redirectPayload);
      if (r && r.headers['location'] && r.headers['location'].includes('evil.com')) {
        results.tests.push({ id: 'crlf-redirect', name: 'CRLF Header Injection in redirect', status: 'fail', severity: 'critical' });
      } else {
        results.tests.push({ id: 'crlf-redirect', name: 'Redirect header injection blocked', status: 'pass', severity: 'info' });
      }
    } catch {
      results.tests.push({ id: 'crlf-redirect', name: 'Redirect header injection blocked', status: 'pass', severity: 'info' });
    }

    // Test 4: HTTP Response Splitting
    try {
      const splitPayload = `${targetUrl.replace(/\/$/, '')}/?q=%0d%0a%0d%0a<html>SynthrexSplit</html>`;
      const r = await safeGet(splitPayload);
      if (r && typeof r.data === 'string' && r.data.includes('SynthrexSplit') && !r.data.includes('q=')) {
        // Only flag if our payload appeared as rendered HTML, not echoed in a form
        results.tests.push({ id: 'crlf-splitting', name: 'HTTP Response Splitting possible', status: 'fail', severity: 'critical' });
      } else {
        results.tests.push({ id: 'crlf-splitting', name: 'HTTP Response Splitting blocked', status: 'pass', severity: 'info' });
      }
    } catch {
      results.tests.push({ id: 'crlf-splitting', name: 'HTTP Response Splitting blocked', status: 'pass', severity: 'info' });
    }

  } catch (err) {
    results.error = `CRLF scan failed: ${err.message}`;
  }
  return { scanner: 'CRLF Injection', icon: '💀', results, testCount: results.tests.length };
}

module.exports = { scan };
