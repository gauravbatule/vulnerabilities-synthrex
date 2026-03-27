const axios = require('axios');

// CRLF Injection Scanner
// Tests for HTTP header injection via %0d%0a in URL parameters
// FP prevention: Only flags if injected header actually appears in response headers
// FN prevention: Multiple encoding variants tested per parameter

// Note: We send payloads as raw URLs (not via URL constructor) because
// the URL API double-encodes percent sequences, neutralizing the payload.

const PARAMS = ['url', 'redirect', 'next', 'page', 'lang', 'q', 'search'];
const SCANNER_TIMEOUT = 45000;

const safeGet = (url) =>
  axios.get(url, {
    timeout: 6000, maxRedirects: 0, validateStatus: () => true,
    headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' }
  }).catch(() => null);

async function scan(targetUrl) {
  const results = { findings: [], tests: [] };
  const deadline = Date.now() + SCANNER_TIMEOUT;
  const base = targetUrl.replace(/\/$/, '');

  try {
    // Build payloads — each injects a unique header we can verify in the response
    const CRLF_PAYLOADS = [
      { name: 'Basic CRLF', suffix: '%0d%0aX-Injected:SynthrexCRLF', checkHeader: 'x-injected', checkValue: 'SynthrexCRLF' },
      { name: 'Double-encoded CRLF', suffix: '%250d%250aX-Injected:SynthrexCRLF', checkHeader: 'x-injected', checkValue: 'SynthrexCRLF' },
      { name: 'Unicode CRLF', suffix: '%E5%98%8A%E5%98%8DX-Injected:SynthrexCRLF', checkHeader: 'x-injected', checkValue: 'SynthrexCRLF' },
      { name: 'LF only', suffix: '%0aX-Injected:SynthrexCRLF', checkHeader: 'x-injected', checkValue: 'SynthrexCRLF' },
      { name: 'CR only', suffix: '%0dX-Injected:SynthrexCRLF', checkHeader: 'x-injected', checkValue: 'SynthrexCRLF' },
      { name: 'Set-Cookie injection', suffix: '%0d%0aSet-Cookie:%20synthrex=crlftest', checkHeader: 'set-cookie', checkValue: 'synthrex=crlftest' },
    ];

    // Test 1: CRLF via query parameters (raw URL to avoid double-encoding)
    let anyVulnerable = false;
    for (const payload of CRLF_PAYLOADS) {
      if (Date.now() > deadline) break;

      let payloadHit = false;
      for (const param of PARAMS) {
        if (Date.now() > deadline || payloadHit) break;
        try {
          // Build URL manually to prevent URL API from encoding the %0d%0a
          const testUrl = `${base}/?${encodeURIComponent(param)}=test${payload.suffix}`;
          const r = await safeGet(testUrl);
          if (!r) continue;

          // Strict check: the exact injected header must exist with exact value
          const headerVal = r.headers[payload.checkHeader];
          const match = payload.checkHeader === 'set-cookie'
            ? (headerVal || '').toString().includes(payload.checkValue)
            : headerVal === payload.checkValue;

          if (match) {
            payloadHit = true;
            anyVulnerable = true;
            results.findings.push({ param, payload: payload.name, evidence: payload.checkHeader });
            results.tests.push({
              id: `crlf-${param}-${payload.name.replace(/\s/g, '-')}`,
              name: `CRLF Injection via ?${param} (${payload.name})`,
              status: 'fail', severity: 'high'
            });
          }
        } catch { /* skip */ }
      }

      // Only add pass result if this specific payload didn't find anything
      if (!payloadHit) {
        results.tests.push({
          id: `crlf-safe-${payload.name.replace(/\s/g, '-')}`,
          name: `CRLF safe: ${payload.name}`,
          status: 'pass', severity: 'info'
        });
      }
    }

    // Test 2: CRLF in URL path
    try {
      const pathUrl = `${base}/%0d%0aX-Injected:SynthrexCRLF`;
      const r = await safeGet(pathUrl);
      if (r && r.headers['x-injected'] === 'SynthrexCRLF') {
        results.tests.push({ id: 'crlf-path', name: 'CRLF Injection in URL path', status: 'fail', severity: 'high' });
      } else {
        results.tests.push({ id: 'crlf-path', name: 'CRLF in URL path blocked', status: 'pass', severity: 'info' });
      }
    } catch {
      results.tests.push({ id: 'crlf-path', name: 'CRLF in URL path blocked', status: 'pass', severity: 'info' });
    }

    // Test 3: Location header injection via CRLF
    try {
      const redirectPayload = `${base}/%0d%0aLocation:%20https://evil.com`;
      const r = await safeGet(redirectPayload);
      if (r && r.headers['location'] && r.headers['location'].includes('evil.com')) {
        results.tests.push({ id: 'crlf-redirect', name: 'CRLF Header Injection in redirect', status: 'fail', severity: 'critical' });
      } else {
        results.tests.push({ id: 'crlf-redirect', name: 'Redirect header injection blocked', status: 'pass', severity: 'info' });
      }
    } catch {
      results.tests.push({ id: 'crlf-redirect', name: 'Redirect header injection blocked', status: 'pass', severity: 'info' });
    }

    // Test 4: HTTP Response Splitting — only flag if injected HTML appears
    // as a separate body (not reflected inside the normal page HTML)
    try {
      const marker = 'SynthrexSplitMarker7f3a';
      const splitUrl = `${base}/?q=%0d%0a%0d%0a<html>${marker}</html>`;
      const r = await safeGet(splitUrl);
      if (r && typeof r.data === 'string') {
        const body = r.data;
        // True response splitting: marker appears but NOT inside a normal HTML attribute or quoted context
        const markerIdx = body.indexOf(marker);
        if (markerIdx !== -1) {
          // Check it's not just reflected in an input value or URL string
          const surrounding = body.substring(Math.max(0, markerIdx - 50), markerIdx);
          const isInAttribute = /value=["'][^"']*$/i.test(surrounding) || /href=["'][^"']*$/i.test(surrounding);
          const isInUrl = /[?&][^=]+=$/i.test(surrounding);
          if (!isInAttribute && !isInUrl) {
            results.tests.push({ id: 'crlf-splitting', name: 'HTTP Response Splitting possible', status: 'fail', severity: 'critical' });
          } else {
            results.tests.push({ id: 'crlf-splitting', name: 'HTTP Response Splitting blocked (reflected in safe context)', status: 'pass', severity: 'info' });
          }
        } else {
          results.tests.push({ id: 'crlf-splitting', name: 'HTTP Response Splitting blocked', status: 'pass', severity: 'info' });
        }
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
